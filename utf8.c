/*
 * Copyright (c) 2026 The Tcpdump Group
 * All rights reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/* \summary: UTF-8 decoding and display policy for text dumps */

#include <config.h>

#include "netdissect-stdinc.h"

#include "netdissect-ctype.h"

#include "netdissect.h"
#include "extract.h"
#include "utf8.h"

#include "unicode-tables.h"

/*
 * Decode one UTF-8 encoded code point from the packet buffer at cp,
 * reading at most avail bytes.  Only the well-formed byte sequences of
 * Table 3-7 of the Unicode Standard are accepted: no overlong forms, no
 * surrogates, nothing above U+10FFFF.  A truncated sequence is not
 * accepted either.
 *
 * On success the sequence length (1 to 4) is returned, the code point
 * is stored in *cpp and the bytes are copied to buf.  On failure 0 is
 * returned.
 */
static u_int
nd_utf8_decode(netdissect_options *ndo, const u_char *cp, u_int avail,
    uint32_t *cpp, u_char *buf)
{
	u_char b;
	u_int i, need;
	uint32_t c;
	u_char lo = 0x80, hi = 0xBF;	/* valid range for the second byte */

	if (avail == 0)
		return 0;
	b = GET_U_1(cp);
	if (b < 0x80) {
		buf[0] = b;
		*cpp = b;
		return 1;
	}
	if (b < 0xC2) {
		/* continuation byte, or overlong 2-byte lead (C0, C1) */
		return 0;
	}
	if (b <= 0xDF) {
		need = 2;
		c = b & 0x1F;
	} else if (b <= 0xEF) {
		need = 3;
		c = b & 0x0F;
		if (b == 0xE0)
			lo = 0xA0;	/* reject overlong */
		else if (b == 0xED)
			hi = 0x9F;	/* reject surrogates */
	} else if (b <= 0xF4) {
		need = 4;
		c = b & 0x07;
		if (b == 0xF0)
			lo = 0x90;	/* reject overlong */
		else if (b == 0xF4)
			hi = 0x8F;	/* reject > U+10FFFF */
	} else {
		/* F5..FF never start a sequence */
		return 0;
	}
	if (avail < need)
		return 0;
	buf[0] = b;
	b = GET_U_1(cp + 1);
	if (b < lo || b > hi)
		return 0;
	buf[1] = b;
	c = (c << 6) | (b & 0x3F);
	for (i = 2; i < need; i++) {
		b = GET_U_1(cp + i);
		if (b < 0x80 || b > 0xBF)
			return 0;
		buf[i] = b;
		c = (c << 6) | (b & 0x3F);
	}
	*cpp = c;
	return need;
}

static int
nd_uni_in_table(uint32_t c, const struct nd_uni_range *table, size_t n)
{
	size_t lo = 0, hi = n;

	while (lo < hi) {
		size_t mid = lo + (hi - lo) / 2;

		if (c < table[mid].first)
			hi = mid;
		else if (c > table[mid].last)
			lo = mid + 1;
		else
			return 1;
	}
	return 0;
}

#define ND_UNI_IN_TABLE(c, table) \
	nd_uni_in_table((c), (table), sizeof(table) / sizeof((table)[0]))

/*
 * Classify a code point for display:
 *
 *   2  displayable, occupies two terminal columns (East Asian Wide
 *      and Fullwidth),
 *   1  displayable, occupies one column,
 *   0  a combining mark, displayable only when attached to a preceding
 *      displayable code point,
 *  -1  not displayable.
 *
 * The tables are an allowlist; see gen-unicode-tables.py for the policy.
 */
static int
nd_uni_columns(uint32_t c)
{
	if (c < 0x80)
		return ND_ASCII_ISGRAPH(c) ? 1 : -1;
	if (ND_UNI_IN_TABLE(c, nd_uni_combining))
		return 0;
	if (!ND_UNI_IN_TABLE(c, nd_uni_graphic))
		return -1;
	return ND_UNI_IN_TABLE(c, nd_uni_wide) ? 2 : 1;
}

u_int
nd_utf8_glyph(netdissect_options *ndo, const u_char *cp, u_int avail,
    struct nd_utf8_glyph *g)
{
	uint32_t c;
	u_int n, total, ncombining;
	int cols;

	n = nd_utf8_decode(ndo, cp, avail, &c, g->bytes);
	if (n == 0)
		return 0;
	cols = nd_uni_columns(c);
	if (cols <= 0)
		return 0;
	total = n;

	/*
	 * Attach up to ND_UTF8_MAX_COMBINING combining marks.  A mark that
	 * is not attached (because the limit is reached, or because there
	 * is no base character before it) is not a glyph and will be
	 * printed as "." by the caller.
	 */
	for (ncombining = 0; ncombining < ND_UTF8_MAX_COMBINING; ncombining++) {
		uint32_t c2;

		n = nd_utf8_decode(ndo, cp + total, avail - total, &c2,
		    g->bytes + total);
		if (n == 0 || nd_uni_columns(c2) != 0)
			break;
		total += n;
	}

	g->nbytes = total;
	g->ncols = (u_int)cols;
	return total;
}
