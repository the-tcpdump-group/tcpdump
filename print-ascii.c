/*	$NetBSD: print-ascii.c,v 1.1 1999/09/30 14:49:12 sjg Exp $	*/

/*-
 * Copyright (c) 1997, 1998 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Alan Barrett and Simon J. Gerraty.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *        This product includes software developed by the NetBSD
 *        Foundation, Inc. and its contributors.
 * 4. Neither the name of The NetBSD Foundation nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/* \summary: ASCII packet dump printer */

#include <config.h>

#include "netdissect-stdinc.h"

#include <stdio.h>
#include <string.h>

#include "netdissect-ctype.h"

#include "netdissect.h"
#include "extract.h"
#include "utf8.h"

#define HEXDUMP_BYTES_PER_LINE 16
#define HEXDUMP_SHORTS_PER_LINE (HEXDUMP_BYTES_PER_LINE / 2)
#define HEXDUMP_HEXSTUFF_PER_SHORT 5 /* 4 hex digits and a space */
#define HEXDUMP_HEXSTUFF_PER_LINE \
		(HEXDUMP_HEXSTUFF_PER_SHORT * HEXDUMP_SHORTS_PER_LINE)

void
ascii_print(netdissect_options *ndo,
            const u_char *cp, u_int length)
{
	u_int caplength;
	u_char s;
	int truncated = FALSE;
	struct nd_utf8_glyph g;
	u_int n;

	ndo->ndo_protocol = "ascii";
	caplength = ND_BYTES_AVAILABLE_AFTER(cp);
	if (length > caplength) {
		length = caplength;
		truncated = TRUE;
	}
	ND_PRINT("\n");
	while (length != 0) {
		if (ndo->ndo_utf8 &&
		    (n = nd_utf8_glyph(ndo, cp, length, &g)) != 0) {
			ND_PRINT("%.*s", (int)n, g.bytes);
			cp += n;
			length -= n;
			continue;
		}
		s = GET_U_1(cp);
		cp++;
		length--;
		if (s == '\r') {
			/*
			 * Don't print CRs at the end of the line; they
			 * don't belong at the ends of lines on UN*X,
			 * and the standard I/O library will give us one
			 * on Windows so we don't need to print one
			 * ourselves.
			 *
			 * In the middle of a line, just print a '.'.
			 */
			if (length > 1 && GET_U_1(cp) != '\n')
				ND_PRINT(".");
		} else {
			if (!ND_ASCII_ISGRAPH(s) &&
			    (s != '\t' && s != ' ' && s != '\n'))
				ND_PRINT(".");
			else
				ND_PRINT("%c", s);
		}
	}
	if (truncated)
		nd_trunc_longjmp(ndo);
}

static void
hex_and_ascii_print_with_offset(netdissect_options *ndo, const char *indent,
				const u_char *cp, u_int length, u_int offset)
{
	u_int caplength;
	u_int i, n;
	u_int s;
	int truncated = FALSE;
	char hexstuff[HEXDUMP_SHORTS_PER_LINE*HEXDUMP_HEXSTUFF_PER_SHORT+1], *hsp;
	/*
	 * The text column of one line.  Each of the HEXDUMP_BYTES_PER_LINE
	 * byte positions of a line is printed as one byte (an ASCII
	 * character, a "." or a filler space) or as one glyph of at most
	 * ND_UTF8_GLYPH_MAX_BYTES bytes, and at most one more glyph carried
	 * over from the previous line is printed at the start of the line.
	 */
	char text[(HEXDUMP_BYTES_PER_LINE + 1) * ND_UTF8_GLYPH_MAX_BYTES + 1];
	char *tp;
	/*
	 * Text column state carried over from one line to the next.
	 *
	 * In the text column each byte of the packet corresponds to exactly
	 * one column.  A glyph is printed at the position of its first byte,
	 * followed by one filler space per remaining byte, so the fillers of
	 * a glyph that spans two lines continue at the start of the next
	 * line.  A two-column glyph that starts at the last position of a
	 * line does not fit there; it is printed at the start of the next
	 * line instead, and its position on the current line is a filler.
	 * A two-column code point is at least 3 bytes long in UTF-8, so
	 * such a glyph always fits at the start of the next line.
	 */
	u_int fill = 0;		/* positions still to print as filler */
	int pending = FALSE;	/* g is a glyph deferred to the next line */
	struct nd_utf8_glyph g;

	caplength = ND_BYTES_AVAILABLE_AFTER(cp);
	if (length > caplength) {
		length = caplength;
		truncated = TRUE;
	}
	while (length != 0) {
		n = length < HEXDUMP_BYTES_PER_LINE ?
		    length : HEXDUMP_BYTES_PER_LINE;

		hsp = hexstuff;
		for (i = 0; i < n; i++) {
			s = GET_U_1(cp + i);
			if ((i & 1) == 0) {
				(void)snprintf(hsp,
				    sizeof(hexstuff) - (hsp - hexstuff),
				    " %02x", s);
				hsp += 3;
			} else {
				(void)snprintf(hsp,
				    sizeof(hexstuff) - (hsp - hexstuff),
				    "%02x", s);
				hsp += 2;
			}
		}
		*hsp = '\0';

		tp = text;
		i = 0;
		if (pending) {
			memcpy(tp, g.bytes, g.nbytes);
			tp += g.nbytes;
			i = g.ncols;
			pending = FALSE;
		}
		while (i < n) {
			if (fill != 0) {
				*tp++ = ' ';
				fill--;
				i++;
				continue;
			}
			if (ndo->ndo_utf8 &&
			    nd_utf8_glyph(ndo, cp + i, length - i, &g) != 0) {
				if (g.ncols <= n - i) {
					memcpy(tp, g.bytes, g.nbytes);
					tp += g.nbytes;
					fill = g.nbytes - g.ncols;
					i += g.ncols;
				} else {
					/*
					 * Two columns needed, one left on
					 * this line.
					 */
					*tp++ = ' ';
					fill = g.nbytes - 1 - g.ncols;
					pending = TRUE;
					i = n;
				}
				continue;
			}
			s = GET_U_1(cp + i);
			*tp++ = (char)(ND_ASCII_ISGRAPH(s) ? s : '.');
			i++;
		}
		*tp = '\0';

		ND_PRINT("%s0x%04x: %-*s  %s",
		    indent, offset, HEXDUMP_HEXSTUFF_PER_LINE, hexstuff, text);
		cp += n;
		length -= n;
		offset += HEXDUMP_BYTES_PER_LINE;
	}
	if (truncated)
		nd_trunc_longjmp(ndo);
}

void
hex_and_ascii_print(netdissect_options *ndo, const char *indent,
		    const u_char *cp, u_int length)
{
	hex_and_ascii_print_with_offset(ndo, indent, cp, length, 0);
}

/*
 * telnet_print() wants this.  It is essentially default_print_unaligned()
 */
void
hex_print_with_offset(netdissect_options *ndo,
                      const char *indent, const u_char *cp, u_int length,
		      u_int offset)
{
	u_int caplength;
	u_int i, s;
	u_int nshorts;
	int truncated = FALSE;

	caplength = ND_BYTES_AVAILABLE_AFTER(cp);
	if (length > caplength) {
		length = caplength;
		truncated = TRUE;
	}
	nshorts = length / sizeof(u_short);
	i = 0;
	while (nshorts != 0) {
		if ((i++ % 8) == 0) {
			ND_PRINT("%s0x%04x: ", indent, offset);
			offset += HEXDUMP_BYTES_PER_LINE;
		}
		s = GET_U_1(cp);
		cp++;
		ND_PRINT(" %02x%02x", s, GET_U_1(cp));
		cp++;
		nshorts--;
	}
	if (length & 1) {
		if ((i % 8) == 0)
			ND_PRINT("%s0x%04x: ", indent, offset);
		ND_PRINT(" %02x", GET_U_1(cp));
	}
	if (truncated)
		nd_trunc_longjmp(ndo);
}

void
hex_print(netdissect_options *ndo,
	  const char *indent, const u_char *cp, u_int length)
{
	hex_print_with_offset(ndo, indent, cp, length, 0);
}
