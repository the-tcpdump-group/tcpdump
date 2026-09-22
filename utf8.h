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

#ifndef netdissect_utf8_h
#define netdissect_utf8_h

/*
 * Safe display of packet data as UTF-8 text.
 *
 * A "glyph" is the unit of text that the -A and -X printers emit as is:
 * one displayable code point, optionally followed by a bounded number
 * of combining marks that attach to it.  Everything that is not a glyph
 * (malformed UTF-8, control and format characters, separators, private
 * use and unassigned code points, ...) is left to the caller, which
 * prints it one byte at a time as "." or as the ASCII byte it is.
 *
 * The decoder and the code point classification are independent of the
 * locale and of the C library, so the output for a given packet is the
 * same on every platform and can be covered by the test suite.
 */

/* Maximum number of combining marks attached to one base code point. */
#define ND_UTF8_MAX_COMBINING	2

/* A code point is at most 4 bytes in UTF-8. */
#define ND_UTF8_GLYPH_MAX_BYTES	(4 * (1 + ND_UTF8_MAX_COMBINING))

struct nd_utf8_glyph {
	u_int nbytes;		/* packet bytes covered, <= ND_UTF8_GLYPH_MAX_BYTES */
	u_int ncols;		/* terminal columns occupied: 1 or 2 */
	u_char bytes[ND_UTF8_GLYPH_MAX_BYTES];	/* the bytes to emit */
};

/*
 * Try to read one glyph from the packet buffer at cp, looking at no more
 * than avail bytes.  Returns the number of packet bytes covered by the
 * glyph (>= 1) and fills in *g, or returns 0 if the bytes at cp do not
 * start a glyph; in the latter case *g is unspecified.
 *
 * An ASCII graphic character is a glyph of its own, so that combining
 * marks following it can be attached to it.  Other ASCII bytes (space,
 * controls) are never glyphs.
 */
extern u_int nd_utf8_glyph(netdissect_options *ndo, const u_char *cp,
    u_int avail, struct nd_utf8_glyph *g);

#endif /* netdissect_utf8_h */
