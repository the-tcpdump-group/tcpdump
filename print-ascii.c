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

#include <wchar.h>
#include <wctype.h>

#ifndef HAVE_WCWIDTH
#include "missing/wcwidth.h"
#endif

#include "netdissect-ctype.h"

#include "netdissect.h"
#include "extract.h"

#define ASCII_LINELENGTH 300
#define HEXDUMP_BYTES_PER_LINE 16
#define HEXDUMP_SHORTS_PER_LINE (HEXDUMP_BYTES_PER_LINE / 2)
#define HEXDUMP_HEXSTUFF_PER_SHORT 5 /* 4 hex digits and a space */
#define HEXDUMP_HEXSTUFF_PER_LINE \
		(HEXDUMP_HEXSTUFF_PER_SHORT * HEXDUMP_SHORTS_PER_LINE)


/*
 * The blow is_utf8_printable is taken from ngrep
 *
 * Check if a UTF-8 character sequence is printable using standard library functions.
 * Returns the number of bytes in the UTF-8 character if printable, 0 otherwise.
 * Also returns the display width (1 or 2 columns) via the width_out parameter.
 *
 * This uses mbrtowc() to convert multi-byte UTF-8 to wide char, then iswprint()
 * to check if it's printable, and wcwidth() to get the display width.
 */
static u_int is_utf8_printable(const unsigned char *s, size_t max_len, int *width_out) {
	if (!s || max_len == 0) return 0;

	mbstate_t state = {0};
	wchar_t wc;

	size_t len = mbrtowc(&wc, (const char *)s, max_len, &state);

	/* Check for errors and incomplete sequences */
	if (len == (size_t)-1) {
		/* Encoding error */
		return 0;
	}

	if (len == (size_t)-2) {
		/* Incomplete multi-byte sequence (need more bytes) */
		return 0;
	}

	if (len == 0) {
		/* Null character */
		return 0;
	}

	/* Check if the wide character is printable */
#if defined(_WIN32) || defined(_WIN64)
	/* Windows iswprint() is too conservative - be more permissive for UTF-8 */
	/* Accept any valid UTF-8 character that's not a control character */
	int is_printable = iswprint(wc) ||
		(wc >= 0x80 && wc < 0xD800) ||  /* Most of BMP except surrogates */
		(wc >= 0xE000 && wc < 0x110000); /* Private use + supplementary planes */

	/* But exclude actual control characters */
	if (wc < 0x20 || (wc >= 0x7F && wc < 0xA0)) {
		is_printable = 0;
	}
#else
	int is_printable = iswprint(wc);
#endif

	if (is_printable) {
		/* Get display width (1 for normal chars, 2 for wide chars like CJK, 0 for combining) */
		int w = wcwidth(wc);
		if (w < 0) w = 1;  /* Treat non-printable/control as width 1 */
		/* Note: wcwidth returns 0 for combining characters, which is correct */
		if (width_out) *width_out = w;
		return (u_int)len;
	}

	return 0;
}

void
ascii_print(netdissect_options *ndo,
            const u_char *cp, u_int length)
{
	u_int caplength;
	u_char s;
	int truncated = FALSE;

	ndo->ndo_protocol = "ascii";
	caplength = ND_BYTES_AVAILABLE_AFTER(cp);
	if (length > caplength) {
		length = caplength;
		truncated = TRUE;
	}
	ND_PRINT("\n");

	while (length > 0) {
		int utf8_len;
		int j;

		utf8_len = ndo->ndo_utf8 ? is_utf8_printable(cp, length, NULL) : 0;

		if (utf8_len > 0) {
			/* Valid printable UTF-8 character */
			for (j = 0; j < utf8_len; j++)
				ND_PRINT("%c", cp[j]);
			cp += utf8_len;
			length -= utf8_len;

		} else {
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
	}
	if (truncated)
		nd_trunc_longjmp(ndo);
}

static void
hex_and_ascii_print_with_offset(netdissect_options *ndo, const char *indent,
				const u_char *cp, u_int length, u_int offset)
{
	u_int caplength;
	u_int nbytes_unprinted;
	u_int s1;
	int truncated = FALSE;
	char hexstuff[HEXDUMP_SHORTS_PER_LINE*HEXDUMP_HEXSTUFF_PER_SHORT+1], *hsp;
	char asciistuff[ASCII_LINELENGTH+1+4], *asp;
	u_int utf8_bytes_to_skip = 0;

	caplength = ND_BYTES_AVAILABLE_AFTER(cp);
	if (length > caplength) {
		length = caplength;
		truncated = TRUE;
	}
	nbytes_unprinted = 0;
	hsp = hexstuff; asp = asciistuff;
	while (length != 0) {
		s1 = GET_U_1(cp);

		// insert the leading space of short
		if ((hsp - hexstuff) % HEXDUMP_HEXSTUFF_PER_SHORT == 0) {
			(void)snprintf(hsp, sizeof(hexstuff) - (hsp - hexstuff), " ");
			hsp++;
		}

		// add the byte
		(void)snprintf(hsp, sizeof(hexstuff) - (hsp - hexstuff), "%02x", s1);
		hsp += 2;

		if (utf8_bytes_to_skip > 0) {
			// only pad the new line
			if (nbytes_unprinted == (u_int)(asp - asciistuff)) {
				*(asp++) = ' ';
			}
			utf8_bytes_to_skip--;
		} else {
			// try to add the display (utf8) chars
			utf8_bytes_to_skip = ndo->ndo_utf8 ? is_utf8_printable(cp, length, NULL) : 0;
			if (utf8_bytes_to_skip > 0) {
				u_int j;
				for (j=0; j<utf8_bytes_to_skip; j++) {
					*(asp++) = (char)GET_U_1(cp+j);
				}
				utf8_bytes_to_skip --;
			} else {
				*(asp++) = (char)(ND_ASCII_ISGRAPH(s1) ? s1 : '.');
			}
		}

		cp++;
		nbytes_unprinted++;
		if (nbytes_unprinted >= (HEXDUMP_SHORTS_PER_LINE * sizeof(u_short))) {
			*hsp = *asp = '\0';
			ND_PRINT("%s0x%04x: %-*s  %s",
			    indent, offset, HEXDUMP_HEXSTUFF_PER_LINE,
			    hexstuff, asciistuff);
			nbytes_unprinted = 0; hsp = hexstuff; asp = asciistuff;
			offset += HEXDUMP_BYTES_PER_LINE;
		}
		length--;
	}

	if (nbytes_unprinted > 0) {
		*hsp = *asp = '\0';
		ND_PRINT("%s0x%04x: %-*s  %s",
		     indent, offset, HEXDUMP_HEXSTUFF_PER_LINE,
		     hexstuff, asciistuff);
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
