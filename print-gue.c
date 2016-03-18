/*	$OpenBSD: print-gue.c	*/

/*
 * Copyright (c) 2016 Google
 * Author: Wilmer van der Gaast (wilmer@google.com)
 * All rights reserved.
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
 *	This product includes software developed by Jason L. Wright
 * 4. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * netdissect printer for GUE - Generic UDP Encapsulation
 * Currently described in:
 * https://tools.ietf.org/html/draft-ietf-nvo3-gue-02#section-2.2
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <netdissect-stdinc.h>

#include <string.h>

#include "netdissect.h"
#include "addrtostr.h"
#include "extract.h"
#include "ipproto.h"

static const char tstr[] = "[|gue]";

/* These macros operate on the first 16-bit word of a GUE packet. */
#define GUE_VERS(bits) ((bits & 0xc000) >> 14)
#define GUE_CONTROL(bits) (bits & 0x400)
#define GUE_HLEN(bits) ((bits & 0x1f00) >> 8)
#define GUE_PROTO(bits) (bits & 0xff)
#define GUE_CTYPE(bits) (bits & 0xff)

static void gue_print_0(netdissect_options *, const u_char *, u_int);

void
gue_print(netdissect_options *ndo, const u_char *bp, u_int length)
{
	u_int len = length, vers;

	if (len < 2) {
		ND_PRINT((ndo, "%s", tstr));
		return;
	}
	vers = GUE_VERS(EXTRACT_16BITS(bp));
	ND_PRINT((ndo, "GUEv%u", vers));

	switch(vers) {
	case 0:
		gue_print_0(ndo, bp, len);
		break;
	default:
		ND_PRINT((ndo, "%s", " (unknown)"));
		break;
	}
	return;
}

static void
gue_print_0(netdissect_options *ndo, const u_char *bp, u_int length)
{
	u_int len = length;
	uint16_t flags, prot;
	u_int control, hlen;

	/* Boundary checking done above */
	flags = EXTRACT_16BITS(bp);
	if (GUE_CONTROL(flags)) {
		ND_PRINT((ndo, ", control packet %02x", GUE_CTYPE(flags)));
		prot = 0;
	} else {
		prot = GUE_PROTO(flags);
	}

	/* Length of additional headers */
	hlen = GUE_HLEN(flags);
	hlen *= 4;

	len -= 2;
	bp += 2;

	if (len < 2)
		goto trunc;
	flags = EXTRACT_16BITS(bp);

	if (flags) {
		ND_PRINT((ndo, ", flags %04x", flags));
	}

	// (E)FLAGS field

	len -= 2;
	bp += 2;

	if (len < hlen)
		goto trunc;

	len -= hlen;
	bp += hlen;

	if (prot == 0) {
		/* Control packet, nothing else to show. */
		return;
	}

        if (ndo->ndo_vflag < 1)
            ND_PRINT((ndo, ": ")); /* put in a colon as protocol demarc */
        else
            ND_PRINT((ndo, "\n\t")); /* if verbose go multiline */

	switch (prot) {
 	case IPPROTO_IPV4:
 		/* ip_print() reads some fields before checking length. */
		if (len < sizeof(struct ip))
			goto trunc;

		ip_print(ndo, bp, len);
		break;
 	case IPPROTO_IPV6:
		ip6_print(ndo, bp, len);
		break;
 	case IPPROTO_NONE:
		ND_PRINT((ndo, "gue-fragment"));
		break;
	default:
		ND_PRINT((ndo, "gue-proto-0x%02x", prot));
	}

	return;

trunc:
	ND_PRINT((ndo, "%s", tstr));
}
