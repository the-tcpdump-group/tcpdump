/*	$OpenBSD: print-gre.c,v 1.6 2002/10/30 03:04:04 fgsch Exp $	*/

/*
 * Copyright (c) 2002 Jason L. Wright (jason@thought.net)
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

/* \summary: Cisco ERSPAN printer */

/*
 * Specifications: I-D draft-foschiano-erspan-03.
 */

#include <config.h>

#include "netdissect-stdinc.h"

#define ND_LONGJMP_FROM_TCHECK
#include "netdissect.h"
#include "extract.h"
#include "gre.h"

#define ERSPAN2_VER_SHIFT	28
#define ERSPAN2_VER_MASK	(0xfU << ERSPAN2_VER_SHIFT)
#define ERSPAN2_VER		(0x1U << ERSPAN2_VER_SHIFT)
#define ERSPAN2_VLAN_SHIFT	16
#define ERSPAN2_VLAN_MASK	(0xfffU << ERSPAN2_VLAN_SHIFT)
#define ERSPAN2_COS_SHIFT	13
#define ERSPAN2_COS_MASK	(0x7U << ERSPAN2_COS_SHIFT)
#define ERSPAN2_EN_SHIFT	11
#define ERSPAN2_EN_MASK		(0x3U << ERSPAN2_EN_SHIFT)
#define ERSPAN2_EN_NONE		(0x0U << ERSPAN2_EN_SHIFT)
#define ERSPAN2_EN_ISL		(0x1U << ERSPAN2_EN_SHIFT)
#define ERSPAN2_EN_DOT1Q	(0x2U << ERSPAN2_EN_SHIFT)
#define ERSPAN2_EN_VLAN		(0x3U << ERSPAN2_EN_SHIFT)
#define ERSPAN2_T_SHIFT		10
#define ERSPAN2_T_MASK		(0x1U << ERSPAN2_T_SHIFT)
#define ERSPAN2_SID_SHIFT	0
#define ERSPAN2_SID_MASK	(0x3ffU << ERSPAN2_SID_SHIFT)

#define ERSPAN2_INDEX_SHIFT	0
#define ERSPAN2_INDEX_MASK	(0xfffffU << ERSPAN2_INDEX_SHIFT)

void
erspan_print(netdissect_options *ndo, uint16_t flags, const u_char *bp, u_int len)
{
	uint32_t hdr, ver, vlan, cos, en, sid, index;

	ndo->ndo_protocol = "erspan";
	nd_print_protocol(ndo);

	if (!(flags & GRE_SP)) {
		ND_PRINT(" type1: ");
		ether_print(ndo, bp, len, ND_BYTES_AVAILABLE_AFTER(bp), NULL, NULL);
		return;
	}

	ND_ICHECK_U(len, <, 4);
	hdr = GET_BE_U_4(bp);
	bp += 4;
	len -= 4;

	ver = hdr & ERSPAN2_VER_MASK;
	if (ver != ERSPAN2_VER) {
		ver >>= ERSPAN2_VER_SHIFT;
		ND_PRINT(" erspan-unknown-version-%x", ver);
		return;
	}

	if (ndo->ndo_vflag)
		ND_PRINT(" type2");

	sid = (hdr & ERSPAN2_SID_MASK) >> ERSPAN2_SID_SHIFT;
	ND_PRINT(" session %u", sid);

	en = hdr & ERSPAN2_EN_MASK;
	vlan = (hdr & ERSPAN2_VLAN_MASK) >> ERSPAN2_VLAN_SHIFT;
	switch (en) {
	case ERSPAN2_EN_NONE:
		break;
	case ERSPAN2_EN_ISL:
		ND_PRINT(" isl %u", vlan);
		break;
	case ERSPAN2_EN_DOT1Q:
		ND_PRINT(" vlan %u", vlan);
		break;
	case ERSPAN2_EN_VLAN:
		ND_PRINT(" vlan payload");
		break;
	}

	if (ndo->ndo_vflag) {
		cos = (hdr & ERSPAN2_COS_MASK) >> ERSPAN2_COS_SHIFT;
		ND_PRINT(" cos %u", cos);

		if (hdr & ERSPAN2_T_MASK)
			ND_PRINT(" truncated");
	}

	ND_ICHECK_U(len, <, 4);
	hdr = GET_BE_U_4(bp);
	bp += 4;
	len -= 4;

	if (ndo->ndo_vflag) {
		index = (hdr & ERSPAN2_INDEX_MASK) >> ERSPAN2_INDEX_SHIFT;
		ND_PRINT(" index %u", index);
	}

	ND_PRINT(": ");
	ether_print(ndo, bp, len, ND_BYTES_AVAILABLE_AFTER(bp), NULL, NULL);
	return;

invalid:
	nd_print_invalid(ndo);
}
