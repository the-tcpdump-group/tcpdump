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

/*
 * ERSPAN Type II.
 */
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
erspan_print_i_ii(netdissect_options *ndo, uint16_t flags, const u_char *bp, u_int len)
{
	uint32_t hdr, ver, vlan, cos, en, sid, index;

	ndo->ndo_protocol = "erspan";
	nd_print_protocol(ndo);

	if (!(flags & GRE_SP)) {
		/*
		 * ERSPAN Type I; no header, just a raw Ethernet frame.
		 */
		ND_PRINT(" type1: ");
		ether_print(ndo, bp, len, ND_BYTES_AVAILABLE_AFTER(bp), NULL, NULL);
		return;
	}

	/*
	 * ERSPAN Type II.
	 */
	ND_ICHECK_U(len, <, 4);
	hdr = GET_BE_U_4(bp);
	bp += 4;
	len -= 4;

	ver = hdr & ERSPAN2_VER_MASK;
	if (ver != ERSPAN2_VER) {
		/*
		 * Not Type II.
		 */
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

/*
 * ERSPAN Type III.
 */
#define ERSPAN3_VER_SHIFT		28
#define ERSPAN3_VER_MASK		(0xfU << ERSPAN3_VER_SHIFT)
#define ERSPAN3_VER			(0x2U << ERSPAN3_VER_SHIFT)
#define ERSPAN3_VLAN_SHIFT		16
#define ERSPAN3_VLAN_MASK		(0xfffU << ERSPAN3_VLAN_SHIFT)
#define ERSPAN3_COS_SHIFT		13
#define ERSPAN3_COS_MASK		(0x7U << ERSPAN3_COS_SHIFT)
#define ERSPAN3_BSO_SHIFT		11
#define ERSPAN3_BSO_MASK		(0x3U << ERSPAN3_BSO_SHIFT)
#define ERSPAN3_BSO_GOOD_UNKNOWN	0x0U
#define ERSPAN3_BSO_BAD			0x3U
#define ERSPAN3_BSO_SHORT		0x1U
#define ERSPAN3_BSO_OVERSIZED		0x2U
#define ERSPAN3_T_SHIFT			10
#define ERSPAN3_T_MASK			(0x1U << ERSPAN3_T_SHIFT)
#define ERSPAN3_SID_SHIFT		0
#define ERSPAN3_SID_MASK		(0x3ffU << ERSPAN3_SID_SHIFT)
#define ERSPAN3_P_SHIFT			15
#define ERSPAN3_P_MASK			(0x1U << ERSPAN3_P_SHIFT)
#define ERSPAN3_FT_SHIFT		10
#define ERSPAN3_FT_MASK			(0x1fU << ERSPAN3_FT_SHIFT)
#define ERSPAN3_FT_ETHERNET		0
#define ERSPAN3_FT_IP			2
#define ERSPAN3_HW_ID_SHIFT		4
#define ERSPAN3_HW_ID_MASK		(0x3fU << ERSPAN3_HW_ID_SHIFT)
#define ERSPAN3_D_SHIFT			3
#define ERSPAN3_D_MASK			(0x1U << ERSPAN3_D_SHIFT)
#define ERSPAN3_GRA_SHIFT		1
#define ERSPAN3_GRA_MASK		(0x3U << ERSPAN3_GRA_SHIFT)
#define ERSPAN3_O_SHIFT			0
#define ERSPAN3_O_MASK			(0x1U << ERSPAN3_O_SHIFT)

static const struct tok erspan3_bso_values[] = {
	{ ERSPAN3_BSO_GOOD_UNKNOWN, "Good/unknown" },
	{ ERSPAN3_BSO_BAD,          "Bad" },
	{ ERSPAN3_BSO_SHORT,        "Short" },
	{ ERSPAN3_BSO_OVERSIZED,    "Oversized" },
	{ 0, NULL }
};

static const struct tok erspan3_ft_values[] = {
	{ ERSPAN3_FT_ETHERNET, "Ethernet" },
	{ ERSPAN3_FT_IP, "IP" },
	{ 0, NULL }
};

void
erspan_print_iii(netdissect_options *ndo, const u_char *bp, u_int len)
{
	uint32_t hdr, hdr2, ver, cos, sid, ft;

	ndo->ndo_protocol = "erspan";
	nd_print_protocol(ndo);

	/*
	 * We do not check the GRE flags; ERSPAN Type III always
	 * has an ERSPAN header.
	 */
	ND_ICHECK_U(len, <, 4);
	hdr = GET_BE_U_4(bp);
	bp += 4;
	len -= 4;

	ver = hdr & ERSPAN3_VER_MASK;
	if (ver != ERSPAN3_VER) {
		/*
		 * Not Type III.
		 */
		ver >>= ERSPAN3_VER_SHIFT;
		ND_PRINT(" erspan-unknown-version-%x", ver);
		return;
	}

	if (ndo->ndo_vflag)
		ND_PRINT(" type3");

	sid = (hdr & ERSPAN3_SID_MASK) >> ERSPAN3_SID_SHIFT;
	ND_PRINT(" session %u", sid);

	ND_PRINT(" bso %s",
		 tok2str(erspan3_bso_values, "unknown %x",
			 (hdr & ERSPAN3_BSO_MASK) >> ERSPAN3_BSO_SHIFT));

	if (ndo->ndo_vflag) {
		cos = (hdr & ERSPAN3_COS_MASK) >> ERSPAN3_COS_SHIFT;
		ND_PRINT(" cos %u", cos);

		if (hdr & ERSPAN3_T_MASK)
			ND_PRINT(" truncated");
	}

	/* Skip timestamp */
	ND_ICHECK_U(len, <, 4);
	bp += 4;
	len -= 4;

	/* Skip SGT */
	ND_ICHECK_U(len, <, 2);
	bp += 2;
	len -= 2;

	/* Additional fields */
	ND_ICHECK_U(len, <, 2);
	hdr2 = GET_BE_U_2(bp);
	bp += 2;
	len -= 2;

	ft = (hdr2 & ERSPAN3_FT_MASK) >> ERSPAN3_FT_SHIFT;
	ND_PRINT(" ft %s",
		 tok2str(erspan3_ft_values, "unknown %x", ft));


	/* Do we have the platform-specific header? */
	if (hdr2 & ERSPAN3_O_MASK) {
		/* Yes.  Skip it. */
		ND_ICHECK_U(len, <, 8);
		bp += 8;
		len -= 8;
	}

	ND_PRINT(": ");

	switch (ft) {

	case ERSPAN3_FT_ETHERNET:
		ether_print(ndo, bp, len, ND_BYTES_AVAILABLE_AFTER(bp), NULL, NULL);
		break;

	default:
		ND_PRINT("Frame type unknown");
		break;
	}
	return;

invalid:
	nd_print_invalid(ndo);
}
