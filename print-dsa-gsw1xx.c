/*
 * Copyright (c) 1988, 1989, 1990, 1991, 1992, 1993, 1994, 1995, 1996, 1997
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) all advertising materials mentioning
 * features or use of this software display the following acknowledgement:
 * ``This product includes software developed by the University of California,
 * Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
 * the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

/* based on print-dsa.c */

/* \summary: MaxLinear (Ethertype) Distributed Switch Architecture */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "netdissect-stdinc.h"

#include "netdissect.h"
#include "ethertype.h"
#include "addrtoname.h"
#include "extract.h"

/*
 * Ingress and Egress have different formats.
 *
 * Format of (Ethertyped) Ingress tagged frames:
 *
 *  0 +----+----+----+----+----+----+----+----+
 *    |       Ether Destination Address       |
 * +6 +----+----+----+----+----+----+----+----+
 *    |       Ether Source Address            |
 * +6 +----+----+----+----+----+----+----+----+  +-
 *    |    Prog. DSA Ether Type [15:8]        |  | (8-byte) Special Tag
 * +1 +----+----+----+----+----+----+----+----+  | Contains a programmable Ether type.
 *    |    Prog. DSA Ether Type [7:0]         |  |  +
 * +1 +----+----+----+----+----+----+----+----+  |  | (6-byte) Special Tag Content
 *    |PME[7] TCE[6] TSE[5] FNL[4]   TTC[3:0] |  |  |
 * +1 +----+----+----+----+----+----+----+----+  |  |
 *    |         TEPML [7:0]                   |  |  |
 * +1 +----+----+----+----+----+----+----+----+  |  |
 *    |         TEPMH [7:0]                   |  |  |
 * +1 +----+----+----+----+----+----+----+----+  |  |
 *    |   Res[7:5]  IE[4]  SP[3:0]            |  |  |
 * +1 +----+----+----+----+----+----+----+----+  |  |
 *    |          Res [7:0] all zero           |  |  |
 * +1 +----+----+----+----+----+----+----+----+  |  |
 *    |          Res [7:0] all zero           |  |  |
 * +1 +----+----+----+----+----+----+----+----+  +- +-
 *
 * Format of (Ethertyped) Egress tagged frames:
 *
 *  0 +----+----+----+----+----+----+----+----+
 *    |       Ether Destination Address       |
 * +6 +----+----+----+----+----+----+----+----+
 *    |        Ether Source Address           |
 * +6 +----+----+----+----+----+----+----+----+  +-
 *    |    Prog. DSA Ether Type [15:8]        |  | (8-byte) Special Tag
 * +1 +----+----+----+----+----+----+----+----+  | Contains a programmable Ether type.
 *    |    Prog. DSA Ether Type [7:0]         |  |  +
 * +1 +----+----+----+----+----+----+----+----+  |  | (6-byte) Special Tag Content
 *    |        TC[7:4]    IPN [3:0]           |  |  |
 * +1 +----+----+----+----+----+----+----+----+  |  |
 *    | PPPOE[7] IPV[6]   IPO[5:0]            |  |  |
 * +1 +----+----+----+----+----+----+----+----+  |  |
 *    |             DLPML [7:0]               |  |  |
 * +1 +----+----+----+----+----+----+----+----+  |  |
 *    |             DLPMR [7:0]               |  |  |
 * +1 +----+----+----+----+----+----+----+----+  |  |
 *    |  MI[7]  KL2UM[6] PLHB[5:0]            |  |  |
 * +1 +----+----+----+----+----+----+----+----+  |  |
 *    |             PLLB [7:0]                |  |  |
 * +2 +----+----+----+----+----+----+----+----+  +- +-
 *    .   .   .   .   .   .   .   .   .
 *
 * PME: Port map enable
 * IPN: Ingress port number
 * TCE: Traffic class enable
 * TSE: Time stamp enable
 * FNL: Force no learning
 * TC: Traffic class
 * IPV: IPv4 packet
 * IPO: IP offset
 * SP: Source port
 * IE: Interrupt enable
 * PPPOE: ppp-over-ethernet
 * DLPML: Destination logical port map low bits.
 * DLPMR: Destination logical port map high (reserved)
 * MI: Mirror indication
 * KL2UM Known l2 unicast/multicast mac.
 * PLHB: Packet Length High Bits
 * PLLB: Packet Length Low Bits.
 * TEPML: Target egress port maps low bits
 * TEPMH: Target egress port maps high bits (reserved)
 * Res: Reserved
 */

#define TOK(tag, byte, mask, shift) ((GET_U_1(&(((const u_char *) tag)[byte])) & (mask)) >> (shift))

#define GSW1XX_ET1(tag) TOK(tag, 0, 0xFF, 0)
#define GSW1XX_ET2(tag) TOK(tag, 1, 0xFF, 0)
#define GSW1XX_TTC(tag) TOK(tag, 2, 0x08, 0)
#define GSW1XX_IG_PME(tag) TOK(tag, 2, 0x80, 7)
#define GSW1XX_IG_TCE(tag) TOK(tag, 2, 0x40, 6)
#define GSW1XX_IG_TSE(tag) TOK(tag, 2, 0x20, 5)
#define GSW1XX_IG_FNL(tag) TOK(tag, 2, 0x10, 4)
#define GSW1XX_IG_SP(tag) TOK(tag, 2, 0x0F, 0)
#define GSW1XX_IG_IE(tag) TOK(tag, 5, 0x10, 3)
#define GSW1XX_EG_IPN(tag) TOK(tag, 2, 0x0F, 0)
#define GSW1XX_EG_TC(tag) TOK(tag, 2, 0xF0, 4)
#define GSW1XX_EG_POE(tag) TOK(tag, 2, 0x80, 7)
#define GSW1XX_EG_IV4(tag) TOK(tag, 2, 0x40, 6)
#define GSW1XX_EG_IPO(tag) TOK(tag, 3, 0x3F, 0)

#define GSW1XX_MAP_LOW(tag) TOK(tag, 3, 0xFF, 0)
#define GSW1XX_MAP_HIGH(tag) TOK(tag, 4, 0xFF, 0)
#define GSW1XX_MAP(tag) ((GSW1XX_MAP_HIGH(tag) << 8) + GSW1XX_MAP_LOW(tag))
#define GSW1XX_LEN_LOW(tag) TOK(tag, 7, 0xFF, 0)
#define GSW1XX_LEN_HIGH(tag) TOK(tag, 6, 0x3F, 0)
#define GSW1XX_LEN(tag) ((GSW1XX_LEN_HIGH(tag) << 8) + GSW1XX_LEN_LOW(tag))

#define SPTAG_LEN 8

static void
tag_common_print(netdissect_options *ndo, const u_char *p)
{
	if (ndo->ndo_eflag ) {
		int egress = !!GSW1XX_LEN(p);

		if (egress)  {
			ND_PRINT("Egress Port %d,", GSW1XX_EG_IPN(p));
			if (ndo->ndo_eflag > 1) {
				ND_PRINT("TTC %d,", GSW1XX_TTC(p));
				ND_PRINT("TC %d,", GSW1XX_EG_TC(p));
				ND_PRINT("IPN %d,", GSW1XX_EG_IPN(p));
				ND_PRINT("POE %d,", GSW1XX_EG_POE(p));
				if (GSW1XX_EG_IPO(p)) {
					ND_PRINT("IV4 %d,", GSW1XX_EG_IV4(p));
					ND_PRINT("IPO %d,", GSW1XX_EG_IPO(p));
				}
				ND_PRINT("Len %d,", GSW1XX_LEN(p));
			}
		} else {
			ND_PRINT("Ingress Port %d,", GSW1XX_IG_SP(p));
			ND_PRINT("MAP %d,", GSW1XX_MAP(p));
			if (ndo->ndo_eflag > 1) {
				ND_PRINT("PME %d,", GSW1XX_IG_PME(p));
				ND_PRINT("TCE %d,", GSW1XX_IG_TCE(p));
				ND_PRINT("TTC %d,", GSW1XX_TTC(p));
				ND_PRINT("FNL %d,", GSW1XX_IG_FNL(p));
				ND_PRINT("IE %d,", GSW1XX_IG_IE(p));
                                ND_PRINT("TSE %d,", GSW1XX_IG_TSE(p));
			}
		}
	}
}

static void
gsw1xx_tag_print(netdissect_options *ndo, const u_char *bp)
{
	const u_char *p = bp;
	uint16_t sptag_etype;

	sptag_etype = GET_BE_U_2(p);
	if (ndo->ndo_eflag > 2) {
		ND_PRINT("MaxLinear ethertype 0x%04x (%s), ", sptag_etype,
			 tok2str(ethertype_values, "Unknown", sptag_etype));
	} else {
		if (sptag_etype == ETHERTYPE_GSW1XX)
			ND_PRINT("GSW1XX ");
		else
			ND_PRINT("GSW1XX Unknown 0x%04x, ", sptag_etype);
	}
	tag_common_print(ndo, p);
}

void
gsw1xx_if_print(netdissect_options *ndo, const struct pcap_pkthdr *h, const u_char *p)
{
	u_int caplen = h->caplen;
	u_int length = h->len;

	ndo->ndo_protocol = "gsw1xx";
	ndo->ndo_ll_hdr_len +=
		ether_switch_tag_print(ndo, p, length, caplen, gsw1xx_tag_print, SPTAG_LEN);
}
