/*
 * Copyright (c) 1988, 1989, 1990, 1991, 1993, 1994
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

/* \summary: IPv6 routing header printer */

#include <config.h>

#include "netdissect-stdinc.h"

#define ND_LONGJMP_FROM_TCHECK
#include "netdissect.h"
#include "addrtoname.h"
#include "extract.h"

#include "ip6.h"

static const struct tok srh_tlv_type[] = {
    { IPV6_SRH_TLV_PAD1, "Pad1"},
    { IPV6_SRH_TLV_PADN, "PadN"},
    { IPV6_SRH_TLV_HMAC, "HMAC"},
    { 0, NULL }
};

static int
srh_tlv_print(netdissect_options *ndo, const u_char *p, u_int bytes_left)
{
	u_int tlv_type, tlv_len;
	while (bytes_left != 0) {
		tlv_type = GET_U_1(p);
		ND_PRINT(", TLV-type=%s(%u)",
			 tok2str(srh_tlv_type, "Unknown", tlv_type),
			 tlv_type);
		ND_ICHECKMSG_U("remaining length", bytes_left, <, 1);
		p += 1;
		bytes_left -= 1;
		if (bytes_left == 0)
			break;
		if (tlv_type == IPV6_SRH_TLV_PAD1)
			continue;

		tlv_len = GET_U_1(p);
		ND_PRINT(", TLV-len=%u", tlv_len);
		ND_ICHECKMSG_U("remaining length", bytes_left, <, 1);
		p += 1;
		bytes_left -= 1;

		switch (tlv_type) {
		case IPV6_SRH_TLV_PADN:
			ND_ICHECKMSG_U("PadN length", tlv_len, >, 5); /* RFC 8754 */
			ND_ICHECKMSG_U("remaining length", bytes_left, <, tlv_len);
			ND_TCHECK_LEN(p, tlv_len);
			p += tlv_len;
			bytes_left -= tlv_len;
			break;
		case IPV6_SRH_TLV_HMAC:
			ND_ICHECKMSG_U("remaining length", bytes_left, <, 6);
			uint16_t reserved;
			uint32_t key_id;
			uint8_t hmac_byte;
			reserved = GET_BE_U_2(p);
			p += 2;
			if (ndo->ndo_vflag)
				ND_PRINT(", D=%u", reserved >> 15);
			if (ndo->ndo_vflag && (reserved & 0x7fff) != 0)
				ND_PRINT(", reserved MBZ %u", reserved & 0x7fff);
			key_id = GET_BE_U_4(p);
			p += 4;
			if (ndo->ndo_vflag)
				ND_PRINT(", HMAC-key-ID=0x%02x", key_id);
			bytes_left -= 6;
			if (ndo->ndo_vflag)
				ND_PRINT(", HMAC=0x");
			for (u_int i = 0; i < tlv_len; i++) {
				hmac_byte = GET_U_1(p);
				ND_ICHECKMSG_U("remaining length", bytes_left, <, 1);
				p += 1;
				bytes_left -= 1;
				if (ndo->ndo_vflag)
					ND_PRINT("%02x", hmac_byte);
			}
			break;
		default:	/* Unknown type */
			if (ndo->ndo_vflag)
				ND_PRINT(", TLV-value=0x");
			ND_ICHECKMSG_U("remaining length", bytes_left, <, tlv_len);
			uint8_t tlv_byte;
			for (u_int i = 0; i < tlv_len; i++) {
				tlv_byte = GET_U_1(p);
				p += 1;
				bytes_left -= 1;
				if (ndo->ndo_vflag)
					ND_PRINT("%02x", tlv_byte);
			}
			break;
		}
	}
	return 0;

invalid:
	return -1;
}


int
rt6_print(netdissect_options *ndo, const u_char *bp, const u_char *bp2 _U_)
{
	const struct ip6_rthdr *dp;
	const struct ip6_rthdr0 *dp0;
	const struct ip6_srh *srh;
	u_int i, len, type, seg_list_len, last_entry;
	int err;
	const u_char *p;

	ndo->ndo_protocol = "rt6";

	nd_print_protocol_caps(ndo);
	dp = (const struct ip6_rthdr *)bp;

	len = GET_U_1(dp->ip6r_len);
	ND_PRINT(" (len=%u", len);	/*)*/
	type = GET_U_1(dp->ip6r_type);
	ND_PRINT(", type=%u", type);
	if (type == IPV6_RTHDR_TYPE_0)
		ND_PRINT(" [Deprecated]");
	ND_PRINT(", segleft=%u", GET_U_1(dp->ip6r_segleft));

	switch (type) {
	case IPV6_RTHDR_TYPE_0:
	case IPV6_RTHDR_TYPE_2:			/* Mobile IPv6 ID-20 */
		dp0 = (const struct ip6_rthdr0 *)dp;

		if (GET_BE_U_4(dp0->ip6r0_reserved) || ndo->ndo_vflag) {
			ND_PRINT(", rsv=0x%0x",
			    GET_BE_U_4(dp0->ip6r0_reserved));
		}

		if (len % 2 == 1) {
			ND_PRINT(" [length %u]", len);
			goto invalid;
		}
		len >>= 1;
		p = (const u_char *) dp0->ip6r0_addr;
		for (i = 0; i < len; i++) {
			ND_PRINT(", [%u]%s", i, GET_IP6ADDR_STRING(p));
			p += 16;
		}
		/*(*/
		ND_PRINT(") ");
		return((GET_U_1(dp0->ip6r0_len) + 1) << 3);
	case IPV6_RTHDR_TYPE_4:
		srh = (const struct ip6_srh *)dp;
		last_entry = GET_U_1(srh->srh_last_ent);
		ND_PRINT(", last-entry=%u", last_entry);

		if (GET_U_1(srh->srh_flags) || ndo->ndo_vflag) {
			ND_PRINT(", flags=0x%0x",
				GET_U_1(srh->srh_flags));
		}

		ND_PRINT(", tag=%x", GET_BE_U_2(srh->srh_tag));
		p  = (const u_char *) srh->srh_segments;
		for (i = 0; i < last_entry + 1; i++) {
			ND_PRINT(", [%u]%s", i, GET_IP6ADDR_STRING(p));
			p += 16;
		}
		seg_list_len = (last_entry + 1) * 2;
		if (seg_list_len < len) {
			/* there is TLV */
			u_int bytes_left;
			bytes_left = (len - seg_list_len) * 8;
			err = srh_tlv_print(ndo, p, bytes_left);
			if (err)
				goto invalid;
		}

		/*(*/
		ND_PRINT(") ");
		return((GET_U_1(srh->srh_len) + 1) << 3);
	default:
		ND_PRINT(" (unknown type)");
		goto invalid;
	}

invalid:
	nd_print_invalid(ndo);
	return -1;
}
