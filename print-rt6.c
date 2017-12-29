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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <netdissect-stdinc.h>

#include <string.h>

#include "netdissect.h"
#include "addrtoname.h"
#include "extract.h"

#include "ip6.h"

int
rt6_print(netdissect_options *ndo, const u_char *bp, const u_char *bp2 _U_)
{
	const struct ip6_rthdr *dp;
	const struct ip6_rthdr0 *dp0;
	const struct ip6_srh *srh;
	const u_char *ep;
	u_int i, len, type;
	const struct in6_addr *addr;

	dp = (const struct ip6_rthdr *)bp;

	/* 'ep' points to the end of available data. */
	ep = ndo->ndo_snapend;

	ND_TCHECK(dp->ip6r_segleft);

	len = EXTRACT_U_1(dp->ip6r_len);
	ND_PRINT((ndo, "srcrt (len=%u", len));	/*)*/
	type = EXTRACT_U_1(dp->ip6r_type);
	ND_PRINT((ndo, ", type=%u", type));
	ND_PRINT((ndo, ", segleft=%u", EXTRACT_U_1(dp->ip6r_segleft)));

	switch (type) {
	case IPV6_RTHDR_TYPE_0:
	case IPV6_RTHDR_TYPE_2:			/* Mobile IPv6 ID-20 */
		dp0 = (const struct ip6_rthdr0 *)dp;

		ND_TCHECK(dp0->ip6r0_reserved);
		if (EXTRACT_BE_U_4(dp0->ip6r0_reserved) || ndo->ndo_vflag) {
			ND_PRINT((ndo, ", rsv=0x%0x",
			    EXTRACT_BE_U_4(dp0->ip6r0_reserved)));
		}

		if (len % 2 == 1)
			goto trunc;
		len >>= 1;
		addr = &dp0->ip6r0_addr[0];
		for (i = 0; i < len; i++) {
			if ((const u_char *)(addr + 1) > ep)
				goto trunc;

			ND_PRINT((ndo, ", [%d]%s", i, ip6addr_string(ndo, addr)));
			addr++;
		}
		/*(*/
		ND_PRINT((ndo, ") "));
		return((EXTRACT_U_1(dp0->ip6r0_len) + 1) << 3);
		break;
	case IPV6_RTHDR_TYPE_4:
		srh = (const struct ip6_srh *)dp;
		ND_PRINT((ndo, ", last-entry=%u", EXTRACT_U_1(srh->srh_last_ent)));

		ND_TCHECK(srh->srh_flags);
		if (EXTRACT_U_1(srh->srh_flags) || ndo->ndo_vflag) {
			ND_PRINT((ndo, ", flags=0x%0x",
				EXTRACT_U_1(srh->srh_flags)));
		}

		ND_PRINT((ndo, ", tag=%x", EXTRACT_BE_U_2(srh->srh_tag)));

		if (len % 2 == 1)
			goto trunc;
		len >>= 1;
		addr = &srh->srh_segments[0];
		for (i = 0; i < len; i++) {
			if ((const u_char *)(addr + 1) > ep)
				goto trunc;

			ND_PRINT((ndo, ", [%d]%s", i, ip6addr_string(ndo, addr)));
			addr++;
		}
		/*(*/
		ND_PRINT((ndo, ") "));
		return((EXTRACT_U_1(srh->srh_len) + 1) << 3);
		break;
	default:
		goto trunc;
		break;
	}

 trunc:
	ND_PRINT((ndo, "[|srcrt]"));
	return -1;
}
