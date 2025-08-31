/*
 * Copyright (c) 1996
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

/* \summary: Raw IPv4/IPv6 printer and similar */

#include <config.h>

#include "netdissect-stdinc.h"

#include "netdissect.h"
#include "extract.h"

#include "ip.h"

/*
 * The DLT_RAW packet has no header. It contains a raw IPv4 or IPv6 packet.
 *
 * The DLT_IPV4 packet has no header. It's defined to contains a raw IPv4
 * packet, but there's no reason to reject IPv6 packets.
 *
 * The DLT_IPV6 packet has no header. It's defined to contains a raw IPv6
 * packet, but there's no reason to reject IPv4 packets.
 */

void
raw_if_print(netdissect_options *ndo, const struct pcap_pkthdr *h, const u_char *p)
{
	ndo->ndo_protocol = "raw";
	ndo->ndo_ll_hdr_len += 0;

	if (h->len < 1) {
		ND_PRINT("truncated-ip %u", h->len);
		return;
	}

	u_char ipver = IP_V((const struct ip *)p);
	switch (ipver) {
	case 4:
		if (ndo->ndo_eflag)
			ND_PRINT("IP ");
		ip_print(ndo, p, h->len);
		break;
	case 6:
		if (ndo->ndo_eflag)
			ND_PRINT("IP6 ");
		ip6_print(ndo, p, h->len);
		break;
	default:
		ND_PRINT("IP%u", ipver);
		nd_print_invalid(ndo);
		break;
	}
}
