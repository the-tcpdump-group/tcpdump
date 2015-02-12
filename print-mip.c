/*
 * Copyright (c) 2013 The TCPDUMP project
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code
 * distributions retain the above copyright notice and this paragraph
 * in its entirety, and (2) distributions including binary code include
 * the above copyright notice and this paragraph in its entirety in
 * the documentation or other materials provided with the distribution.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND
 * WITHOUT ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, WITHOUT
 * LIMITATION, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE.
 *
 * Code by Håkon Struijk Holmen (hawken@thehawken.org) based
 *  on work by Ola Martin Lykkja (ola.lykkja@q-free.com)
 */

#define NETDISSECT_REWORKED
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <tcpdump-stdinc.h>

#include "interface.h"
#include "extract.h"
#include "addrtoname.h"


/*
MIP student protocol.
Header:
	3 bits: T R A (Transport Routing Address-resolution)
		Transport means we are transporting user data
		Routing ???
		Address means we are requesting someone to tell us their hardware address
		no flags is arp response which means we are sending our hardware address back to the requester
	4 bits: TTL
		as in IPv4, only that this is initially 0xf
	9 bits: len
		you have to multiply it to get the payload length
	8 bits: source
	8 bits: destination
*/

#define TRA_TRANSPORT 4
#define TRA_ROUTING   2
#define TRA_ARP       1
#define TRA_ARP_REP   0

struct mip_hdr {
	u_char  mip_flags1;
	u_char  mip_flags2;
	u_char  mip_src;
	u_char  mip_dst;
};

#define TRA(m) (((m)->mip_flags1>>5) & 0x007)
#define TTL(m) (((m)->mip_flags1>>1) & 0x00f)
#define LEN(m) (((((m)->mip_flags1 & 1) << 8) | (m)->mip_flags2)*4)

static const struct tok tra_values[] = {
	{ TRA_TRANSPORT, "Transport"    },
	{ TRA_ROUTING,   "Routing"      },
	{ TRA_ARP,       "Arp request"  },
	{ TRA_ARP_REP,   "Arp response" },
	{ 0,             NULL           }
};

void mip_print(netdissect_options *ndo, const u_char *eth, const u_char *bp, u_int length, u_int caplen)
{
	const struct mip_hdr *mip = (const struct mip_hdr*)bp;
	int tra, ttl, len, src, dst;

	tra = TRA(mip);
	ttl = TTL(mip);
	len = LEN(mip);
	src = mip->mip_src;
	dst = mip->mip_dst;

	ND_TCHECK2(*bp, 4);

	ND_PRINT((ndo, "MIP %i -> %i: TTL %i, payload length %i, TRA %s", src, dst, ttl, len,  tok2str(tra_values, "unknown (%u)", tra)));

	return;

trunc:
	ND_PRINT((ndo, "[|mip]"));
}


/*
 * Local Variables:
 * c-style: whitesmith
 * c-basic-offset: 8
 * End:
 */
