/*
 * Copyright (c) 1996
 *      The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the above copyright notice and this paragraph are
 * duplicated in all such forms and that any documentation,
 * advertising materials, and other materials related to such
 * distribution and use acknowledge that the software was developed
 * by the University of California, Lawrence Berkeley Laboratory,
 * Berkeley, CA.  The name of the University may not be used to
 * endorse or promote products derived from this software without
 * specific prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 *
 * Initial contribution from John Hawkinson <jhawk@bbnplanet.com>
 *
 * This module implements support for decoding GRE (Generic Routing
 * Encapsulation) tunnels; they're documented in RFC1701 and RFC1702.
 * This code only supports the IP encapsulation thereof.
 */

#ifndef lint
static const char rcsid[] =
    "@(#) $Header: /tcpdump/master/tcpdump/print-gre.c,v 1.10 2001-02-03 20:21:28 fenner Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/param.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <netdb.h>
#include <stdio.h>

#include "interface.h"
#include "addrtoname.h"
#include "extract.h"		/* must come after interface.h */

#define GRE_SIZE (20)

struct gre {
	u_short flags;
	u_short proto;
	union {
		struct gre_ckof {
			u_short cksum;
			u_short offset;
		}        gre_ckof;
		u_int32_t key;
		u_int32_t seq;
	}     gre_void1;
	union {
		u_int32_t key;
		u_int32_t seq;
		u_int32_t routing;
	}     gre_void2;
	union {
		u_int32_t seq;
		u_int32_t routing;
	}     gre_void3;
	union {
		u_int32_t routing;
	}     gre_void4;
};

/* RFC 2784 - GRE */
#define GRE_CP		0x8000	/* Checksum Present */
#define GRE_VER_MASK	0x0007	/* Version */

/* RFC 2890 - Key and Sequence extensions to GRE */
#define GRE_KP		0x2000	/* Key Present */
#define GRE_SP		0x1000	/* Sequence Present */

/* Legacy from RFC 1700 */
#define GRE_RP		0x4000	/* Routing Present */
#define GRE_sP		0x0800	/* strict source route present */
#define GRE_RECUR_MASK	0x0700  /* Recursion Control */
#define GRE_RECUR_SHIFT	8

/* "Enhanced GRE" from RFC2637 - PPTP */
#define GRE_AP		0x0080	/* Ack present */

#define GRE_MBZ_MASK	0x0078	/* not defined */

/*
 * Deencapsulate and print a GRE-tunneled IP datagram
 *
 * XXX PPTP needs to interpret the "key" field...
 */
void
gre_print(const u_char *bp, u_int length)
{
	const u_char *cp = bp + 4;
	const struct gre *gre;
	u_short flags, proto, extracted_ethertype;

	gre = (const struct gre *)bp;

	TCHECK(gre->proto);
	flags = EXTRACT_16BITS(&gre->flags);
	proto = EXTRACT_16BITS(&gre->proto);

	if (flags) {
		/* Decode the flags */
		putchar('[');
		if (flags & GRE_CP)
			putchar('C');
		if (flags & GRE_RP)
			putchar('R');
		if (flags & GRE_KP)
			putchar('K');
		if (flags & GRE_SP)
			putchar('S');
		if (flags & GRE_sP)
			putchar('s');
		if (flags & GRE_AP)
			putchar('A');
		if (flags & GRE_RECUR_MASK)
			printf("R%x", (flags & GRE_RECUR_MASK) >> GRE_RECUR_SHIFT);
		if (flags & GRE_VER_MASK)
			printf("v%x", flags & GRE_VER_MASK);
		if (flags & GRE_MBZ_MASK)
			printf("!%x", flags & GRE_MBZ_MASK);
		fputs("] ", stdout);
	}
	/* Checksum & Offset are present */
	if ((flags & GRE_CP) | (flags & GRE_RP))
		cp += 4;

	/* We don't support routing fields (variable length) now. Punt. */
	if (flags & GRE_RP)
		return;

	if (flags & GRE_KP) {
		TCHECK2(*cp, 4);
		if (vflag > 1)
			printf("K:%08x ", EXTRACT_32BITS(cp));
		cp += 4;	/* skip key */
	}
	if (flags & GRE_SP) {
		TCHECK2(*cp, 4);
		if (vflag > 1)
			printf("S:%08x ", EXTRACT_32BITS(cp));
		cp += 4;	/* skip seq */
	}
	if (flags & GRE_AP && (flags & GRE_VER_MASK) >= 1) {
		TCHECK2(*cp, 4);
		if (vflag > 1)
			printf("A:%08x ", EXTRACT_32BITS(cp));
		cp += 4;	/* skip ack */
	}

	TCHECK(cp[0]);

	length -= cp - bp;
	if (ether_encap_print(proto, cp, length, length,
	    &extracted_ethertype) == 0)
 		printf("gre-proto-0x%04X", proto);
	return;

trunc:
	fputs("[|gre]", stdout);

}
