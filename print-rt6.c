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

#ifndef lint
static const char rcsid[] =
    "@(#) /master/usr.sbin/tcpdump/tcpdump/print-icmp.c,v 2.1 1995/02/03 18:14:42 polk Exp (LBL)";
#endif

#ifdef INET6

#include <sys/param.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <net/if.h>

#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip_var.h>
#include <netinet/udp.h>
#include <netinet/udp_var.h>
#include <netinet/tcp.h>

#include <stdio.h>

#include <netinet/ip6.h>

#include "interface.h"
#include "addrtoname.h"

int
rt6_print(register const u_char *bp, register const u_char *bp2)
{
	register const struct ip6_rthdr0 *dp;
	register const struct ip6_hdr *ip;
	register const u_char *ep;
	u_long bitmap = 0x0800;
	u_long slmap;
	int i, len;

#if 0
#define TCHECK(var) if ((u_char *)&(var) >= ep - sizeof(var)) goto trunc
#endif

	dp = (struct ip6_rthdr0 *)bp;
	ip = (struct ip6_hdr *)bp2;
	len = dp->ip6r0_len;

	/* 'ep' points to the end of avaible data. */
	ep = snapend;

        printf("%s > %s: ",
	       ip6addr_string(&ip->ip6_src),
	       ip6addr_string(&ip->ip6_dst));
	
	TCHECK(dp->ip6r0_slmap[2]);
	printf("srcrt (len=%d, ", dp->ip6r0_len);
	printf("type=%d, ", dp->ip6r0_type);
	printf("segleft=%d, ", dp->ip6r0_segleft);
	if (dp->ip6r0_type != 0)
		goto trunc;
	slmap = (dp->ip6r0_slmap[0] << 16)
	      | (dp->ip6r0_slmap[1] <<  8)
	      | (dp->ip6r0_slmap[2]);
	printf("bitmap=");
	for (i = 24; i > 0; i--) {
		if (slmap & bitmap)
			printf("S");
		else
			printf("L");
		bitmap >>= 1;
	}
	if (len % 2 == 1)
		goto trunc;
	len >>= 1;
	printf(", ");
	for (i = 0; i < len; i++) {
		if ((((u_char *)&(dp->ip6r0_reserved)) + sizeof(u_long)
		     + (i<<4)) > ep) goto trunc;
		printf(" [%d]%s", i,
		       ip6addr_string(((u_char *)&(dp->ip6r0_reserved)) +
				      sizeof(u_long) + (i<<4)));
		if (i != len - 1)
			printf(", ");
		   
	}
	printf(")");
	return((dp->ip6r0_len + 1) << 3);
 trunc:
	fputs("[|srcrt]", stdout);
	return 65535;
#undef TCHECK
}
#endif /* INET6 */
