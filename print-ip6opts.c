/*
 * Copyright (C) 1998 WIDE Project.
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
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef lint
static const char rcsid[] =
     "@(#) $Header: /tcpdump/master/tcpdump/print-ip6opts.c,v 1.7 2000-10-07 05:53:11 itojun Exp $";
#endif

#ifdef INET6
#include <sys/param.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <stdio.h>

#include "ip6.h"

#include "interface.h"
#include "addrtoname.h"

void
ip6_opt_print(const u_char *bp, int len)
{
    int i;
    int optlen;

    for (i = 0; i < len; i += optlen) {
	switch (bp[i]) {
#ifndef IP6OPT_PAD1
#define IP6OPT_PAD1	0x00
#endif
	case IP6OPT_PAD1:
	    optlen = 1;
	    break;
#ifndef IP6OPT_PADN
#define IP6OPT_PADN	0x01
#endif
	case IP6OPT_PADN:
#ifndef IP6OPT_MINLEN
#define IP6OPT_MINLEN	2
#endif
	    if (len - i < IP6OPT_MINLEN) {
		printf("(padn: trunc)");
		goto trunc;
	    }
	    optlen = bp[i + 1] + 2;
	    break;
#ifndef IP6OPT_RTALERT
#define IP6OPT_RTALERT	0x05
#endif
	case IP6OPT_RTALERT:
#ifndef IP6OPT_RTALERT_LEN
#define IP6OPT_RTALERT_LEN	4
#endif
	    if (len - i < IP6OPT_RTALERT_LEN) {
		printf("(rtalert: trunc)");
		goto trunc;
	    }
	    if (bp[i + 1] != IP6OPT_RTALERT_LEN - 2) {
		printf("(rtalert: invalid len %d)", bp[i + 1]);
		goto trunc;
	    }
	    printf("(rtalert: 0x%04x) ", ntohs(*(u_int16_t *)&bp[i + 2]));
	    optlen = IP6OPT_RTALERT_LEN;
	    break;
#ifndef IP6OPT_JUMBO
#define IP6OPT_JUMBO	0xC2
#endif
	case IP6OPT_JUMBO:
#ifndef IP6OPT_JUMBO_LEN
#define IP6OPT_JUMBO_LEN	6
#endif
	    if (len - i < IP6OPT_JUMBO_LEN) {
		printf("(jumbo: trunc)");
		goto trunc;
	    }
	    if (bp[i + 1] != IP6OPT_JUMBO_LEN - 2) {
		printf("(jumbo: invalid len %d)", bp[i + 1]);
		goto trunc;
	    }
	    printf("(jumbo: %u) ", (u_int32_t)ntohl(*(u_int32_t *)&bp[i + 2]));
	    optlen = IP6OPT_JUMBO_LEN;
	    break;
	default:
	    if (len - i < IP6OPT_MINLEN) {
		printf("(type %d: trunc)", bp[i]);
		goto trunc;
	    }
	    printf("(type 0x%02x: len=%d) ", bp[i], bp[i + 1]);
	    optlen = bp[i + 1] + 2;
	    break;
	}
    }

#if 0
end:
#endif
    return;

trunc:
    printf("[trunc] ");
}

int
hbhopt_print(register const u_char *bp)
{
    const struct ip6_hbh *dp = (struct ip6_hbh *)bp;
    register const u_char *ep;
    int hbhlen = 0;

    /* 'ep' points to the end of available data. */
    ep = snapend;
    TCHECK(dp->ip6h_len);
    hbhlen = (int)((dp->ip6h_len + 1) << 3);
    TCHECK2(dp, hbhlen);
    printf("HBH ");
    if (vflag)
	ip6_opt_print((const u_char *)dp + sizeof(*dp), hbhlen - sizeof(*dp));

    return(hbhlen);

  trunc:
    fputs("[|HBH]", stdout);
    return(hbhlen);
}

int
dstopt_print(register const u_char *bp)
{
    const struct ip6_dest *dp = (struct ip6_dest *)bp;
    register const u_char *ep;
    int dstoptlen = 0;

    /* 'ep' points to the end of available data. */
    ep = snapend;
    TCHECK(dp->ip6d_len);
    dstoptlen = (int)((dp->ip6d_len + 1) << 3);
    TCHECK2(dp, dstoptlen);
    printf("DSTOPT ");
    if (vflag) {
	ip6_opt_print((const u_char *)dp + sizeof(*dp),
	    dstoptlen - sizeof(*dp));
    }

    return(dstoptlen);

  trunc:
    fputs("[|DSTOPT]", stdout);
    return(dstoptlen);
}
#endif /* INET6 */
