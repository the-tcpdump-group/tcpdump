/*
 * Copyright (C) 2002 WIDE Project.
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
     "@(#) $Header: /tcpdump/master/tcpdump/print-mobility.c,v 1.2 2002-07-08 08:58:37 fenner Exp $";
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
#include "extract.h"		/* must come after interface.h */

/* Mobility header */
struct ip6_mobility {
        u_int8_t ip6m_pproto;   /* following payload protocol (for PG) */
	u_int8_t ip6m_len;      /* length in units of 8 octets */
	u_int16_t ip6m_type;    /* message type */
	u_int16_t ip6m_cksum;   /* sum of IPv6 pseudo-header and MH */
	union {
		u_int16_t	ip6m_un_data16[1]; /* type-specific field */
		u_int8_t	ip6m_un_data8[2];  /* type-specific fiedl */
	} ip6m_dataun;
};

#define ip6m_data16	ip6m_dataun.ip6m_un_data16
#define ip6m_data8	ip6m_dataun.ip6m_un_data8

#define IP6M_MINLEN	8

/* message type */
#define IP6M_BINDING_REQUEST	0x0000	/* Binding Refresh Request */
#define IP6M_HOME_TEST_INIT	0x0001	/* Home Test Init */
#define IP6M_CAREOF_TEST_INIT	0x0002	/* Care-of Test Init */
#define IP6M_HOME_TEST		0x0003	/* Home Test */
#define IP6M_CAREOF_TEST	0x0004	/* Care-of Test */
#define IP6M_BINDING_UPDATE	0x0005	/* Binding Update */
#define IP6M_BINDING_ACK	0x0006	/* Binding Acknowledgement */
#define IP6M_BINDING_ERROR	0x0007	/* Binding Error */

/* Mobility Header Options */
#define IP6MOPT_MINLEN		2
#define IP6MOPT_PAD1          0x0
#define IP6MOPT_PADN          0x1
#define IP6MOPT_UI            0x2
#define IP6MOPT_UI_MINLEN       4
#define IP6MOPT_ALTCOA        0x3
#define IP6MOPT_ALTCOA_MINLEN  18
#define IP6MOPT_NONCEID       0x4
#define IP6MOPT_NONCEID_MINLEN  6
#define IP6MOPT_AUTH          0x5
#define IP6MOPT_AUTH_MINLEN     2 /* 2+len */

void
mobility_opt_print(const u_char *bp, int len)
{
	int i;
	int optlen;

	for (i = 0; i < len; i += optlen) {
		if (bp[i] == IP6MOPT_PAD1)
			optlen = 1;
		else {
			if (i + 1 < len)
				optlen = bp[i + 1];
			else
				goto trunc;
			if (optlen < IP6MOPT_MINLEN)
				optlen = IP6MOPT_MINLEN;	/* XXX */
		}
		if (i + optlen > len)
			goto trunc;

		switch (bp[i]) {
		case IP6MOPT_PAD1:
			printf("(pad1)");
			break;
		case IP6MOPT_PADN:
			if (len - i < IP6MOPT_MINLEN) {
				printf("(padn: trunc)");
				goto trunc;
			}
			printf("(padn)");
			break;
		case IP6MOPT_UI:
			if (len - i < IP6MOPT_UI_MINLEN) {
				printf("(ui: trunc)");
				goto trunc;
			}
			printf("(ui: 0x%04x)", EXTRACT_16BITS(&bp[i+2]));
			break;
		case IP6MOPT_ALTCOA:
			if (len - i < IP6MOPT_ALTCOA_MINLEN) {
				printf("(altcoa: trunc)");
				goto trunc;
			}
			printf("(alt-CoA: %s)", ip6addr_string(&bp[i+2]));
			break;
		case IP6MOPT_NONCEID:
			if (len - i < IP6MOPT_NONCEID_MINLEN) {
				printf("(ni: trunc)");
				goto trunc;
			}
			printf("(ni: ho=0x%04x ci=0x%04x)",
				EXTRACT_16BITS(&bp[i+2]),
				EXTRACT_16BITS(&bp[i+4]));
			break;
		case IP6MOPT_AUTH:
			if (len - i < IP6MOPT_AUTH_MINLEN) {
				printf("(auth: trunc)");
				goto trunc;
			}
			printf("(auth spi: 0x%08x)",
				EXTRACT_32BITS(&bp[i+2]));
			break;
		default:
			if (len - i < IP6MOPT_MINLEN) {
				printf("(sopt_type %d: trunc)", bp[i]);
				goto trunc;
			}
			printf("(type-0x%02x: len=%d)", bp[i], bp[i + 1]);
			break;
		}
	}
	return;

trunc:
	printf("[trunc] ");
}

/*
 * Mobility Header
 */
int
mobility_print(const u_char *bp, const u_char *bp2)
{
	const struct ip6_mobility *mh;
	const struct ip6_hdr *ip6;
	const u_char *ep;
	int mhlen, hlen, type;

	mh = (struct ip6_mobility *)bp;
	ip6 = (struct ip6_hdr *)bp2;

	/* 'ep' points to the end of available data. */
	ep = snapend;

	TCHECK(mh->ip6m_len);
	mhlen = (int)(mh->ip6m_len << 3);
	if (mhlen < IP6M_MINLEN)
		mhlen = IP6M_MINLEN;	/* XXX */

	/* XXX ip6m_cksum */

	TCHECK(mh->ip6m_type);
	type = ntohs(mh->ip6m_type);
	switch (type) {
	case IP6M_BINDING_REQUEST:
		printf("mobility: BRR");
		hlen = IP6M_MINLEN;
		break;
	case IP6M_HOME_TEST_INIT:
	case IP6M_CAREOF_TEST_INIT:
		printf("mobility: %soTI",
			type == IP6M_HOME_TEST_INIT ? "H" : "C");
		hlen = IP6M_MINLEN;
		TCHECK2(*mh, hlen + 4);
		printf(" cookie=0x%x", EXTRACT_32BITS(&bp[hlen]));
		hlen += 4;
		break;
	case IP6M_HOME_TEST:
	case IP6M_CAREOF_TEST:
		printf("mobility: %soT",
			type == IP6M_HOME_TEST ? "H" : "C");
		hlen = IP6M_MINLEN;
		TCHECK2(*mh, hlen + 2);
		printf(" nonce id=0x%x", EXTRACT_16BITS(&bp[hlen]));
		hlen += 2;
		/* Reserved (16bits) */
		hlen += 2;
		TCHECK2(*mh, hlen + 4);
		printf(" mobile cookie=0x%x", EXTRACT_32BITS(&bp[hlen]));
		hlen += 4;
		/* Home(Care-of) Cookie (128 bits) */
		hlen += 16;
		break;
	case IP6M_BINDING_UPDATE:
		printf("mobility: BU");
		TCHECK(mh->ip6m_data8[0]);
		if (mh->ip6m_data8[0] & 0xf0)
			printf(" ");
		if (mh->ip6m_data8[0] & 0x80)
			printf("A");
		if (mh->ip6m_data8[0] & 0x40)
			printf("H");
		if (mh->ip6m_data8[0] & 0x20)
			printf("S");
		if (mh->ip6m_data8[0] & 0x10)
			printf("D");
		hlen = IP6M_MINLEN;
		TCHECK2(*mh, hlen + 2);
		printf(" seq#=%d", EXTRACT_16BITS(&bp[hlen]));
		hlen += 2;
		/* Reserved (16bits) */
		hlen += 2;
		TCHECK2(*mh, hlen + 4);
		printf(" lifetime=%d", EXTRACT_32BITS(&bp[hlen]));
		hlen += 4;
		TCHECK2(*mh, hlen + 16);
		printf(" homeaddr %s", ip6addr_string(&bp[hlen]));
		hlen += 16;
		break;
	case IP6M_BINDING_ACK:
		printf("mobility: BA");
		TCHECK(mh->ip6m_data8[0]);
		printf(" status=%d", mh->ip6m_data8[0]);
		hlen = IP6M_MINLEN;
		TCHECK2(*mh, hlen + 2);
		printf(" seq#=%d", EXTRACT_16BITS(&bp[hlen]));
		hlen += 2;
		/* Reserved (16bits) */
		hlen += 2;
		TCHECK2(*mh, hlen + 4);
		printf(" lifetime=%d", EXTRACT_32BITS(&bp[hlen]));
		hlen += 4;
		TCHECK2(*mh, hlen + 4);
		printf(" refresh=%d", ntohl(*(u_int32_t *)&bp[hlen]));
		hlen += 4;
		break;
	case IP6M_BINDING_ERROR:
		printf("mobility: BE");
		TCHECK(mh->ip6m_data8[0]);
		printf(" status=%d", mh->ip6m_data8[0]);
		hlen = IP6M_MINLEN;
		TCHECK2(*mh, hlen + 16);
		printf(" homeaddr %s", ip6addr_string(&bp[hlen]));
		hlen += 16;
		break;
	default:
		printf("mobility: type-#%d len=%d", type, mh->ip6m_len);
		return(mhlen);
		break;
	}
    	if (vflag)
		mobility_opt_print(&bp[hlen], mhlen - hlen);

	return(mhlen);

 trunc:
	fputs("[|MOBILITY]", stdout);
	return(mhlen);
}
#endif /* INET6 */
