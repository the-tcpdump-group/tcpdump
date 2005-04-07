/*
 * Copyright (c) 1990, 1991, 1993, 1994, 1995, 1996, 1997
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
static const char rcsid[] _U_ =
    "@(#) $Header: /tcpdump/master/tcpdump/print-chdlc.c,v 1.33 2005-04-07 23:07:33 hannes Exp $ (LBL)";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <tcpdump-stdinc.h>

#include <pcap.h>
#include <stdio.h>

#include "interface.h"
#include "addrtoname.h"
#include "ethertype.h"
#include "extract.h"
#include "ppp.h"
#include "chdlc.h"

static void chdlc_slarp_print(const u_char *, u_int);

/* Standard CHDLC printer */
u_int
chdlc_if_print(const struct pcap_pkthdr *h, register const u_char *p)
{
	register u_int length = h->len;
	register u_int caplen = h->caplen;
	const struct ip *ip;
	u_int proto;

	if (caplen < CHDLC_HDRLEN) {
		printf("[|chdlc]");
		return (caplen);
	}

	proto = EXTRACT_16BITS(&p[2]);
	if (eflag) {
		switch (p[0]) {
		case CHDLC_UNICAST:
			printf("unicast ");
			break;
		case CHDLC_BCAST:
			printf("bcast ");
			break;
		default:
			printf("0x%02x ", p[0]);
			break;
		}
		printf("%d %04x: ", length, proto);
	}

	length -= CHDLC_HDRLEN;
	ip = (const struct ip *)(p + CHDLC_HDRLEN);
	switch (proto) {
	case ETHERTYPE_IP:
		ip_print(gndo, (const u_char *)ip, length);
		break;
#ifdef INET6
	case ETHERTYPE_IPV6:
		ip6_print((const u_char *)ip, length);
		break;
#endif
	case CHDLC_TYPE_SLARP:
		chdlc_slarp_print((const u_char *)ip, length);
		break;
#if 0
	case CHDLC_TYPE_CDP:
		chdlc_cdp_print((const u_char *)ip, length);
		break;
#endif
        case ETHERTYPE_MPLS:
        case ETHERTYPE_MPLS_MULTI:
                mpls_print((const u_char *)(ip), length);
		break;
        case ETHERTYPE_ISO:
                /* is the fudge byte set ? lets verify by spotting ISO headers */
                if (*(p+CHDLC_HDRLEN+1) == 0x81 ||
                    *(p+CHDLC_HDRLEN+1) == 0x82 ||
                    *(p+CHDLC_HDRLEN+1) == 0x83)
                    isoclns_print(p+CHDLC_HDRLEN+1, length-1, length-1);
                else
                    isoclns_print(p+CHDLC_HDRLEN, length, length);
                break;
	default:
                printf("unknown CHDLC protocol (0x%04x)", proto);
                break;
	}

	return (CHDLC_HDRLEN);
}

struct cisco_slarp {
	u_int8_t code[4];
#define SLARP_REQUEST	0
#define SLARP_REPLY	1
#define SLARP_KEEPALIVE	2
	union {
		struct {
			u_int8_t addr[4];
			u_int8_t mask[4];
			u_int8_t unused[6];
		} addr;
		struct {
			u_int8_t myseq[4];
			u_int8_t yourseq[4];
			u_int8_t rel[2];
			u_int8_t t1[2];
			u_int8_t t2[2];
		} keep;
	} un;
};

#define SLARP_LEN	18

static void
chdlc_slarp_print(const u_char *cp, u_int length)
{
	const struct cisco_slarp *slarp;

        printf("SLARP (length: %u), ",length);
	if (length < SLARP_LEN)
		goto trunc;

	slarp = (const struct cisco_slarp *)cp;
	TCHECK(*slarp);
	switch (EXTRACT_32BITS(&slarp->code)) {
	case SLARP_REQUEST:
		printf("request");
                /* ok we do not know it - but lets at least dump it */
                print_unknown_data(cp+4,"\n\t",length-4);
		break;
	case SLARP_REPLY:
		printf("reply %s/%s",
			ipaddr_string(&slarp->un.addr.addr),
			ipaddr_string(&slarp->un.addr.mask));
		break;
	case SLARP_KEEPALIVE:
		printf("keepalive: mineseen=0x%08x, yourseen=0x%08x",
			EXTRACT_32BITS(&slarp->un.keep.myseq),
			EXTRACT_32BITS(&slarp->un.keep.yourseq));
		printf(", reliability=0x%04x, t1=%d.%d",
			EXTRACT_16BITS(&slarp->un.keep.rel),
			EXTRACT_16BITS(&slarp->un.keep.t1),
			EXTRACT_16BITS(&slarp->un.keep.t2));
		break;
	default:
		printf("0x%02x unknown", EXTRACT_32BITS(&slarp->code));
                if (vflag <= 1)
                    print_unknown_data(cp+4,"\n\t",length-4);
		break;
	}

	if (SLARP_LEN < length && vflag)
		printf(", (trailing junk: %d bytes)", length - SLARP_LEN);
        if (vflag > 1)
            print_unknown_data(cp+4,"\n\t",length-4);
	return;

trunc:
	printf("[|slarp]");
}


/*
 * Local Variables:
 * c-style: whitesmith
 * c-basic-offset: 8
 * End:
 */
