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

#ifndef lint
static const char rcsid[] =
    "@(#) $Header: /tcpdump/master/tcpdump/print-arp.c,v 1.55 2002-08-01 08:53:00 risso Exp $ (LBL)";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <tcpdump-stdinc.h>

#include <stdio.h>
#include <string.h>

#include "interface.h"
#include "addrtoname.h"
#include "ether.h"
#include "ethertype.h"
#include "extract.h"			/* must come after interface.h */

/*
 * Address Resolution Protocol.
 *
 * See RFC 826 for protocol description.  ARP packets are variable
 * in size; the arphdr structure defines the fixed-length portion.
 * Protocol type values are the same as those for 10 Mb/s Ethernet.
 * It is followed by the variable-sized fields ar_sha, arp_spa,
 * arp_tha and arp_tpa in that order, according to the lengths
 * specified.  Field names used correspond to RFC 826.
 */
struct	arp_pkthdr {
	u_short	ar_hrd;		/* format of hardware address */
#define ARPHRD_ETHER 	1	/* ethernet hardware format */
#define ARPHRD_IEEE802	6	/* token-ring hardware format */
#define ARPHRD_ARCNET	7	/* arcnet hardware format */
#define ARPHRD_FRELAY 	15	/* frame relay hardware format */
#define ARPHRD_STRIP 	23	/* Ricochet Starmode Radio hardware format */
#define ARPHRD_IEEE1394	24	/* IEEE 1394 (FireWire) hardware format */
	u_short	ar_pro;		/* format of protocol address */
	u_char	ar_hln;		/* length of hardware address */
	u_char	ar_pln;		/* length of protocol address */
	u_short	ar_op;		/* one of: */
#define	ARPOP_REQUEST	1	/* request to resolve address */
#define	ARPOP_REPLY	2	/* response to previous request */
#define	ARPOP_REVREQUEST 3	/* request protocol address given hardware */
#define	ARPOP_REVREPLY	4	/* response giving protocol address */
#define ARPOP_INVREQUEST 8 	/* request to identify peer */
#define ARPOP_INVREPLY	9	/* response identifying peer */
/*
 * The remaining fields are variable in size,
 * according to the sizes above.
 */
#ifdef COMMENT_ONLY
	u_char	ar_sha[];	/* sender hardware address */
	u_char	ar_spa[];	/* sender protocol address */
	u_char	ar_tha[];	/* target hardware address */
	u_char	ar_tpa[];	/* target protocol address */
#endif
#define ar_sha(ap)	(((const u_char *)((ap)+1))+0)
#define ar_spa(ap)	(((const u_char *)((ap)+1))+  (ap)->ar_hln)
#define ar_tha(ap)	(((const u_char *)((ap)+1))+  (ap)->ar_hln+(ap)->ar_pln)
#define ar_tpa(ap)	(((const u_char *)((ap)+1))+2*(ap)->ar_hln+(ap)->ar_pln)
};

#define ARP_HDRLEN	8

#define HRD(ap) ((ap)->ar_hrd)
#define HLN(ap) ((ap)->ar_hln)
#define PLN(ap) ((ap)->ar_pln)
#define OP(ap)  ((ap)->ar_op)
#define PRO(ap) ((ap)->ar_pro)
#define SHA(ap) (ar_sha(ap))
#define SPA(ap) (ar_spa(ap))
#define THA(ap) (ar_tha(ap))
#define TPA(ap) (ar_tpa(ap))

/*
 * ATM Address Resolution Protocol.
 *
 * See RFC 2225 for protocol description.  ARP packets are variable
 * in size; the arphdr structure defines the fixed-length portion.
 * Protocol type values are the same as those for 10 Mb/s Ethernet.
 * It is followed by the variable-sized fields ar_sha, arp_spa,
 * arp_tha and arp_tpa in that order, according to the lengths
 * specified.  Field names used correspond to RFC 826.
 */
struct	atmarp_pkthdr {
	u_short	ar_hrd;		/* format of hardware address */
#define ARPHRD_ATM2225	19	/* ATM (RFC 2225) */
	u_short	ar_pro;		/* format of protocol address */
	u_char	ar_shtl;	/* length of hardware address */
	u_char	ar_sstl;	/* length of hardware address */
	u_short	ar_op;		/* same as regular ARP */
	u_char	ar_spln;
	u_char	ar_thtl;
	u_char	ar_tstl;
	u_char	ar_tpln;
/*
 * The remaining fields are variable in size,
 * according to the sizes above.
 */
#ifdef COMMENT_ONLY
	u_char	ar_sha[];	/* sender hardware address */
	u_char	ar_spa[];	/* sender protocol address */
	u_char	ar_tha[];	/* target hardware address */
	u_char	ar_tpa[];	/* target protocol address */
#endif
#define ar_sha(ap)	(((const u_char *)((ap)+1))+0)
#define ar_spa(ap)	(((const u_char *)((ap)+1))+  (ap)->ar_hln)
#define ar_tha(ap)	(((const u_char *)((ap)+1))+  (ap)->ar_hln+(ap)->ar_pln)
#define ar_tpa(ap)	(((const u_char *)((ap)+1))+2*(ap)->ar_hln+(ap)->ar_pln)
};

static u_char ezero[6];

static void
atmarp_print(const u_char *bp, u_int length, u_int caplen)
{
	const struct arp_pkthdr *ap;
	u_short pro, hrd, op;

	ap = (const struct arp_pkthdr *)bp;
	TCHECK(*ap);
	if ((const u_char *)(ar_tpa(ap) + PLN(ap)) > snapend) {
		(void)printf("truncated-arp");
		default_print((const u_char *)ap, length);
		return;
	}

	hrd = EXTRACT_16BITS(&HRD(ap));
	if (hrd == ARPHRD_ATM2225)
		atmarp_print(bp, length, caplen);
	pro = EXTRACT_16BITS(&PRO(ap));
	op = EXTRACT_16BITS(&OP(ap));

	if (pro != ETHERTYPE_IP && pro != ETHERTYPE_TRAIL) {
		(void)printf("arp-#%d for proto #%d (%d) hardware #%d (%d)",
				op, pro, PLN(ap), hrd, HLN(ap));
		return;
	}
	if (pro == ETHERTYPE_TRAIL)
		(void)printf("trailer-");
	switch (op) {

	case ARPOP_REQUEST:
		(void)printf("arp who-has %s", ipaddr_string(TPA(ap)));
		if (memcmp((const char *)ezero, (const char *)THA(ap), HLN(ap)) != 0)
			(void)printf(" (%s)",
			    linkaddr_string(THA(ap), HLN(ap)));
		(void)printf(" tell %s", ipaddr_string(SPA(ap)));
		break;

	case ARPOP_REPLY:
		(void)printf("arp reply %s", ipaddr_string(SPA(ap)));
		(void)printf(" is-at %s", linkaddr_string(SHA(ap), HLN(ap)));
		break;

	case ARPOP_REVREQUEST:
		(void)printf("rarp who-is %s tell %s",
			linkaddr_string(THA(ap), HLN(ap)),
			linkaddr_string(SHA(ap), HLN(ap)));
		break;

	case ARPOP_REVREPLY:
		(void)printf("rarp reply %s at %s",
			linkaddr_string(THA(ap), HLN(ap)),
			ipaddr_string(TPA(ap)));
		break;

	case ARPOP_INVREQUEST:
		(void)printf("invarp who-is %s tell %s",
			linkaddr_string(THA(ap), HLN(ap)),
			linkaddr_string(SHA(ap), HLN(ap)));
		break;

	case ARPOP_INVREPLY:
		(void)printf("invarp reply %s at %s",
			linkaddr_string(THA(ap), HLN(ap)),
			ipaddr_string(TPA(ap)));
		break;

	default:
		(void)printf("arp-#%d", op);
		default_print((const u_char *)ap, caplen);
		return;
	}
	if (hrd != ARPHRD_ETHER)
		printf(" hardware #%d", hrd);
	return;
trunc:
	(void)printf("[|arp]");
}

void
arp_print(const u_char *bp, u_int length, u_int caplen)
{
	const struct arp_pkthdr *ap;
	u_short pro, hrd, op;

	ap = (const struct arp_pkthdr *)bp;
	TCHECK(*ap);
	if ((const u_char *)(ar_tpa(ap) + PLN(ap)) > snapend) {
		(void)printf("truncated-arp");
		default_print((const u_char *)ap, length);
		return;
	}

	hrd = EXTRACT_16BITS(&HRD(ap));
	if (hrd == ARPHRD_ATM2225)
		atmarp_print(bp, length, caplen);
	pro = EXTRACT_16BITS(&PRO(ap));
	op = EXTRACT_16BITS(&OP(ap));

	if (pro != ETHERTYPE_IP && pro != ETHERTYPE_TRAIL) {
		(void)printf("arp-#%d for proto #%d (%d) hardware #%d (%d)",
				op, pro, PLN(ap), hrd, HLN(ap));
		return;
	}
	if (pro == ETHERTYPE_TRAIL)
		(void)printf("trailer-");
	switch (op) {

	case ARPOP_REQUEST:
		(void)printf("arp who-has %s", ipaddr_string(TPA(ap)));
		if (memcmp((const char *)ezero, (const char *)THA(ap), HLN(ap)) != 0)
			(void)printf(" (%s)",
			    linkaddr_string(THA(ap), HLN(ap)));
		(void)printf(" tell %s", ipaddr_string(SPA(ap)));
		break;

	case ARPOP_REPLY:
		(void)printf("arp reply %s", ipaddr_string(SPA(ap)));
		(void)printf(" is-at %s", linkaddr_string(SHA(ap), HLN(ap)));
		break;

	case ARPOP_REVREQUEST:
		(void)printf("rarp who-is %s tell %s",
			linkaddr_string(THA(ap), HLN(ap)),
			linkaddr_string(SHA(ap), HLN(ap)));
		break;

	case ARPOP_REVREPLY:
		(void)printf("rarp reply %s at %s",
			linkaddr_string(THA(ap), HLN(ap)),
			ipaddr_string(TPA(ap)));
		break;

	case ARPOP_INVREQUEST:
		(void)printf("invarp who-is %s tell %s",
			linkaddr_string(THA(ap), HLN(ap)),
			linkaddr_string(SHA(ap), HLN(ap)));
		break;

	case ARPOP_INVREPLY:
		(void)printf("invarp reply %s at %s",
			linkaddr_string(THA(ap), HLN(ap)),
			ipaddr_string(TPA(ap)));
		break;

	default:
		(void)printf("arp-#%d", op);
		default_print((const u_char *)ap, caplen);
		return;
	}
	if (hrd != ARPHRD_ETHER)
		printf(" hardware #%d", hrd);
	return;
trunc:
	(void)printf("[|arp]");
}
