/*	$OpenBSD: print-pflog.c,v 1.9 2001/09/18 14:52:53 jakob Exp $	*/

/*
 * Copyright (c) 1990, 1991, 1993, 1994, 1995, 1996
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
    "@(#) $Header: /tcpdump/master/tcpdump/print-pflog.c,v 1.1 2002-02-05 10:07:39 guy Exp $ (LBL)";
#endif

#include <sys/param.h>
#include <sys/time.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <stdio.h>
#include <pcap.h>

#include "interface.h"
#include "addrtoname.h"

/* The header in OpenBSD pflog files. */

struct pfloghdr {
	u_int32_t af;
	char	ifname[16];
	int16_t rnr;
	u_int16_t reason;
	u_int16_t action;
	u_int16_t dir;
};
#define PFLOG_HDRLEN    sizeof(struct pfloghdr)

/* Actions */
#define PF_PASS  0
#define PF_DROP  1
#define PF_SCRUB 2

/* Directions */
#define PF_IN  0
#define PF_OUT 1

static struct tok pf_reasons[] = {
	{ 0,	"match" },
	{ 1,	"bad-offset" },
	{ 2,	"fragment" },
	{ 3,	"short" },
	{ 4,	"normalize" },
	{ 5,	"memory" },
	{ 0,	NULL }
};

static struct tok pf_actions[] = {
	{ PF_PASS,	"pass" },
	{ PF_DROP,	"drop" },
	{ PF_SCRUB,	"scrub" },
	{ 0,		NULL }
};

static struct tok pf_directions[] = {
	{ PF_IN,	"in" },
	{ PF_OUT,	"out" },
	{ 0,		NULL }
};

#define OPENBSD_AF_INET		2
#define OPENBSD_AF_INET6	24

static void
pflog_print(const struct pfloghdr *hdr)
{
	printf("rule %d/%s: %s %s on %s: ",
	    (short)ntohs(hdr->rnr),
	    tok2str(pf_reasons, "unkn(%u)", ntohs(hdr->reason)),
	    tok2str(pf_actions, "unkn(%u)", ntohs(hdr->action)),
	    tok2str(pf_directions, "unkn(%u)", ntohs(hdr->dir)),
	    hdr->ifname);
}

void
pflog_if_print(u_char *user, const struct pcap_pkthdr *h,
     register const u_char *p)
{
	u_int length = h->len;
	u_int caplen = h->caplen;
	const struct pfloghdr *hdr;
	u_int8_t af;

	ts_print(&h->ts);

	if (caplen < PFLOG_HDRLEN) {
		printf("[|pflog]");
		goto out;
	}

	/*
	 * Some printers want to get back at the link level addresses,
	 * and/or check that they're not walking off the end of the packet.
	 * Rather than pass them all the way down, we set these globals.
	 */
	packetp = p;
	snapend = p + caplen;

	hdr = (const struct pfloghdr *)p;
	if (eflag)
		pflog_print(hdr);
	af = ntohl(hdr->af);
	length -= PFLOG_HDRLEN;
	caplen -= PFLOG_HDRLEN;
	p += PFLOG_HDRLEN;
	switch (af) {

	case OPENBSD_AF_INET:
		ip_print(p, length);
		break;

#ifdef INET6
	case OPENBSD_AF_INET6:
		ip6_print(p, length);
		break;
#endif

	default:
		/* address family not handled, print raw packet */
		if (!eflag)
			pflog_print(hdr);
		if (!xflag && !qflag)
			default_print(p, caplen);
	}

	if (xflag)
		default_print(p, caplen);
out:
	putchar('\n');
	--infodelay;
	if (infoprint)
		info(0);
}
