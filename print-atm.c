/*
 * Copyright (c) 1994, 1995, 1996, 1997
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
    "@(#) $Header: /tcpdump/master/tcpdump/print-atm.c,v 1.23 2002-04-07 10:05:40 guy Exp $ (LBL)";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/param.h>
#include <sys/time.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <stdio.h>
#include <pcap.h>
#include <string.h>

#include "interface.h"
#include "addrtoname.h"
#include "ethertype.h"

#include "ether.h"

/*
 * Print an RFC 1483 LLC-encapsulated ATM frame.
 */
static void
atm_llc_print(const u_char *p, int length, int caplen)
{
	struct ether_header ehdr;
	u_short ether_type;
	u_short extracted_ethertype;

	ether_type = p[6] << 8 | p[7];

	/*
	 * Fake up an Ethernet header for the benefit of printers that
	 * insist on "packetp" pointing to an Ethernet header.
	 */
	memset(&ehdr, '\0', sizeof ehdr);

	/*
	 * Some printers want to get back at the ethernet addresses,
	 * and/or check that they're not walking off the end of the packet.
	 * Rather than pass them all the way down, we set these globals.
	 */
	snapend = p + caplen;
	/*
	 * Actually, the only printers that use packetp are print-arp.c
	 * and print-bootp.c, and they assume that packetp points to an
	 * Ethernet header.  The right thing to do is to fix them to know
	 * which link type is in use when they excavate. XXX
	 */
	packetp = (u_char *)&ehdr;

	if (!llc_print(p, length, caplen, ESRC(&ehdr), EDST(&ehdr),
	    &extracted_ethertype)) {
		/* ether_type not known, print raw packet */
		if (extracted_ethertype) {
			printf("(LLC %s) ",
		etherproto_string(htons(extracted_ethertype)));
		}
		if (!xflag && !qflag)
			default_print(p, caplen);
	}
}

/*
 * This is the top level routine of the printer.  'p' is the points
 * to the LLC/SNAP header of the packet, 'tvp' is the timestamp,
 * 'length' is the length of the packet off the wire, and 'caplen'
 * is the number of bytes actually captured.
 */
void
atm_if_print(u_char *user, const struct pcap_pkthdr *h, const u_char *p)
{
	u_int caplen = h->caplen;
	u_int length = h->len;

	++infodelay;
	ts_print(&h->ts);

	if (caplen < 8) {
		printf("[|atm]");
		goto out;
	}
	if (p[0] != 0xaa || p[1] != 0xaa || p[2] != 0x03) {
		/*
		 * XXX - assume 802.6 MAC header from Fore driver.
		 * XXX - should we also assume it's not a MAC header
		 * if it begins with 0xfe 0xfe 0x03, for RFC 2684
		 * routed NLPID-formatted PDUs?
		 */
		if (eflag)
			printf("%04x%04x %04x%04x ",
			       p[0] << 24 | p[1] << 16 | p[2] << 8 | p[3],
			       p[4] << 24 | p[5] << 16 | p[6] << 8 | p[7],
			       p[8] << 24 | p[9] << 16 | p[10] << 8 | p[11],
			       p[12] << 24 | p[13] << 16 | p[14] << 8 | p[15]);
		p += 20;
		length -= 20;
		caplen -= 20;
	}
	atm_llc_print(p, length, caplen);
	if (xflag)
		default_print(p, caplen);
 out:
	putchar('\n');
	--infodelay;
	if (infoprint)
		info(0);
}
