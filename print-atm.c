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
    "@(#) $Header: /tcpdump/master/tcpdump/print-atm.c,v 1.27 2002-12-04 19:12:39 hannes Exp $ (LBL)";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <tcpdump-stdinc.h>

#include <stdio.h>
#include <pcap.h>
#include <string.h>

#include "interface.h"
#include "extract.h"
#include "addrtoname.h"
#include "ethertype.h"
#include "atm.h"
#include "atmuni31.h"

#include "ether.h"

/*
 * This is the top level routine of the printer.  'p' points
 * to the LLC/SNAP header of the packet, 'h->ts' is the timestamp,
 * 'h->length' is the length of the packet off the wire, and 'h->caplen'
 * is the number of bytes actually captured.
 */
void
atm_if_print(u_char *user _U_, const struct pcap_pkthdr *h, const u_char *p)
{
	u_int caplen = h->caplen;
	u_int length = h->len;

	++infodelay;
	ts_print(&h->ts);

	if (caplen < 8) {
		printf("[|atm]");
		goto out;
	}

	/*
	 * Some printers want to check that they're not walking off the
	 * end of the packet.
	 * Rather than pass it all the way down, we set this global.
	 */
	snapend = p + caplen;

	if (EXTRACT_24BITS(p) == 0xaaaa03) {
		/*
		 * XXX - assume 802.6 MAC header from Fore driver.
		 * XXX - should we also assume it's not a MAC header
		 * if it begins with 0xfe 0xfe 0x03, for RFC 2684
		 * routed NLPID-formatted PDUs?
		 */
		if (eflag)
			printf("%08x%08x %08x%08x ",
			       EXTRACT_32BITS(p),
			       EXTRACT_32BITS(p+4),
			       EXTRACT_32BITS(p+8),
			       EXTRACT_32BITS(p+12));
		p += 20;
		length -= 20;
		caplen -= 20;
	}

        /* lets call into the generic LLC handler */
	llc_print(p, length, caplen, NULL, NULL, NULL);

	if (xflag)
		default_print(p, caplen);
 out:
	putchar('\n');
}

/*
 * ATM signalling.
 */
static struct tok msgtype2str[] = {
	{ CALL_PROCEED,		"Call_proceeding" },
	{ CONNECT,		"Connect" },
	{ CONNECT_ACK,		"Connect_ack" },
	{ SETUP,		"Setup" },
	{ RELEASE,		"Release" },
	{ RELEASE_DONE,		"Release_complete" },
	{ RESTART,		"Restart" },
	{ RESTART_ACK,		"Restart_ack" },
	{ STATUS,		"Status" },
	{ STATUS_ENQ,		"Status_enquiry" },
	{ ADD_PARTY,		"Add_party" },
	{ ADD_PARTY_ACK,	"Add_party_ack" },
	{ ADD_PARTY_REJ,	"Add_party_reject" },
	{ DROP_PARTY,		"Drop_party" },
	{ DROP_PARTY_ACK,	"Drop_party_ack" },
	{ 0,			NULL }
};

static void
sig_print(const u_char *p, int caplen)
{
	bpf_u_int32 call_ref;

	if (caplen < PROTO_POS) {
		printf("[|atm]");
		return;
	}
	if (p[PROTO_POS] == Q2931) {
		/*
		 * protocol:Q.2931 for User to Network Interface 
		 * (UNI 3.1) signalling
		 */
		printf("Q.2931");
		if (caplen < MSG_TYPE_POS) {
			printf(" [|atm]");
			return;
		}
		printf(":%s ",
		    tok2str(msgtype2str, "msgtype#%d", p[MSG_TYPE_POS]));

		if (caplen < CALL_REF_POS+3) {
			printf("[|atm]");
			return;
		}
		call_ref = EXTRACT_24BITS(&p[CALL_REF_POS]);
		printf("CALL_REF:0x%06x", call_ref);
	} else {
		/* SCCOP with some unknown protocol atop it */
		printf("SSCOP, proto %d ", p[PROTO_POS]);
	}
}

/*
 * Print an ATM PDU (such as an AAL5 PDU).
 */
void
atm_print(u_int vpi, u_int vci, u_int traftype, const u_char *p, u_int length,
    u_int caplen)
{
	if (eflag)
		printf("VPI:%u VCI:%u ", vpi, vci);

	/*
	 * Some printers want to check that they're not walking off the
	 * end of the packet.
	 * Rather than pass it all the way down, we set this global.
	 */
	snapend = p + caplen;

	if (vpi == 0) {
		switch (vci) {

		case PPC:
			sig_print(p, caplen);
			goto out;

		case BCC:
			printf("broadcast sig: ");
			goto out;

		case OAMF4SC:
			printf("oamF4(segment): ");
			goto out;

		case OAMF4EC:
			printf("oamF4(end): ");
			goto out;

		case METAC:
			printf("meta: ");
			goto out;

		case ILMIC:
			printf("ilmi: ");
			snmp_print(p, length);
			goto out;
		}
	}

	switch (traftype) {

	case ATM_LLC:
	default:
		/*
		 * Assumes traffic is LLC if unknown.
                 * call into the generic LLC handler
		 */
		llc_print(p, length, caplen, NULL, NULL, NULL);
		break;

	case ATM_LANE:
		lane_print(p, length, caplen);
		break;
	}

out:
	if (xflag)
		default_print(p, caplen);
}
