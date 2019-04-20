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

/* \summary: Marvell (Ethertype) Distributed Switch Architecture printer */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "netdissect-stdinc.h"

#include "netdissect.h"
#include "ethertype.h"
#include "addrtoname.h"
#include "extract.h"

/*
 * Format of (Ethertyped or not) DSA tagged frames:
 *
 *      7   6   5   4   3   2   1   0  
 *    .   .   .   .   .   .   .   .   .
 *  0 +---+---+---+---+---+---+---+---+
 *    |   Ether Destination Address   |
 * +6 +---+---+---+---+---+---+---+---+
 *    |     Ether Source Address      |
 * +6 +---+---+---+---+---+---+---+---+  +-
 *    |  Prog. DSA Ether Type [15:8]  |  | (8-byte) EDSA Tag
 * +1 +---+---+---+---+---+---+---+---+  | Contains a programmable Ether type,
 *    |  Prog. DSA Ether Type [7:0]   |  | two reserved bytes (always 0),
 * +1 +---+---+---+---+---+---+---+---+  | and a standard DSA tag.
 *    |     Reserved (0x00 0x00)      |  |
 * +2 +---+---+---+---+---+---+---+---+  |  +-
 *    | Mode  |b29|    Src/Trg Dev    |  |  | (4-byte) DSA Tag
 * +1 +---+---+---+---+---+---+---+---+  |  | Contains a DSA tag mode,
 *    |Src/Trg Port/Trunk |b18|b17|b16|  |  | source or target switch device,
 * +1 +---+---+---+---+---+---+---+---+  |  | source or target port or trunk,
 *    | PRI [2:0] |b12|  VID [11:8]   |  |  | and misc (IEEE and FPri) bits.
 * +1 +---+---+---+---+---+---+---+---+  |  |
 *    |           VID [7:0]           |  |  |
 * +1 +---+---+---+---+---+---+---+---+  +- +-
 *    |       Ether Length/Type       |
 * +2 +---+---+---+---+---+---+---+---+
 *    .   .   .   .   .   .   .   .   .
 *
 * Mode: Forward, To_CPU, From_CPU, To_Sniffer
 * b29: (Source or Target) IEEE Tag Mode
 * b18: Forward's Src_Is_Trunk, To_CPU's Code[2], To_Sniffer's Rx_Sniff
 * b17: To_CPU's Code[1]
 * b16: Original frame's CFI
 * b12: To_CPU's Code[0]
 */

#define TOK(tag, byte, mask, shift) ((GET_U_1(&(((const u_char *) tag)[byte])) & (mask)) >> (shift))

#define DSA_LEN 4
#define DSA_MODE(tag) TOK(tag, 0, 0xc0, 6)
#define  DSA_MODE_TO_CPU 0x0
#define  DSA_MODE_FROM_CPU 0x1
#define  DSA_MODE_TO_SNIFFER 0x2
#define  DSA_MODE_FORWARD 0x3
#define DSA_TAGGED(tag) TOK(tag, 0, 0x20, 5)
#define DSA_DEV(tag) TOK(tag, 0, 0x1f, 0)
#define DSA_PORT(tag) TOK(tag, 1, 0xf8, 3)
#define DSA_TRUNK(tag) TOK(tag, 1, 0x04, 2)
#define DSA_RX_SNIFF(tag) TOK(tag, 1, 0x04, 2)
#define DSA_CFI(tag) TOK(tag, 1, 0x01, 0)
#define DSA_PRI(tag) TOK(tag, 2, 0xe0, 5)
#define DSA_VID(tag) ((u_short)((TOK(tag, 2, 0xe0, 5) << 8) | (TOK(tag, 3, 0xff, 0))))
#define DSA_CODE(tag) ((TOK(tag, 1, 0x06, 1) << 1) | TOK(tag, 2, 0x10, 4))

#define EDSA_LEN 8
#define EDSA_ETYPE(tag) ((u_short)((TOK(tag, 0, 0xff, 0) << 8) | (TOK(tag, 1, 0xff, 0))))

static const struct tok dsa_mode_values[] = {
	{ DSA_MODE_TO_CPU, "To CPU" },
	{ DSA_MODE_FROM_CPU, "From CPU" },
	{ DSA_MODE_TO_SNIFFER, "To Sniffer"},
	{ DSA_MODE_FORWARD, "Forward" },
	{ 0, NULL }
};

static const struct tok dsa_code_values[] = {
	{ 0x0, "BPDU (MGMT) Trap" },
	{ 0x1, "Frame2Reg" },
	{ 0x2, "IGMP/MLD Trap" },
	{ 0x3, "Policy Trap" },
	{ 0x4, "ARP Mirror" },
	{ 0x5, "Policy Mirror" },
	{ 0, NULL }
};

static u_int
dsa_if_print_full(netdissect_options *ndo, const struct pcap_pkthdr *h,
		  const u_char *p, u_int taglen)
{
	const u_char *edsa, *dsa;
	int save_eflag;
	int ret;

	if (h->caplen < 2*MAC_ADDR_LEN + taglen) {
		nd_print_trunc(ndo);
		return (h->caplen);
	}

	if (h->len < 2*MAC_ADDR_LEN + taglen) {
		nd_print_trunc(ndo);
		return (h->len);
	}

	if (taglen == EDSA_LEN) {
		edsa = p + 2*MAC_ADDR_LEN;
		dsa = edsa + 4;
	} else {
		edsa = NULL;
		dsa = p + 2*MAC_ADDR_LEN;
	}

	if (ndo->ndo_eflag) {
		ND_PRINT("%s > %s, ",
			 etheraddr_string(ndo, p + MAC_ADDR_LEN),
			 etheraddr_string(ndo, p));

		if (edsa) {
			ND_PRINT("Marvell EDSA ethertype 0x%04x (%s), ", EDSA_ETYPE(edsa),
				 tok2str(ethertype_values, "Unknown", EDSA_ETYPE(edsa)));
			ND_PRINT("rsvd %u %u, ", edsa[2], edsa[3]);
		} else {
			ND_PRINT("Marvell DSA ");
		}

		ND_PRINT("mode %s, ", tok2str(dsa_mode_values, "unknown", DSA_MODE(dsa)));

		switch (DSA_MODE(dsa)) {
		case DSA_MODE_FORWARD:
			ND_PRINT("dev %u, %s %u, ", DSA_DEV(dsa),
				 DSA_TRUNK(dsa) ? "trunk" : "port", DSA_PORT(dsa));
			break;
		case DSA_MODE_FROM_CPU:
			ND_PRINT("target dev %u, port %u, ",
				 DSA_DEV(dsa), DSA_PORT(dsa));
			break;
		case DSA_MODE_TO_CPU:
			ND_PRINT("source dev %u, port %u, ",
				 DSA_DEV(dsa), DSA_PORT(dsa));
			ND_PRINT("code %s, ",
				 tok2str(dsa_code_values, "reserved", DSA_CODE(dsa)));
			break;
		case DSA_MODE_TO_SNIFFER:
			ND_PRINT("source dev %u, port %u, ",
				 DSA_DEV(dsa), DSA_PORT(dsa));
			ND_PRINT("%s sniff, ",
				 DSA_RX_SNIFF(dsa) ? "ingress" : "egress");
			break;
		default:
			break;
		}

		ND_PRINT("%s, ", DSA_TAGGED(dsa) ? "tagged" : "untagged");
		ND_PRINT("%s", DSA_CFI(dsa) ? "CFI, " : "");
		ND_PRINT("VID %u, ", DSA_VID(dsa));
		ND_PRINT("FPri %u, ", DSA_PRI(dsa));
	} else {
		if (edsa) {
			ND_PRINT("EDSA 0x%04x, ", EDSA_ETYPE(edsa));
		} else {
			ND_PRINT("DSA ");
		}

		switch (DSA_MODE(dsa)) {
		case DSA_MODE_FORWARD:
			ND_PRINT("Forward %s %u.%u, ",
				 DSA_TRUNK(dsa) ? "trunk" : "port",
				 DSA_DEV(dsa), DSA_PORT(dsa));
			break;
		case DSA_MODE_FROM_CPU:
			ND_PRINT("CPU > port %u.%u, ",
				 DSA_DEV(dsa), DSA_PORT(dsa));
			break;
		case DSA_MODE_TO_CPU:
			ND_PRINT("port %u.%u > CPU, ",
				 DSA_DEV(dsa), DSA_PORT(dsa));
			break;
		case DSA_MODE_TO_SNIFFER:
			ND_PRINT("port %u.%u > %s Sniffer, ",
				 DSA_DEV(dsa), DSA_PORT(dsa),
				 DSA_RX_SNIFF(dsa) ? "Rx" : "Tx");
			break;
		default:
			break;
		}

		ND_PRINT("VLAN %u%c, ", DSA_VID(dsa), DSA_TAGGED(dsa) ? 't' : 'u');
	}

	/* We printed the Ethernet destination and source addresses already */
	save_eflag = ndo->ndo_eflag;
	ndo->ndo_eflag = 0;

	/* Parse the rest of the Ethernet header, and the frame payload,
	 * telling ether_hdr_len_print() how big the non-standard Ethernet
	 * header is.
	 *
	 * +-----------+-----------+---------------------+--------------+
	 * | MAC DA (6)| MAC SA (6)|DSA/EDSA tag (taglen)|Type/Length(2)|
	 * +-----------+-----------+---------------------+--------------+
	 */
	ret = ether_hdr_len_print(ndo, p, h->len, h->caplen, NULL, NULL,
				  2*MAC_ADDR_LEN + taglen + 2);

	ndo->ndo_eflag = save_eflag;

	return ret;
}

u_int
dsa_if_print(netdissect_options *ndo, const struct pcap_pkthdr *h, const u_char *p)
{
	ndo->ndo_protocol = "dsa";

	return dsa_if_print_full(ndo, h, p, DSA_LEN);
}

u_int
edsa_if_print(netdissect_options *ndo, const struct pcap_pkthdr *h, const u_char *p)
{
	ndo->ndo_protocol = "edsa";

	return dsa_if_print_full(ndo, h, p, EDSA_LEN);
}
