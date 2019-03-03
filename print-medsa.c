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

/* \summary: Marvell Extended Distributed Switch Architecture (MEDSA) printer */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "netdissect-stdinc.h"

#include "netdissect.h"
#include "ethertype.h"
#include "addrtoname.h"
#include "extract.h"

struct	ether_header {
	nd_mac_addr	ether_dhost;
	nd_mac_addr	ether_shost;
	nd_uint16_t	ether_length_type;
};

#define ETHER_SA_OFFSET		12

/*
 * Marvell Extended Distributed Switch Archiecture.
 *
 * A Marvell proprietary header used for passing packets to/from
 * specific ports of a switch. There is no open specification of this
 * header, but is documented in the Marvell Switch data sheets. For
 * background, see:
 *
 * https://lwn.net/Articles/302333/
 */

struct mdsa_pkthdr {
	nd_uint8_t  tag_flags_dev;
	nd_uint8_t  port_trunc_codehi_cfi;
	nd_uint8_t  pri_vidhi_codelo;
	nd_uint8_t  vidlo;
};

#define MEDSA_TAG_LEN 6
#define MDSA_TAG_LEN 4
#define ETHER_TYPE_LEN 2

/* EDSA header bytes 0 and 1 are reserved and should contain 0 */
#define TAG(medsa)	(EXTRACT_U_1(mdsa->tag_flags_dev) >> 6)
#define TAG_TO_CPU	0
#define TAG_FROM_CPU	1
#define TAG_FORWARD	3
#define SRC_TAG(medsa)	((EXTRACT_U_1(mdsa->tag_flags_dev) >> 5) & 0x01)
#define SRC_DEV(medsa)	(EXTRACT_U_1(mdsa->tag_flags_dev) & 0x1f)
#define SRC_PORT(medsa)	((EXTRACT_U_1(mdsa->port_trunc_codehi_cfi) >> 3) & 0x01f)
#define TRUNK(medsa)	((EXTRACT_U_1(mdsa->port_trunc_codehi_cfi) >> 2) & 0x01)
#define CODE(medsa)	((EXTRACT_U_1(mdsa->port_trunc_codehi_cfi) & 0x06) |	\
			 ((EXTRACT_U_1(mdsa->pri_vidhi_codelo) >> 4) & 0x01))
#define CODE_BDPU	0
#define CODE_IGMP_MLD	2
#define CODE_ARP_MIRROR	4
#define CFI(medsa)	(EXTRACT_U_1(mdsa->port_trunc_codehi_cfi) & 0x01)
#define PRI(medsa)	(EXTRACT_U_1(mdsa->pri_vidhi_codelo) >> 5)
#define VID(medsa)	((u_short)(EXTRACT_U_1(mdsa->pri_vidhi_codelo) & 0xf) << 8 |	\
			  EXTRACT_U_1(mdsa->vidlo))

static const struct tok tag_values[] = {
	{ TAG_TO_CPU, "To_CPU" },
	{ TAG_FROM_CPU, "From_CPU" },
	{ TAG_FORWARD, "Forward" },
	{ 0, NULL },
};

static const struct tok code_values[] = {
	{ CODE_BDPU, "BDPU" },
	{ CODE_IGMP_MLD, "IGMP/MLD" },
	{ CODE_ARP_MIRROR, "APR_Mirror" },
	{ 0, NULL },
};

static void
mdsa_print_full(netdissect_options *ndo,
		const struct mdsa_pkthdr *mdsa,
		u_int caplen)
{
	u_char tag = TAG(mdsa);

	ND_PRINT("%s",
		  tok2str(tag_values, "Unknown (%u)", tag));

	switch (tag) {
	case TAG_TO_CPU:
		ND_PRINT(", %stagged", SRC_TAG(mdsa) ? "" : "un");
		ND_PRINT(", dev.port:vlan %u.%u:%u",
			  SRC_DEV(mdsa), SRC_PORT(mdsa), VID(mdsa));

		ND_PRINT(", %s",
			  tok2str(code_values, "Unknown (%u)", CODE(mdsa)));
		if (CFI(mdsa))
			ND_PRINT(", CFI");

		ND_PRINT(", pri %u: ", PRI(mdsa));
		break;
	case TAG_FROM_CPU:
		ND_PRINT(", %stagged", SRC_TAG(mdsa) ? "" : "un");
		ND_PRINT(", dev.port:vlan %u.%u:%u",
			  SRC_DEV(mdsa), SRC_PORT(mdsa), VID(mdsa));

		if (CFI(mdsa))
			ND_PRINT(", CFI");

		ND_PRINT(", pri %u: ", PRI(mdsa));
		break;
	case TAG_FORWARD:
		ND_PRINT(", %stagged", SRC_TAG(mdsa) ? "" : "un");
		if (TRUNK(mdsa))
			ND_PRINT(", dev.trunk:vlan %u.%u:%u",
				  SRC_DEV(mdsa), SRC_PORT(mdsa), VID(mdsa));
		else
			ND_PRINT(", dev.port:vlan %u.%u:%u",
				  SRC_DEV(mdsa), SRC_PORT(mdsa), VID(mdsa));

		if (CFI(mdsa))
			ND_PRINT(", CFI");

		ND_PRINT(", pri %u: ", PRI(mdsa));
		break;
	default:
		ND_DEFAULTPRINT((const u_char *)mdsa, caplen);
		return;
	}
}

void
medsa_print(netdissect_options *ndo,
	    const u_char *bp, u_int length, u_int caplen,
	    const struct lladdr_info *src, const struct lladdr_info *dst)
{
	const struct mdsa_pkthdr *mdsa;
	u_short ether_type;

	ndo->ndo_protocol = "medsa";
	ND_TCHECK_LEN(bp, MEDSA_TAG_LEN);

	/* First two bytes are reserved, skip them to the common part */
	mdsa = (const struct mdsa_pkthdr *)(bp + 2);

	if (!ndo->ndo_eflag)
		ND_PRINT("MEDSA %u.%u:%u: ",
			  SRC_DEV(mdsa), SRC_PORT(mdsa), VID(mdsa));
	else
		mdsa_print_full(ndo, mdsa, caplen);

	bp += MEDSA_TAG_LEN;
	length -= MEDSA_TAG_LEN;
	caplen -= MEDSA_TAG_LEN;

	/* Get the real ethertype of the frame, which follows directly
	   after the EDSA header. */
	ether_type = EXTRACT_BE_U_2(bp);

	bp += ETHER_TYPE_LEN;
	length -= ETHER_TYPE_LEN;
	caplen -= ETHER_TYPE_LEN;

	if (ether_type <= MAX_ETHERNET_LENGTH_VAL) {
		/* Try to print the LLC-layer header & higher layers */
		if (llc_print(ndo, bp, length, caplen, src, dst) < 0) {
			/* packet type not known, print raw packet */
			if (!ndo->ndo_suppress_default_print)
				ND_DEFAULTPRINT(bp, caplen);
		}
	} else {
		if (ndo->ndo_eflag)
			ND_PRINT("ethertype %s (0x%04x) ",
				  tok2str(ethertype_values, "Unknown",
					  ether_type),
				  ether_type);
		if (ethertype_print(ndo, ether_type, bp, length, caplen, src, dst) == 0) {
			/* ether_type not known, print raw packet */
			if (!ndo->ndo_eflag)
				ND_PRINT("ethertype %s (0x%04x) ",
					  tok2str(ethertype_values, "Unknown",
						  ether_type),
					  ether_type);

			if (!ndo->ndo_suppress_default_print)
				ND_DEFAULTPRINT(bp, caplen);
		}
	}
	return;
trunc:
	nd_print_trunc(ndo);
}

/* The DSA tag is 4 bytes. It has the same content as the last 4 bytes
 * of the EDSA tag.
 */

u_int
mdsa_tag_if_print(netdissect_options *ndo, const struct pcap_pkthdr *h,
		  const u_char *bp)
{
	const struct mdsa_pkthdr *mdsa;
	const struct ether_header *ehp;
	int old_eflag = ndo->ndo_eflag;
	u_int caplen = h->caplen;
	u_int length = h->len;
	int ret;

	ndo->ndo_protocol = "mdsa";
	if (caplen < ETHER_SA_OFFSET + MDSA_TAG_LEN) {
		nd_print_trunc(ndo);
		return (caplen);
	}

	if (length < ETHER_SA_OFFSET + MDSA_TAG_LEN) {
		nd_print_trunc(ndo);
		return (length);
	}

	ehp = (const struct ether_header *)bp;
	if (ndo->ndo_eflag)
		ND_PRINT("%s > %s, ",
			     etheraddr_string(ndo, ehp->ether_shost),
			     etheraddr_string(ndo, ehp->ether_dhost));

	mdsa = (const struct mdsa_pkthdr *)(bp + ETHER_SA_OFFSET);

	if (!ndo->ndo_eflag)
		ND_PRINT("MDSA %u.%u:%u: ",
			  SRC_DEV(mdsa), SRC_PORT(mdsa), VID(mdsa));
	else
		mdsa_print_full(ndo, mdsa, caplen - ETHER_SA_OFFSET);

	/* We printed the Ethernet header already */
	ndo->ndo_eflag = 0;

	/* Parse the Ethernet frame regularly telling how big the non
	 * standard Ethernet header is.
	 *
	 * +-----------++-----------++------------------++--------------+
	 * | MAC DA (6)|| MAC SA (6)||Marvel DSA tag (4)||Type/Length(2)|
	 * +-----------++-----------++------------------++--------------+
	 */
	ret = ether_print_hdr_len(ndo, bp, length, caplen, NULL, NULL,
				  ETHER_SA_OFFSET + MDSA_TAG_LEN + 2);
	ndo->ndo_eflag = old_eflag;
	return ret;
}
