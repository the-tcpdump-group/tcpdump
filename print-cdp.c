/*
 * Copyright (c) 1992, 1993, 1994, 1995, 1996, 1997
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
 *
 * Code by Gert Doering, SpaceNet GmbH, gert@space.net
 *
 * Reference documentation:
 *    http://www.cisco.com/univercd/cc/td/doc/product/lan/trsrb/frames.htm
 */

/* \summary: Cisco Discovery Protocol (CDP) printer */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "netdissect-stdinc.h"

#include <string.h>

#include "netdissect.h"
#include "addrtoname.h"
#include "extract.h"
#include "nlpid.h"


#define CDP_HEADER_LEN             4
#define CDP_HEADER_VERSION_OFFSET  0
#define CDP_HEADER_TTL_OFFSET      1
#define CDP_HEADER_CHECKSUM_OFFSET 2

#define CDP_TLV_HEADER_LEN  4
#define CDP_TLV_TYPE_OFFSET 0
#define CDP_TLV_LEN_OFFSET  2

static const struct tok cdp_tlv_values[] = {
    { 0x01,             "Device-ID"},
    { 0x02,             "Address"},
    { 0x03,             "Port-ID"},
    { 0x04,             "Capability"},
    { 0x05,             "Version String"},
    { 0x06,             "Platform"},
    { 0x07,             "Prefixes"},
    { 0x08,             "Protocol-Hello option"},
    { 0x09,             "VTP Management Domain"},
    { 0x0a,             "Native VLAN ID"},
    { 0x0b,             "Duplex"},
    { 0x0e,             "ATA-186 VoIP VLAN assignment"},
    { 0x0f,             "ATA-186 VoIP VLAN request"},
    { 0x10,             "power consumption"},
    { 0x11,             "MTU"},
    { 0x12,             "AVVID trust bitmap"},
    { 0x13,             "AVVID untrusted ports CoS"},
    { 0x14,             "System Name"},
    { 0x15,             "System Object ID (not decoded)"},
    { 0x16,             "Management Addresses"},
    { 0x17,             "Physical Location"},
    { 0, NULL}
};

static const struct tok cdp_capability_values[] = {
    { 0x01,             "Router" },
    { 0x02,             "Transparent Bridge" },
    { 0x04,             "Source Route Bridge" },
    { 0x08,             "L2 Switch" },
    { 0x10,             "L3 capable" },
    { 0x20,             "IGMP snooping" },
    { 0x40,             "L1 capable" },
    { 0, NULL }
};

static int cdp_print_addr(netdissect_options *, const u_char *, u_int);
static int cdp_print_prefixes(netdissect_options *, const u_char *, u_int);
static unsigned int cdp_get_number(const u_char *, u_int);

void
cdp_print(netdissect_options *ndo,
          const u_char *pptr, u_int length, u_int caplen)
{
	u_int type, len, i, j;
	const u_char *tptr;

	ndo->ndo_protocol = "cdp";
	if (caplen < CDP_HEADER_LEN) {
		nd_print_trunc(ndo);
		return;
	}

	tptr = pptr; /* temporary pointer */

	ND_TCHECK_LEN(tptr, CDP_HEADER_LEN);
	ND_PRINT("CDPv%u, ttl: %us", EXTRACT_U_1((tptr + CDP_HEADER_VERSION_OFFSET)),
					   EXTRACT_U_1(tptr + CDP_HEADER_TTL_OFFSET));
	if (ndo->ndo_vflag)
		ND_PRINT(", checksum: 0x%04x (unverified), length %u", EXTRACT_BE_U_2(tptr + CDP_HEADER_CHECKSUM_OFFSET), length);
	tptr += CDP_HEADER_LEN;

	while (tptr < (pptr+length)) {
		ND_TCHECK_LEN(tptr, CDP_TLV_HEADER_LEN); /* read out Type and Length */
		type = EXTRACT_BE_U_2(tptr + CDP_TLV_TYPE_OFFSET);
		len  = EXTRACT_BE_U_2(tptr + CDP_TLV_LEN_OFFSET); /* object length includes the 4 bytes header length */
		if (len < CDP_TLV_HEADER_LEN) {
		    if (ndo->ndo_vflag)
			ND_PRINT("\n\t%s (0x%02x), TLV length: %u byte%s (too short)",
			       tok2str(cdp_tlv_values,"unknown field type", type),
			       type,
			       len,
			       PLURAL_SUFFIX(len)); /* plural */
		    else
			ND_PRINT(", %s TLV length %u too short",
			       tok2str(cdp_tlv_values,"unknown field type", type),
			       len);
		    break;
		}
		tptr += CDP_TLV_HEADER_LEN;
		len -= CDP_TLV_HEADER_LEN;

		ND_TCHECK_LEN(tptr, len);

		if (ndo->ndo_vflag || type == 1) { /* in non-verbose mode just print Device-ID */

		    if (ndo->ndo_vflag)
			ND_PRINT("\n\t%s (0x%02x), value length: %u byte%s: ",
			       tok2str(cdp_tlv_values,"unknown field type", type),
			       type,
			       len,
			       PLURAL_SUFFIX(len)); /* plural */

		    switch (type) {

		    case 0x01: /* Device-ID */
			if (!ndo->ndo_vflag)
			    ND_PRINT(", Device-ID ");
			ND_PRINT("'");
			(void)nd_printn(ndo, tptr, len, NULL);
			ND_PRINT("'");
			break;
		    case 0x02: /* Address */
			if (cdp_print_addr(ndo, tptr, len) < 0)
			    goto trunc;
			break;
		    case 0x03: /* Port-ID */
			ND_PRINT("'");
			(void)nd_printn(ndo, tptr, len, NULL);
			ND_PRINT("'");
			break;
		    case 0x04: /* Capabilities */
			if (len < 4)
			    goto trunc;
			ND_PRINT("(0x%08x): %s",
			       EXTRACT_BE_U_4(tptr),
			       bittok2str(cdp_capability_values, "none", EXTRACT_BE_U_4(tptr)));
			break;
		    case 0x05: /* Version */
			ND_PRINT("\n\t  ");
			for (i=0;i<len;i++) {
			    j = EXTRACT_U_1(tptr + i);
			    if (j == '\n') /* lets rework the version string to
					      get a nice indentation */
				ND_PRINT("\n\t  ");
			    else
				fn_print_char(ndo, j);
			}
			break;
		    case 0x06: /* Platform */
			ND_PRINT("'");
			(void)nd_printn(ndo, tptr, len, NULL);
			ND_PRINT("'");
			break;
		    case 0x07: /* Prefixes */
			if (cdp_print_prefixes(ndo, tptr, len) < 0)
			    goto trunc;
			break;
		    case 0x08: /* Protocol Hello Option - not documented */
			break;
		    case 0x09: /* VTP Mgmt Domain  - CDPv2 */
			ND_PRINT("'");
			(void)nd_printn(ndo, tptr, len, NULL);
			ND_PRINT("'");
			break;
		    case 0x0a: /* Native VLAN ID - CDPv2 */
			if (len < 2)
			    goto trunc;
			ND_PRINT("%u", EXTRACT_BE_U_2(tptr));
			break;
		    case 0x0b: /* Duplex - CDPv2 */
			if (len < 1)
			    goto trunc;
			ND_PRINT("%s", EXTRACT_U_1(tptr) ? "full": "half");
			break;

		    /* http://www.cisco.com/c/en/us/td/docs/voice_ip_comm/cata/186/2_12_m/english/release/notes/186rn21m.html
		     * plus more details from other sources
		     *
		     * There are apparently versions of the request with both
		     * 2 bytes and 3 bytes of value.  The 3 bytes of value
		     * appear to be a 1-byte application type followed by a
		     * 2-byte VLAN ID; the 2 bytes of value are unknown
		     * (they're 0x20 0x00 in some captures I've seen; that
		     * is not a valid VLAN ID, as VLAN IDs are 12 bits).
		     *
		     * The replies all appear to be 3 bytes long.
		     */
		    case 0x0e: /* ATA-186 VoIP VLAN assignment - incomplete doc. */
			if (len < 3)
			    goto trunc;
			ND_PRINT("app %u, vlan %u", EXTRACT_U_1(tptr), EXTRACT_BE_U_2(tptr + 1));
			break;
		    case 0x0f: /* ATA-186 VoIP VLAN request - incomplete doc. */
			if (len < 2)
			    goto trunc;
			if (len == 2)
			    ND_PRINT("unknown 0x%04x", EXTRACT_BE_U_2(tptr));
			else
			    ND_PRINT("app %u, vlan %u", EXTRACT_U_1(tptr), EXTRACT_BE_U_2(tptr + 1));
			break;
		    case 0x10: /* Power - not documented */
			ND_PRINT("%1.2fW", cdp_get_number(tptr, len) / 1000.0);
			break;
		    case 0x11: /* MTU - not documented */
			if (len < 4)
			    goto trunc;
			ND_PRINT("%u bytes", EXTRACT_BE_U_4(tptr));
			break;
		    case 0x12: /* AVVID trust bitmap - not documented */
			if (len < 1)
			    goto trunc;
			ND_PRINT("0x%02x", EXTRACT_U_1(tptr));
			break;
		    case 0x13: /* AVVID untrusted port CoS - not documented */
			if (len < 1)
			    goto trunc;
			ND_PRINT("0x%02x", EXTRACT_U_1(tptr));
			break;
		    case 0x14: /* System Name - not documented */
			ND_PRINT("'");
			(void)nd_printn(ndo, tptr, len, NULL);
			ND_PRINT("'");
			break;
		    case 0x16: /* System Object ID - not documented */
			if (cdp_print_addr(ndo, tptr, len) < 0)
				goto trunc;
			break;
		    case 0x17: /* Physical Location - not documented */
			if (len < 1)
			    goto trunc;
			ND_PRINT("0x%02x", EXTRACT_U_1(tptr));
			if (len > 1) {
				ND_PRINT("/");
				(void)nd_printn(ndo, tptr + 1, len - 1, NULL);
			}
			break;
		    default:
			print_unknown_data(ndo, tptr, "\n\t  ", len);
			break;
		    }
		}
		tptr = tptr+len;
	}
	if (ndo->ndo_vflag < 1)
	    ND_PRINT(", length %u", caplen);

	return;
trunc:
	nd_print_trunc(ndo);
}

/*
 * Protocol type values.
 *
 * PT_NLPID means that the protocol type field contains an OSI NLPID.
 *
 * PT_IEEE_802_2 means that the protocol type field contains an IEEE 802.2
 * LLC header that specifies that the payload is for that protocol.
 */
#define PT_NLPID		1	/* OSI NLPID */
#define PT_IEEE_802_2		2	/* IEEE 802.2 LLC header */

static int
cdp_print_addr(netdissect_options *ndo,
	       const u_char * p, u_int l)
{
	u_int pt, pl, al, num;
	const u_char *endp = p + l;
	static const u_char prot_ipv6[] = {
		0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x86, 0xdd
	};

	ND_TCHECK_4(p);
	if (p + 4 > endp)
		goto trunc;
	num = EXTRACT_BE_U_4(p);
	p += 4;

	while (p < endp && num != 0) {
		ND_TCHECK_2(p);
		if (p + 2 > endp)
			goto trunc;
		pt = EXTRACT_U_1(p);		/* type of "protocol" field */
		pl = EXTRACT_U_1(p + 1);	/* length of "protocol" field */
		p += 2;

		ND_TCHECK_2(p + pl);
		if (p + pl + 2 > endp)
			goto trunc;
		al = EXTRACT_BE_U_2(p + pl);	/* address length */

		if (pt == PT_NLPID && pl == 1 && EXTRACT_U_1(p) == NLPID_IP &&
		    al == 4) {
			/*
			 * IPv4: protocol type = NLPID, protocol length = 1
			 * (1-byte NLPID), protocol = 0xcc (NLPID for IPv4),
			 * address length = 4
			 */
			p += 3;

			ND_TCHECK_4(p);
			if (p + 4 > endp)
				goto trunc;
			ND_PRINT("IPv4 (%u) %s", num, ipaddr_string(ndo, p));
			p += 4;
		}
		else if (pt == PT_IEEE_802_2 && pl == 8 &&
		    memcmp(p, prot_ipv6, 8) == 0 && al == 16) {
			/*
			 * IPv6: protocol type = IEEE 802.2 header,
			 * protocol length = 8 (size of LLC+SNAP header),
			 * protocol = LLC+SNAP header with the IPv6
			 * Ethertype, address length = 16
			 */
			p += 10;
			ND_TCHECK_LEN(p, al);
			if (p + al > endp)
				goto trunc;

			ND_PRINT("IPv6 (%u) %s", num, ip6addr_string(ndo, p));
			p += al;
		}
		else {
			/*
			 * Generic case: just print raw data
			 */
			ND_TCHECK_LEN(p, pl);
			if (p + pl > endp)
				goto trunc;
			ND_PRINT("pt=0x%02x, pl=%u, pb=", EXTRACT_U_1((p - 2)), pl);
			while (pl-- > 0) {
				ND_PRINT(" %02x", EXTRACT_U_1(p));
				p++;
			}
			ND_TCHECK_2(p);
			if (p + 2 > endp)
				goto trunc;
			ND_PRINT(", al=%u, a=", al);
			p += 2;
			ND_TCHECK_LEN(p, al);
			if (p + al > endp)
				goto trunc;
			while (al-- > 0) {
				ND_PRINT(" %02x", EXTRACT_U_1(p));
				p++;
			}
		}
		num--;
		if (num)
			ND_PRINT(" ");
	}

	return 0;

trunc:
	return -1;
}


static int
cdp_print_prefixes(netdissect_options *ndo,
		   const u_char * p, u_int l)
{
	if (l % 5)
		goto trunc;

	ND_PRINT(" IPv4 Prefixes (%u):", l / 5);

	while (l > 0) {
		ND_PRINT(" %u.%u.%u.%u/%u",
			  EXTRACT_U_1(p), EXTRACT_U_1(p + 1), EXTRACT_U_1(p + 2),
			  EXTRACT_U_1(p + 3), EXTRACT_U_1(p + 4));
		l -= 5;
		p += 5;
	}

	return 0;

trunc:
	return -1;
}

/* read in a <n>-byte number, MSB first
 * (of course this can handle max sizeof(int))
 */
static unsigned int cdp_get_number(const u_char * p, u_int l)
{
    unsigned int res=0;
    while( l>0 )
    {
	res = (res<<8) + EXTRACT_U_1(p);
	p++; l--;
    }
    return res;
}
