/*	$OpenBSD: print-nhrp.c,v 1.2 2022/12/28 21:30:19 jmc Exp $ */

/*
 * Copyright (c) 2020 Remi Locherer <remi@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* \summary: NHRP printer */

/*
 * RFC 2332 NBMA Next Hop Resolution Protocol (NHRP)
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "netdissect-stdinc.h"

#define ND_LONGJMP_FROM_TCHECK
#include "netdissect.h"
#include "addrtoname.h"
#include "af.h"
#include "ethertype.h"
#include "interface.h"
#include "extract.h"

#define NHRP_VER_RFC2332		1

#define NHRP_PKT_RESOLUTION_REQUEST	1
#define NHRP_PKT_RESOLUTION_REPLY	2
#define NHRP_PKT_REGISTRATION_REQUEST	3
#define NHRP_PKT_REGISTRATION_REPLY	4
#define NHRP_PKT_PURGE_REQUEST		5
#define NHRP_PKT_PURGE_REPLY		6
#define NHRP_PKT_ERROR_INDICATION	7

static const struct tok pkt_types[] = {
	{ NHRP_PKT_RESOLUTION_REQUEST,   "res request" },
	{ NHRP_PKT_RESOLUTION_REPLY,     "res reply" },
	{ NHRP_PKT_REGISTRATION_REQUEST, "reg request" },
	{ NHRP_PKT_REGISTRATION_REPLY,   "reg reply" },
	{ NHRP_PKT_PURGE_REQUEST,        "purge request" },
	{ NHRP_PKT_PURGE_REPLY,          "purge reply" },
	{ NHRP_PKT_ERROR_INDICATION,     "error indication" },
	{ 0, NULL }
};

/*
 * Fixed header part.
 */
struct nhrp_fixed_header {
	nd_uint16_t	afn;		/* link layer address */
	nd_uint16_t	pro_type;	/* protocol type (short form) */
	nd_uint8_t	pro_snap[5];	/* protocol type (long form) */
	nd_uint8_t	hopcnt;		/* hop count */
	nd_uint16_t	pktsz;		/* length of the NHRP packet (octets) */
	nd_uint16_t	chksum;		/* IP checksum over the entier packet */
	nd_uint16_t	extoff;		/* extension offset */
	nd_uint8_t	op_version;	/* version of address mapping and
					   management protocol */
	nd_uint8_t	op_type;	/* NHRP packet type */
	nd_uint8_t	shtl;		/* type and length of src NBMA addr */
	nd_uint8_t	sstl;		/* type and length of src NBMA
					   subaddress */
};

/*
 * Mandatory header part.  This is the beginning of the mandatory
 * header; it's followed by addresses and client information entries.
 *
 * The mandatory header part formats are similar for
 * all NHRP packets; the only difference is that NHRP_PKT_ERROR_INDICATION
 * has a 16-bit error code and a 16-bit error packet offset rather
 * than a 32-bit request ID.
 */
struct nhrp_mand_header {
	nd_uint8_t	spl;		/* src proto len */
	nd_uint8_t	dpl;		/* dst proto len */
	nd_uint16_t	flags;		/* flags */
        union {
		nd_uint32_t	id;	/* request id */
		struct {		/* error code */
			nd_uint16_t	code;
			nd_uint16_t	offset;
		} err;
	} u;
};

#define NHRP_FIXED_HEADER_LEN			20

struct nhrp_cie {
	/* client information entry */
	nd_uint8_t	code;
	nd_uint8_t	plen;
	nd_uint16_t	unused;
	nd_uint16_t	mtu;
	nd_uint16_t	htime;
	nd_uint8_t	cli_addr_tl;
	nd_uint8_t	cli_saddr_tl;
	nd_uint8_t	cli_proto_tl;
	nd_uint8_t	pref;
};

static u_int	nhrp_print_cie(netdissect_options *ndo, const u_char *, uint16_t, uint16_t, uint16_t);

/*
 * Get string for IPv4 address pointed to by addr if addrlen is 4;
 * otherwise, get it as a string for the sequence of hex bytes.
 */
static const char *
nhrp_ipv4_addr_string(netdissect_options *ndo, const u_char *addr, u_int addrlen)
{
	if (addrlen == 4)
		return (GET_IPADDR_STRING(addr));
	else
		return (GET_LINKADDR_STRING(addr, LINKADDR_OTHER, addrlen));
}
#define NHRP_IPv4_ADDR_STRING(addr, addrlen) \
	nhrp_ipv4_addr_string(ndo, (addr), (addrlen))

/*
 * Get string for IPv6 address pointed to by addr if addrlen is 16;
 * otherwise, get it as a string for the sequence of hex bytes.
 */
static const char *
nhrp_ipv6_addr_string(netdissect_options *ndo, const u_char *addr, u_int addrlen)
{
	if (addrlen == 16)
		return (GET_IP6ADDR_STRING(addr));
	else
		return (GET_LINKADDR_STRING(addr, LINKADDR_OTHER, addrlen));
}
#define NHRP_IPv6_ADDR_STRING(addr, addrlen) \
	nhrp_ipv6_addr_string(ndo, (addr), (addrlen))

/*
 * Get string for MAC address pointed to by addr if addrlen is 6;
 * otherwise, get it as a string for the sequence of hex bytes.
 */
static const char *
nhrp_mac_addr_string(netdissect_options *ndo, const u_char *addr, u_int addrlen)
{
	if (addrlen == 6)
		return (GET_ETHERADDR_STRING(addr));
	else
		return (GET_LINKADDR_STRING(addr, LINKADDR_OTHER, addrlen));
}
#define NHRP_MAC_ADDR_STRING(addr, addrlen) \
	nhrp_mac_addr_string(ndo, (addr), (addrlen))

void
nhrp_print(netdissect_options *ndo, const u_char *bp, u_int length)
{
	const struct nhrp_fixed_header	*fixed_hdr;
	uint16_t			afn;
	uint16_t			pro_type;
	uint16_t			pktsz;
	uint16_t			extoff;
	uint8_t				op_version;
	uint8_t				op_type;
	uint8_t				shtl, sstl;
	const struct nhrp_mand_header	*mand_hdr;
	uint16_t			mand_part_len;
	uint8_t				spl, dpl;

	ndo->ndo_protocol = "nhrp";
	nd_print_protocol_caps(ndo);
	ND_PRINT(": ");

	fixed_hdr = (const struct nhrp_fixed_header *)bp;

	ND_ICHECK_ZU(length, <, sizeof(*fixed_hdr));
	op_version = GET_U_1(fixed_hdr->op_version);
	if (op_version != NHRP_VER_RFC2332) {
		ND_PRINT("unknown-version-%02x", op_version);
		return;
	}

	afn = GET_BE_U_2(fixed_hdr->afn);
	pro_type = GET_BE_U_2(fixed_hdr->pro_type);

	pktsz = GET_BE_U_2(fixed_hdr->pktsz);
	ND_ICHECKMSG_ZU("pktsz", pktsz, <, sizeof(*fixed_hdr));
	extoff = GET_BE_U_2(fixed_hdr->extoff);

	op_type = GET_U_1(fixed_hdr->op_type);
	ND_PRINT("%s", tok2str(pkt_types, "unknown-op-type-%04x", op_type));

	/*
	 * Mandatory part length.
	 * We already know that pktsz is large enough for the fixed
	 * header and the fixed part of the mandatory heaer.
	 */
	if (extoff == 0) {
		mand_part_len = pktsz - sizeof(*fixed_hdr);
	} else {
		ND_ICHECKMSG_U("extoff", extoff, >, pktsz);
		ND_ICHECKMSG_ZU("extoff", extoff, <, sizeof(*fixed_hdr));
		mand_part_len = extoff - sizeof(*fixed_hdr);
	}
	length -= sizeof(*fixed_hdr);
	if (mand_part_len > length)
		mand_part_len = (uint16_t)length;

	/* We start looking at the mandatory header here. */
	ND_TCHECK_LEN(bp, sizeof(*fixed_hdr));
	bp += sizeof(*fixed_hdr);
	length -= sizeof(*fixed_hdr);
	ND_ICHECK_ZU(mand_part_len, <, sizeof(*mand_hdr));
	ND_TCHECK_LEN(bp, sizeof(*mand_hdr));
	mand_hdr = (const struct nhrp_mand_header *)bp;

	switch (op_type) {
	case NHRP_PKT_RESOLUTION_REQUEST:
	case NHRP_PKT_RESOLUTION_REPLY:
	case NHRP_PKT_REGISTRATION_REQUEST:
	case NHRP_PKT_REGISTRATION_REPLY:
	case NHRP_PKT_PURGE_REQUEST:
	case NHRP_PKT_PURGE_REPLY:
		ND_PRINT(", id %u", GET_BE_U_4(mand_hdr->u.id));
		break;
	case NHRP_PKT_ERROR_INDICATION:
		ND_PRINT(", error %u", GET_BE_U_2(mand_hdr->u.err.code));
		return;
	}

	shtl = GET_U_1(fixed_hdr->shtl);
	sstl = GET_U_1(fixed_hdr->sstl);

	if (ndo->ndo_vflag) {
		ND_PRINT(", hopcnt %u", GET_U_1(fixed_hdr->hopcnt));

		/* most significant bit must be 0 */
		if (shtl & 0x80)
			ND_PRINT(" (shtl bit 7 set)");

		/* check 2nd most significant bit */
		if (shtl & 0x40)
			ND_PRINT(" (nbma E.154)");
	}

	/* Mandatory header part */
	spl = GET_U_1(mand_hdr->spl);
	dpl = GET_U_1(mand_hdr->dpl);
	bp += sizeof(*mand_hdr);	/* Skip to the addresses */
	mand_part_len -= sizeof(*mand_hdr);

	/* Source NBMA Address, if any. */
	if (shtl != 0) {
		ND_ICHECK_U(mand_part_len, <, shtl);
		switch (afn) {
		case AFNUM_IP:
			ND_PRINT(", src nbma %s", NHRP_IPv4_ADDR_STRING(bp, shtl));
			break;
		case AFNUM_IP6:
			ND_PRINT(", src nbma %s", NHRP_IPv6_ADDR_STRING(bp, shtl));
			break;
		case AFNUM_802:
			ND_PRINT(", src nbma %s", NHRP_MAC_ADDR_STRING(bp, shtl));
			break;
		default:
			ND_PRINT(", unknown-nbma-addr-family-%04x (%s)",
			         afn, GET_LINKADDR_STRING(bp, LINKADDR_OTHER, shtl));
			break;
		}
		bp += shtl;
		mand_part_len -= shtl;
	}

	/* Skip the Source NBMA SubAddress, if any */
	if (sstl != 0) {
		ND_ICHECK_U(mand_part_len, <, sstl);
		ND_TCHECK_LEN(bp, sstl);
		bp += sstl;
		mand_part_len -= sstl;
	}

	ND_PRINT(", ");
	/* Source Protocol Address */
	if (spl != 0) {
		ND_ICHECK_U(mand_part_len, <, spl);
		switch (pro_type) {
		case ETHERTYPE_IP:
			ND_PRINT("%s ", NHRP_IPv4_ADDR_STRING(bp, spl));
			break;
		case ETHERTYPE_IPV6:
			ND_PRINT("%s ", NHRP_IPv6_ADDR_STRING(bp, spl));
			break;
		default:
			ND_PRINT("proto type %04x ", pro_type);
			ND_PRINT("%s ", GET_LINKADDR_STRING(bp, LINKADDR_OTHER, spl));
			break;
		}
		bp += spl;
		mand_part_len -= spl;
	}
	ND_PRINT("->");
	/* Destination Protocol Address */
	if (dpl != 0) {
		ND_ICHECK_U(mand_part_len, <, dpl);
		switch (pro_type) {
		case ETHERTYPE_IP:
			ND_PRINT(" %s", NHRP_IPv4_ADDR_STRING(bp, dpl));
			break;
		case ETHERTYPE_IPV6:
			ND_PRINT(" %s", NHRP_IPv6_ADDR_STRING(bp, dpl));
			break;
		default:
			ND_PRINT(" %s", GET_LINKADDR_STRING(bp, LINKADDR_OTHER, dpl));
			break;
		}
		bp += dpl;
		mand_part_len -= dpl;
	}

	switch (op_type) {
	case NHRP_PKT_RESOLUTION_REQUEST:
	case NHRP_PKT_RESOLUTION_REPLY:
	case NHRP_PKT_REGISTRATION_REQUEST:
	case NHRP_PKT_REGISTRATION_REPLY:
	case NHRP_PKT_PURGE_REQUEST:
	case NHRP_PKT_PURGE_REPLY:
		/* Client Information Entries */
		while (mand_part_len != 0) {
			u_int cie_len;

			/*
			 * cie_len is guaranteed by nhrp_print_cie()
			 * to be <= mand_part_len.
			 */
			cie_len = nhrp_print_cie(ndo, bp, mand_part_len,
			    afn, pro_type);
			bp += cie_len;
			mand_part_len -= (uint16_t)cie_len;
		}
		break;
	case NHRP_PKT_ERROR_INDICATION:
		/* Contents of NHRP Packet in error */
		break;
	default:
		break;
	}
	return;

invalid:
	nd_print_invalid(ndo);
}

static u_int
nhrp_print_cie(netdissect_options *ndo, const u_char *data, uint16_t mand_part_len,
               uint16_t afn, uint16_t pro_type)
{
	const struct nhrp_cie	*cie;
	u_int			cie_len;
	uint8_t			cli_addr_tl;
	uint8_t			cli_saddr_tl;
	uint8_t			cli_proto_tl;

	cie = (const struct nhrp_cie *)data;
	cie_len = 0;
	ND_ICHECKMSG_ZU("remaining mandatory part length",
	                 mand_part_len, <, sizeof(*cie));

	ND_PRINT(" (code %d", GET_U_1(cie->code));
	if (ndo->ndo_vflag)
		ND_PRINT(", pl %d, mtu %d, htime %d, pref %d",
		    GET_U_1(cie->plen),
		    GET_BE_U_2(cie->mtu),
		    GET_BE_U_2(cie->htime),
		    GET_U_1(cie->pref));

	cli_addr_tl = GET_U_1(cie->cli_addr_tl);
	cli_saddr_tl = GET_U_1(cie->cli_saddr_tl);
	cli_proto_tl = GET_U_1(cie->cli_proto_tl);

	/* check 2nd most significant bit */
	if (cli_addr_tl & 0x40)
		ND_PRINT(", nbma E.154");

	data += sizeof(*cie);
	cie_len += sizeof(*cie);
	mand_part_len -= sizeof(*cie);

	if (cli_addr_tl) {
		ND_ICHECKMSG_U("remaining mandatory part length",
		                mand_part_len, <, cli_addr_tl);
		switch (afn) {
		case AFNUM_IP:
			ND_PRINT(", nbma %s", NHRP_IPv4_ADDR_STRING(data, cli_addr_tl));
			break;
		case AFNUM_IP6:
			ND_PRINT(", nbma %s", NHRP_IPv6_ADDR_STRING(data, cli_addr_tl));
			break;
		case AFNUM_802:
			ND_PRINT(", nbma %s", NHRP_MAC_ADDR_STRING(data, cli_addr_tl));
			break;
		default:
			ND_PRINT(", unknown-nbma-addr-family-%04x (%s)",
			    afn, GET_LINKADDR_STRING(data, LINKADDR_OTHER, cli_addr_tl));
			break;
		}
		data += cli_addr_tl;
		cie_len += cli_addr_tl;
		mand_part_len -= cli_addr_tl;
	}

	if (cli_saddr_tl) {
		ND_ICHECKMSG_U("remaining mandatory part length",
		                mand_part_len, <, cli_addr_tl);
		ND_PRINT(", unknown-nbma-saddr-family");
		ND_TCHECK_LEN(data, cli_saddr_tl);
		data += cli_saddr_tl;
		cie_len += cli_saddr_tl;
		mand_part_len -= cli_saddr_tl;
	}

	if (cli_proto_tl) {
		ND_ICHECKMSG_U("remaining mandatory part length",
		                mand_part_len, <, cli_proto_tl);
		switch (pro_type) {
		case ETHERTYPE_IP:
			ND_PRINT(", proto %s", NHRP_IPv4_ADDR_STRING(data, cli_proto_tl));
			break;
		case ETHERTYPE_IPV6:
			ND_PRINT(", proto %s", NHRP_IPv6_ADDR_STRING(data, cli_proto_tl));
			break;
		default:
			ND_PRINT(", unknown-proto-family-%04x (%s)",
			    pro_type, GET_LINKADDR_STRING(data, LINKADDR_OTHER, cli_proto_tl));
			break;
		}
		cie_len += cli_proto_tl;
		mand_part_len -= cli_proto_tl;
	}

	ND_PRINT(")");

	return (cie_len);

invalid:
	nd_print_invalid(ndo);
	return (cie_len);
}
