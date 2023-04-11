/*	$OpenBSD: print-gre.c,v 1.6 2002/10/30 03:04:04 fgsch Exp $	*/

/*
 * Copyright (c) 2002 Jason L. Wright (jason@thought.net)
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
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/* \summary: Generic Routing Encapsulation (GRE) printer */

/*
 * netdissect printer for GRE - Generic Routing Encapsulation
 * RFC 1701 (GRE), RFC 1702 (GRE IPv4), RFC 2637 (PPTP, which
 * has an extended form of GRE), RFC 2784 (revised GRE, with
 * R, K, S, and s bits and Recur and Offset fields now reserved
 * in the header, and no optional Key or Sequence number in the
 * header), and RFC 2890 (proposal to add back the K and S bits
 * and the optional Key and Sequence number).
 *
 * The RFC 2637 PPTP GRE repurposes the Key field to hold a
 * 16-bit Payload Length and a 16-bit Call ID.
 *
 * RFC 7637 (NVGRE) repurposes the Key field to hold a 24-bit
 * Virtual Subnet ID (VSID) and an 8-bit FlowID.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "netdissect-stdinc.h"

#define ND_LONGJMP_FROM_TCHECK
#include "netdissect.h"
#include "addrtostr.h"
#include "extract.h"
#include "ethertype.h"


#define	GRE_CP		0x8000		/* checksum present */
#define	GRE_RP		0x4000		/* routing present */
#define	GRE_KP		0x2000		/* key present */
#define	GRE_SP		0x1000		/* sequence# present */
#define	GRE_sP		0x0800		/* source routing */
#define	GRE_AP		0x0080		/* acknowledgment# present */

static const struct tok gre_flag_values[] = {
    { GRE_CP, "checksum present"},
    { GRE_RP, "routing present"},
    { GRE_KP, "key present"},
    { GRE_SP, "sequence# present"},
    { GRE_sP, "source routing present"},
    { GRE_AP, "ack present"},
    { 0, NULL }
};

#define	GRE_RECRS_MASK	0x0700		/* recursion count */
#define	GRE_VERS_MASK	0x0007		/* protocol version */

/* source route entry types */
#define	GRESRE_IP	0x0800		/* IP */
#define	GRESRE_ASN	0xfffe		/* ASN */

/*
 * Ethertype values used for GRE (but not elsewhere?).
 */
#define GRE_CDP			0x2000	/* Cisco Discovery Protocol */
#define GRE_NHRP		0x2001	/* Next Hop Resolution Protocol */
#define GRE_WCCP		0x883e	/* Web Cache C* Protocol */

struct wccp_redirect {
	nd_uint8_t	flags;
#define WCCP_T			(1 << 7)
#define WCCP_A			(1 << 6)
#define WCCP_U			(1 << 5)
	nd_uint8_t	ServiceId;
	nd_uint8_t	AltBucket;
	nd_uint8_t	PriBucket;
};

static void gre_print_0(netdissect_options *, const u_char *, u_int);
static void gre_print_1(netdissect_options *, const u_char *, u_int);
static int gre_sre_print(netdissect_options *, uint16_t, uint8_t, uint8_t, const u_char *, u_int);
static int gre_sre_ip_print(netdissect_options *, uint8_t, uint8_t, const u_char *, u_int);
static int gre_sre_asn_print(netdissect_options *, uint8_t, uint8_t, const u_char *, u_int);

void
gre_print(netdissect_options *ndo, const u_char *bp, u_int length)
{
	u_int vers;

	ndo->ndo_protocol = "gre";
	nd_print_protocol_caps(ndo);
	ND_ICHECK_U(length, <, 2);
	vers = GET_BE_U_2(bp) & GRE_VERS_MASK;
	ND_PRINT("v%u",vers);

	switch(vers) {
	case 0:
		gre_print_0(ndo, bp, length);
		break;
	case 1:
		gre_print_1(ndo, bp, length);
		break;
	default:
		ND_PRINT(" ERROR: unknown-version");
		break;
	}
	return;

invalid:
	nd_print_invalid(ndo);
}

static void
gre_print_0(netdissect_options *ndo, const u_char *bp, u_int length)
{
	u_int len = length;
	uint16_t flags, prot;

	ND_ICHECK_U(len, <, 2);
	flags = GET_BE_U_2(bp);
	if (ndo->ndo_vflag)
		ND_PRINT(", Flags [%s]",
			 bittok2str(gre_flag_values,"none",flags));

	len -= 2;
	bp += 2;

	ND_ICHECK_U(len, <, 2);
	prot = GET_BE_U_2(bp);
	len -= 2;
	bp += 2;

	if ((flags & GRE_CP) | (flags & GRE_RP)) {
		uint16_t sum;

		ND_ICHECK_U(len, <, 2);
		sum =  GET_BE_U_2(bp);
		if (ndo->ndo_vflag)
			ND_PRINT(", sum 0x%x", sum);
		bp += 2;
		len -= 2;

		ND_ICHECK_U(len, <, 2);
		ND_PRINT(", off 0x%x", GET_BE_U_2(bp));
		bp += 2;
		len -= 2;
	}

	if (flags & GRE_KP) {
		uint32_t key;

		ND_ICHECK_U(len, <, 4);
		key = GET_BE_U_4(bp);
		bp += 4;
		len -= 4;

		/*
		 * OpenBSD shows this as both a 32-bit
		 * (decimal) key value and a VSID+FlowID
		 * pair, with the VSID in decimal and
		 * the FlowID in hex, as key=<Key>|<VSID>+<FlowID>,
		 * in case this is NVGRE.
		 */
		ND_PRINT(", key=0x%x", key);
	}

	if (flags & GRE_SP) {
		ND_ICHECK_U(len, <, 4);
		ND_PRINT(", seq %u", GET_BE_U_4(bp));
		bp += 4;
		len -= 4;
	}

	if (flags & GRE_RP) {
		for (;;) {
			uint16_t af;
			uint8_t sreoff;
			uint8_t srelen;

			ND_ICHECK_U(len, <, 4);
			af = GET_BE_U_2(bp);
			sreoff = GET_U_1(bp + 2);
			srelen = GET_U_1(bp + 3);
			bp += 4;
			len -= 4;

			if (af == 0 && srelen == 0)
				break;

			if (!gre_sre_print(ndo, af, sreoff, srelen, bp, len))
				goto invalid;

			ND_ICHECK_U(len, <, srelen);
			bp += srelen;
			len -= srelen;
		}
	}

	if (ndo->ndo_eflag)
		ND_PRINT(", proto %s (0x%04x)",
			 tok2str(ethertype_values,"unknown",prot), prot);

	ND_PRINT(", length %u",length);

	if (ndo->ndo_vflag < 1)
		ND_PRINT(": "); /* put in a colon as protocol demarc */
	else
		ND_PRINT("\n\t"); /* if verbose go multiline */

	switch (prot) {
	case 0x0000:
		/*
		 * 0x0000 is reserved, but Cisco, at least, appears to
		 * use it for keep-alives; see, for example,
		 * https://www.cisco.com/c/en/us/support/docs/ip/generic-routing-encapsulation-gre/118370-technote-gre-00.html#anc1
		 */
		printf("keep-alive");
		break;
	case GRE_WCCP:
		/*
		 * This is a bit weird.
		 *
		 * This may either just mean "IPv4" or it may mean
		 * "IPv4 preceded by a WCCP redirect header".  We
		 * check to see if the first octet looks like the
		 * beginning of an IPv4 header and, if not, dissect
		 * it "IPv4 preceded by a WCCP redirect header",
		 * otherwise we dissect it as just IPv4.
		 *
		 * See "Packet redirection" in draft-forster-wrec-wccp-v1-00,
		 * section 4.12 "Traffic Forwarding" in
		 * draft-wilson-wrec-wccp-v2-01, and section 3.12.1
		 * "Forwarding using GRE Encapsulation" in
		 * draft-param-wccp-v2rev1-01.
		 */
		ND_PRINT("wccp ");

		ND_ICHECK_U(len, <, 1);
		if (GET_U_1(bp) >> 4 != 4) {
			/*
			 * First octet isn't 0x4*, so it's not IPv4.
			 */
			const struct wccp_redirect *wccp;
			uint8_t wccp_flags;

			ND_ICHECK_ZU(len, <, sizeof(*wccp));
			wccp = (const struct wccp_redirect *)bp;
			wccp_flags = GET_U_1(wccp->flags);

			ND_PRINT("T:%c A:%c U:%c SId:%u Alt:%u Pri:%u",
			    (wccp_flags & WCCP_T) ? '1' : '0',
			    (wccp_flags & WCCP_A) ? '1' : '0',
			    (wccp_flags & WCCP_U) ? '1' : '0',
			    GET_U_1(wccp->ServiceId),
			    GET_U_1(wccp->AltBucket),
			    GET_U_1(wccp->PriBucket));

			bp += sizeof(*wccp);
			len -= sizeof(*wccp);

			printf(": ");
		}
		/* FALLTHROUGH */
	case ETHERTYPE_IP:
		ip_print(ndo, bp, len);
		break;
	case ETHERTYPE_IPV6:
		ip6_print(ndo, bp, len);
		break;
	case ETHERTYPE_MPLS:
	case ETHERTYPE_MPLS_MULTI:
		mpls_print(ndo, bp, len);
		break;
	case ETHERTYPE_IPX:
		ipx_print(ndo, bp, len);
		break;
	case ETHERTYPE_ATALK:
		atalk_print(ndo, bp, len);
		break;
	case ETHERTYPE_GRE_ISO:
		isoclns_print(ndo, bp, len);
		break;
	case ETHERTYPE_TEB:
		ether_print(ndo, bp, len, ND_BYTES_AVAILABLE_AFTER(bp), NULL, NULL);
		break;
	case ETHERTYPE_NSH:
		nsh_print(ndo, bp, len);
		break;
	case GRE_CDP:
		cdp_print(ndo, bp, len);
		break;
	case GRE_NHRP:
		nhrp_print(ndo, bp, len);
		break;
	default:
		ND_PRINT("gre-proto-0x%x", prot);
	}
	return;

invalid:
	nd_print_invalid(ndo);
}

static void
gre_print_1(netdissect_options *ndo, const u_char *bp, u_int length)
{
	u_int len = length;
	uint16_t flags, prot;

	ND_ICHECK_U(len, <, 2);
	flags = GET_BE_U_2(bp);
	len -= 2;
	bp += 2;

	if (ndo->ndo_vflag)
		ND_PRINT(", Flags [%s]",
			 bittok2str(gre_flag_values,"none",flags));

	ND_ICHECK_U(len, <, 2);
	prot = GET_BE_U_2(bp);
	len -= 2;
	bp += 2;


	if (flags & GRE_KP) {
		uint32_t k;

		ND_ICHECK_U(len, <, 4);
		k = GET_BE_U_4(bp);
		ND_PRINT(", call %u", k & 0xffff);
		len -= 4;
		bp += 4;
	}

	if (flags & GRE_SP) {
		ND_ICHECK_U(len, <, 4);
		ND_PRINT(", seq %u", GET_BE_U_4(bp));
		bp += 4;
		len -= 4;
	}

	if (flags & GRE_AP) {
		ND_ICHECK_U(len, <, 4);
		ND_PRINT(", ack %u", GET_BE_U_4(bp));
		bp += 4;
		len -= 4;
	}

	if ((flags & GRE_SP) == 0)
		ND_PRINT(", no-payload");

	if (ndo->ndo_eflag)
		ND_PRINT(", proto %s (0x%04x)",
			 tok2str(ethertype_values,"unknown",prot), prot);

	ND_PRINT(", length %u",length);

	if ((flags & GRE_SP) == 0)
		return;

	if (ndo->ndo_vflag < 1)
		ND_PRINT(": "); /* put in a colon as protocol demarc */
	else
		ND_PRINT("\n\t"); /* if verbose go multiline */

	switch (prot) {
	case ETHERTYPE_PPP:
		ppp_print(ndo, bp, len);
		break;
	default:
		ND_PRINT("gre-proto-0x%x", prot);
		break;
	}
	return;

invalid:
	nd_print_invalid(ndo);
}

static int
gre_sre_print(netdissect_options *ndo, uint16_t af, uint8_t sreoff,
	      uint8_t srelen, const u_char *bp, u_int len)
{
	int ret;

	switch (af) {
	case GRESRE_IP:
		ND_PRINT(", (rtaf=ip");
		ret = gre_sre_ip_print(ndo, sreoff, srelen, bp, len);
		ND_PRINT(")");
		break;
	case GRESRE_ASN:
		ND_PRINT(", (rtaf=asn");
		ret = gre_sre_asn_print(ndo, sreoff, srelen, bp, len);
		ND_PRINT(")");
		break;
	default:
		ND_PRINT(", (rtaf=0x%x)", af);
		ret = 1;
	}
	return (ret);
}

static int
gre_sre_ip_print(netdissect_options *ndo, uint8_t sreoff, uint8_t srelen,
		 const u_char *bp, u_int len)
{
	const u_char *up = bp;
	char buf[INET_ADDRSTRLEN];

	if (sreoff & 3) {
		ND_PRINT(", badoffset=%u", sreoff);
		goto invalid;
	}
	if (srelen & 3) {
		ND_PRINT(", badlength=%u", srelen);
		goto invalid;
	}
	if (sreoff >= srelen) {
		ND_PRINT(", badoff/len=%u/%u", sreoff, srelen);
		goto invalid;
	}

	while (srelen != 0) {
		ND_ICHECK_U(len, <, 4);

		ND_TCHECK_LEN(bp, sizeof(nd_ipv4));
		addrtostr(bp, buf, sizeof(buf));
		ND_PRINT(" %s%s",
			 ((bp - up) == sreoff) ? "*" : "", buf);

		bp += 4;
		len -= 4;
		srelen -= 4;
	}
	return 1;

invalid:
	return 0;
}

static int
gre_sre_asn_print(netdissect_options *ndo, uint8_t sreoff, uint8_t srelen,
		  const u_char *bp, u_int len)
{
	const u_char *up = bp;

	if (sreoff & 1) {
		ND_PRINT(", badoffset=%u", sreoff);
		goto invalid;
	}
	if (srelen & 1) {
		ND_PRINT(", badlength=%u", srelen);
		goto invalid;
	}
	if (sreoff >= srelen) {
		ND_PRINT(", badoff/len=%u/%u", sreoff, srelen);
		goto invalid;
	}

	while (srelen != 0) {
		ND_ICHECK_U(len, <, 2);

		ND_PRINT(" %s%x",
			 ((bp - up) == sreoff) ? "*" : "", GET_BE_U_2(bp));

		bp += 2;
		len -= 2;
		srelen -= 2;
	}
	return 1;

invalid:
	return 0;
}
