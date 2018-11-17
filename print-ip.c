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

/* \summary: IP printer */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "netdissect-stdinc.h"

#include <string.h>

#include "netdissect.h"
#include "addrtoname.h"
#include "extract.h"

#include "ip.h"
#include "ipproto.h"


static const struct tok ip_option_values[] = {
    { IPOPT_EOL, "EOL" },
    { IPOPT_NOP, "NOP" },
    { IPOPT_TS, "timestamp" },
    { IPOPT_SECURITY, "security" },
    { IPOPT_RR, "RR" },
    { IPOPT_SSRR, "SSRR" },
    { IPOPT_LSRR, "LSRR" },
    { IPOPT_RA, "RA" },
    { IPOPT_RFC1393, "traceroute" },
    { 0, NULL }
};

/*
 * print the recorded route in an IP RR, LSRR or SSRR option.
 */
static int
ip_printroute(netdissect_options *ndo,
              const u_char *cp, u_int length)
{
	u_int ptr;
	u_int len;

	if (length < 3) {
		ND_PRINT(" [bad length %u]", length);
		return (0);
	}
	if ((length + 1) & 3)
		ND_PRINT(" [bad length %u]", length);
	ND_TCHECK_1(cp + 2);
	ptr = EXTRACT_U_1(cp + 2) - 1;
	if (ptr < 3 || ((ptr + 1) & 3) || ptr > length + 1)
		ND_PRINT(" [bad ptr %u]", EXTRACT_U_1(cp + 2));

	for (len = 3; len < length; len += 4) {
		ND_TCHECK_4(cp + len);
		ND_PRINT(" %s", ipaddr_string(ndo, cp + len));
		if (ptr > len)
			ND_PRINT(",");
	}
	return (0);

trunc:
	return (-1);
}

/*
 * If source-routing is present and valid, return the final destination.
 * Otherwise, return IP destination.
 *
 * This is used for UDP and TCP pseudo-header in the checksum
 * calculation.
 */
static uint32_t
ip_finddst(netdissect_options *ndo,
           const struct ip *ip)
{
	u_int length;
	u_int len;
	const u_char *cp;

	cp = (const u_char *)(ip + 1);
	length = IP_HL(ip) * 4;
	if (length < sizeof(struct ip))
		goto trunc;
	length -= sizeof(struct ip);

	for (; length != 0; cp += len, length -= len) {
		int tt;

		ND_TCHECK_1(cp);
		tt = EXTRACT_U_1(cp);
		if (tt == IPOPT_EOL)
			break;
		else if (tt == IPOPT_NOP)
			len = 1;
		else {
			ND_TCHECK_1(cp + 1);
			len = EXTRACT_U_1(cp + 1);
			if (len < 2)
				break;
		}
		if (length < len)
			goto trunc;
		ND_TCHECK_LEN(cp, len);
		switch (tt) {

		case IPOPT_SSRR:
		case IPOPT_LSRR:
			if (len < 7)
				break;
			return (EXTRACT_IPV4_TO_NETWORK_ORDER(cp + len - 4));
		}
	}
trunc:
	return (EXTRACT_IPV4_TO_NETWORK_ORDER(ip->ip_dst));
}

/*
 * Compute a V4-style checksum by building a pseudoheader.
 */
int
nextproto4_cksum(netdissect_options *ndo,
                 const struct ip *ip, const uint8_t *data,
                 u_int len, u_int covlen, u_int next_proto)
{
	struct phdr {
		uint32_t src;
		uint32_t dst;
		u_char mbz;
		u_char proto;
		uint16_t len;
	} ph;
	struct cksum_vec vec[2];

	/* pseudo-header.. */
	ph.len = htons((uint16_t)len);
	ph.mbz = 0;
	ph.proto = next_proto;
	ph.src = EXTRACT_IPV4_TO_NETWORK_ORDER(ip->ip_src);
	if (IP_HL(ip) == 5)
		ph.dst = EXTRACT_IPV4_TO_NETWORK_ORDER(ip->ip_dst);
	else
		ph.dst = ip_finddst(ndo, ip);

	vec[0].ptr = (const uint8_t *)(void *)&ph;
	vec[0].len = sizeof(ph);
	vec[1].ptr = data;
	vec[1].len = covlen;
	return (in_cksum(vec, 2));
}

static int
ip_printts(netdissect_options *ndo,
           const u_char *cp, u_int length)
{
	u_int ptr;
	u_int len;
	u_int hoplen;
	const char *type;

	if (length < 4) {
		ND_PRINT("[bad length %u]", length);
		return (0);
	}
	ND_PRINT(" TS{");
	ND_TCHECK_1(cp + 3);
	hoplen = ((EXTRACT_U_1(cp + 3) & 0xF) != IPOPT_TS_TSONLY) ? 8 : 4;
	if ((length - 4) & (hoplen-1))
		ND_PRINT("[bad length %u]", length);
	ND_TCHECK_1(cp + 2);
	ptr = EXTRACT_U_1(cp + 2) - 1;
	len = 0;
	if (ptr < 4 || ((ptr - 4) & (hoplen-1)) || ptr > length + 1)
		ND_PRINT("[bad ptr %u]", EXTRACT_U_1(cp + 2));
	ND_TCHECK_1(cp + 3);
	switch (EXTRACT_U_1(cp + 3)&0xF) {
	case IPOPT_TS_TSONLY:
		ND_PRINT("TSONLY");
		break;
	case IPOPT_TS_TSANDADDR:
		ND_PRINT("TS+ADDR");
		break;
	/*
	 * prespecified should really be 3, but some ones might send 2
	 * instead, and the IPOPT_TS_PRESPEC constant can apparently
	 * have both values, so we have to hard-code it here.
	 */

	case 2:
		ND_PRINT("PRESPEC2.0");
		break;
	case 3:			/* IPOPT_TS_PRESPEC */
		ND_PRINT("PRESPEC");
		break;
	default:
		ND_PRINT("[bad ts type %u]", EXTRACT_U_1(cp + 3)&0xF);
		goto done;
	}

	type = " ";
	for (len = 4; len < length; len += hoplen) {
		if (ptr == len)
			type = " ^ ";
		ND_TCHECK_LEN(cp + len, hoplen);
		ND_PRINT("%s%u@%s", type, EXTRACT_BE_U_4(cp + len + hoplen - 4),
			  hoplen!=8 ? "" : ipaddr_string(ndo, cp + len));
		type = " ";
	}

done:
	ND_PRINT("%s", ptr == len ? " ^ " : "");

	if (EXTRACT_U_1(cp + 3) >> 4)
		ND_PRINT(" [%u hops not recorded]} ", EXTRACT_U_1(cp + 3)>>4);
	else
		ND_PRINT("}");
	return (0);

trunc:
	return (-1);
}

/*
 * print IP options.
   If truncated return -1, else 0.
 */
static int
ip_optprint(netdissect_options *ndo,
            const u_char *cp, u_int length)
{
	u_int option_len;
	const char *sep = "";

	for (; length > 0; cp += option_len, length -= option_len) {
		u_int option_code;

		ND_PRINT("%s", sep);
		sep = ",";

		ND_TCHECK_1(cp);
		option_code = EXTRACT_U_1(cp);

		ND_PRINT("%s",
		          tok2str(ip_option_values,"unknown %u",option_code));

		if (option_code == IPOPT_NOP ||
                    option_code == IPOPT_EOL)
			option_len = 1;

		else {
			ND_TCHECK_1(cp + 1);
			option_len = EXTRACT_U_1(cp + 1);
			if (option_len < 2) {
				ND_PRINT(" [bad length %u]", option_len);
				return 0;
			}
		}

		if (option_len > length) {
			ND_PRINT(" [bad length %u]", option_len);
			return 0;
		}

		ND_TCHECK_LEN(cp, option_len);

		switch (option_code) {
		case IPOPT_EOL:
			return 0;

		case IPOPT_TS:
			if (ip_printts(ndo, cp, option_len) == -1)
				goto trunc;
			break;

		case IPOPT_RR:       /* fall through */
		case IPOPT_SSRR:
		case IPOPT_LSRR:
			if (ip_printroute(ndo, cp, option_len) == -1)
				goto trunc;
			break;

		case IPOPT_RA:
			if (option_len < 4) {
				ND_PRINT(" [bad length %u]", option_len);
				break;
			}
			ND_TCHECK_1(cp + 3);
			if (EXTRACT_BE_U_2(cp + 2) != 0)
				ND_PRINT(" value %u", EXTRACT_BE_U_2(cp + 2));
			break;

		case IPOPT_NOP:       /* nothing to print - fall through */
		case IPOPT_SECURITY:
		default:
			break;
		}
	}
	return 0;

trunc:
	return -1;
}

#define IP_RES 0x8000

static const struct tok ip_frag_values[] = {
        { IP_MF,        "+" },
        { IP_DF,        "DF" },
	{ IP_RES,       "rsvd" }, /* The RFC3514 evil ;-) bit */
        { 0,            NULL }
};

struct ip_print_demux_state {
	const struct ip *ip;
	const u_char *cp;
	u_int   len, off;
	u_char  nh;
	int     advance;
};

static void
ip_print_demux(netdissect_options *ndo,
	       struct ip_print_demux_state *ipds)
{
	const char *p_name;

again:
	switch (ipds->nh) {

	case IPPROTO_AH:
		if (!ND_TTEST_1(ipds->cp)) {
			ndo->ndo_protocol = "ah";
			nd_print_trunc(ndo);
			break;
		}
		ipds->nh = EXTRACT_U_1(ipds->cp);
		ipds->advance = ah_print(ndo, ipds->cp);
		if (ipds->advance <= 0)
			break;
		ipds->cp += ipds->advance;
		ipds->len -= ipds->advance;
		goto again;

	case IPPROTO_ESP:
	{
		u_int enh, padlen;
		ipds->advance = esp_print(ndo, ipds->cp, ipds->len,
				    (const u_char *)ipds->ip,
				    &enh, &padlen);
		if (ipds->advance <= 0)
			break;
		ipds->cp += ipds->advance;
		ipds->len -= ipds->advance + padlen;
		ipds->nh = enh & 0xff;
		goto again;
	}

	case IPPROTO_IPCOMP:
	{
		ipcomp_print(ndo, ipds->cp);
		/*
		 * Either this has decompressed the payload and
		 * printed it, in which case there's nothing more
		 * to do, or it hasn't, in which case there's
		 * nothing more to do.
		 */
		break;
	}

	case IPPROTO_SCTP:
		sctp_print(ndo, ipds->cp, (const u_char *)ipds->ip, ipds->len);
		break;

	case IPPROTO_DCCP:
		dccp_print(ndo, ipds->cp, (const u_char *)ipds->ip, ipds->len);
		break;

	case IPPROTO_TCP:
		/* pass on the MF bit plus the offset to detect fragments */
		tcp_print(ndo, ipds->cp, ipds->len, (const u_char *)ipds->ip,
			  ipds->off & (IP_MF|IP_OFFMASK));
		break;

	case IPPROTO_UDP:
		/* pass on the MF bit plus the offset to detect fragments */
		udp_print(ndo, ipds->cp, ipds->len, (const u_char *)ipds->ip,
			  ipds->off & (IP_MF|IP_OFFMASK));
		break;

	case IPPROTO_ICMP:
		/* pass on the MF bit plus the offset to detect fragments */
		icmp_print(ndo, ipds->cp, ipds->len, (const u_char *)ipds->ip,
			   ipds->off & (IP_MF|IP_OFFMASK));
		break;

	case IPPROTO_PIGP:
		/*
		 * XXX - the current IANA protocol number assignments
		 * page lists 9 as "any private interior gateway
		 * (used by Cisco for their IGRP)" and 88 as
		 * "EIGRP" from Cisco.
		 *
		 * Recent BSD <netinet/in.h> headers define
		 * IP_PROTO_PIGP as 9 and IP_PROTO_IGRP as 88.
		 * We define IP_PROTO_PIGP as 9 and
		 * IP_PROTO_EIGRP as 88; those names better
		 * match was the current protocol number
		 * assignments say.
		 */
		igrp_print(ndo, ipds->cp, ipds->len);
		break;

	case IPPROTO_EIGRP:
		eigrp_print(ndo, ipds->cp, ipds->len);
		break;

	case IPPROTO_ND:
		ND_PRINT(" nd %u", ipds->len);
		break;

	case IPPROTO_EGP:
		egp_print(ndo, ipds->cp, ipds->len);
		break;

	case IPPROTO_OSPF:
		ospf_print(ndo, ipds->cp, ipds->len, (const u_char *)ipds->ip);
		break;

	case IPPROTO_IGMP:
		igmp_print(ndo, ipds->cp, ipds->len);
		break;

	case IPPROTO_IPV4:
		/* DVMRP multicast tunnel (ip-in-ip encapsulation) */
		ip_print(ndo, ipds->cp, ipds->len);
		if (! ndo->ndo_vflag) {
			ND_PRINT(" (ipip-proto-4)");
			return;
		}
		break;

	case IPPROTO_IPV6:
		/* ip6-in-ip encapsulation */
		ip6_print(ndo, ipds->cp, ipds->len);
		break;

	case IPPROTO_RSVP:
		rsvp_print(ndo, ipds->cp, ipds->len);
		break;

	case IPPROTO_GRE:
		/* do it */
		gre_print(ndo, ipds->cp, ipds->len);
		break;

	case IPPROTO_MOBILE:
		mobile_print(ndo, ipds->cp, ipds->len);
		break;

	case IPPROTO_PIM:
		pim_print(ndo, ipds->cp, ipds->len, (const u_char *)ipds->ip);
		break;

	case IPPROTO_VRRP:
		if (ndo->ndo_packettype == PT_CARP) {
			if (ndo->ndo_vflag)
				ND_PRINT("carp %s > %s: ",
					     ipaddr_string(ndo, ipds->ip->ip_src),
					     ipaddr_string(ndo, ipds->ip->ip_dst));
			carp_print(ndo, ipds->cp, ipds->len,
				EXTRACT_U_1(ipds->ip->ip_ttl));
		} else {
			if (ndo->ndo_vflag)
				ND_PRINT("vrrp %s > %s: ",
					     ipaddr_string(ndo, ipds->ip->ip_src),
					     ipaddr_string(ndo, ipds->ip->ip_dst));
			vrrp_print(ndo, ipds->cp, ipds->len,
				(const u_char *)ipds->ip,
				EXTRACT_U_1(ipds->ip->ip_ttl));
		}
		break;

	case IPPROTO_PGM:
		pgm_print(ndo, ipds->cp, ipds->len, (const u_char *)ipds->ip);
		break;

	default:
		if (ndo->ndo_nflag==0 && (p_name = netdb_protoname(ipds->nh)) != NULL)
			ND_PRINT(" %s", p_name);
		else
			ND_PRINT(" ip-proto-%u", ipds->nh);
		ND_PRINT(" %u", ipds->len);
		break;
	}
}

void
ip_inner_print(netdissect_options *ndo,
	       const u_char *bp,
	       u_int length, u_int nh,
	       const u_char *bp2)
{
	struct ip_print_demux_state  ipd;

	ipd.ip = (const struct ip *)bp2;
	ipd.cp = bp;
	ipd.len  = length;
	ipd.off  = 0;
	ipd.nh   = nh;
	ipd.advance = 0;

	ip_print_demux(ndo, &ipd);
}


/*
 * print an IP datagram.
 */
void
ip_print(netdissect_options *ndo,
	 const u_char *bp,
	 u_int length)
{
	struct ip_print_demux_state  ipd;
	struct ip_print_demux_state *ipds=&ipd;
	const u_char *ipend;
	u_int hlen;
	struct cksum_vec vec[1];
	uint8_t ip_tos, ip_ttl, ip_proto;
	uint16_t sum, ip_sum;
	const char *p_name;
	int truncated = 0;

	ndo->ndo_protocol = "ip";
	ipds->ip = (const struct ip *)bp;
	ND_TCHECK_1(ipds->ip->ip_vhl);
	if (IP_V(ipds->ip) != 4) { /* print version and fail if != 4 */
	    if (IP_V(ipds->ip) == 6)
	      ND_PRINT("IP6, wrong link-layer encapsulation");
	    else
	      ND_PRINT("IP%u", IP_V(ipds->ip));
	    nd_print_invalid(ndo);
	    return;
	}
	if (!ndo->ndo_eflag)
		ND_PRINT("IP ");

	ND_TCHECK_SIZE(ipds->ip);
	if (length < sizeof (struct ip)) {
		ND_PRINT("truncated-ip %u", length);
		return;
	}
	hlen = IP_HL(ipds->ip) * 4;
	if (hlen < sizeof (struct ip)) {
		ND_PRINT("bad-hlen %u", hlen);
		return;
	}

	ipds->len = EXTRACT_BE_U_2(ipds->ip->ip_len);
	if (length < ipds->len)
		ND_PRINT("truncated-ip - %u bytes missing! ",
			ipds->len - length);
	if (ipds->len < hlen) {
#ifdef GUESS_TSO
            if (ipds->len) {
                ND_PRINT("bad-len %u", ipds->len);
                return;
            }
            else {
                /* we guess that it is a TSO send */
                ipds->len = length;
            }
#else
            ND_PRINT("bad-len %u", ipds->len);
            return;
#endif /* GUESS_TSO */
	}

	/*
	 * Cut off the snapshot length to the end of the IP payload.
	 */
	ipend = bp + ipds->len;
	if (ipend < ndo->ndo_snapend)
		ndo->ndo_snapend = ipend;

	ipds->len -= hlen;

	ipds->off = EXTRACT_BE_U_2(ipds->ip->ip_off);

        ip_proto = EXTRACT_U_1(ipds->ip->ip_p);

        if (ndo->ndo_vflag) {
            ip_tos = EXTRACT_U_1(ipds->ip->ip_tos);
            ND_PRINT("(tos 0x%x", ip_tos);
            /* ECN bits */
            switch (ip_tos & 0x03) {

            case 0:
                break;

            case 1:
                ND_PRINT(",ECT(1)");
                break;

            case 2:
                ND_PRINT(",ECT(0)");
                break;

            case 3:
                ND_PRINT(",CE");
                break;
            }

            ip_ttl = EXTRACT_U_1(ipds->ip->ip_ttl);
            if (ip_ttl >= 1)
                ND_PRINT(", ttl %u", ip_ttl);

	    /*
	     * for the firewall guys, print id, offset.
             * On all but the last stick a "+" in the flags portion.
	     * For unfragmented datagrams, note the don't fragment flag.
	     */
	    ND_PRINT(", id %u, offset %u, flags [%s], proto %s (%u)",
                         EXTRACT_BE_U_2(ipds->ip->ip_id),
                         (ipds->off & 0x1fff) * 8,
                         bittok2str(ip_frag_values, "none", ipds->off&0xe000),
                         tok2str(ipproto_values, "unknown", ip_proto),
                         ip_proto);

            ND_PRINT(", length %u", EXTRACT_BE_U_2(ipds->ip->ip_len));

            if ((hlen - sizeof(struct ip)) > 0) {
                ND_PRINT(", options (");
                if (ip_optprint(ndo, (const u_char *)(ipds->ip + 1),
                    hlen - sizeof(struct ip)) == -1) {
                        ND_PRINT(" [truncated-option]");
			truncated = 1;
                }
                ND_PRINT(")");
            }

	    if (!ndo->ndo_Kflag && (const u_char *)ipds->ip + hlen <= ndo->ndo_snapend) {
	        vec[0].ptr = (const uint8_t *)(const void *)ipds->ip;
	        vec[0].len = hlen;
	        sum = in_cksum(vec, 1);
		if (sum != 0) {
		    ip_sum = EXTRACT_BE_U_2(ipds->ip->ip_sum);
		    ND_PRINT(", bad cksum %x (->%x)!", ip_sum,
			     in_cksum_shouldbe(ip_sum, sum));
		}
	    }

	    ND_PRINT(")\n    ");
	    if (truncated) {
		ND_PRINT("%s > %s: ",
			 ipaddr_string(ndo, ipds->ip->ip_src),
			 ipaddr_string(ndo, ipds->ip->ip_dst));
		goto trunc;
	    }
	}

	/*
	 * If this is fragment zero, hand it to the next higher
	 * level protocol.
	 */
	if ((ipds->off & 0x1fff) == 0) {
		ipds->cp = (const u_char *)ipds->ip + hlen;
		ipds->nh = EXTRACT_U_1(ipds->ip->ip_p);

		if (ipds->nh != IPPROTO_TCP && ipds->nh != IPPROTO_UDP &&
		    ipds->nh != IPPROTO_SCTP && ipds->nh != IPPROTO_DCCP) {
			ND_PRINT("%s > %s: ",
				     ipaddr_string(ndo, ipds->ip->ip_src),
				     ipaddr_string(ndo, ipds->ip->ip_dst));
		}
		ip_print_demux(ndo, ipds);
	} else {
		/*
		 * Ultra quiet now means that all this stuff should be
		 * suppressed.
		 */
		if (ndo->ndo_qflag > 1)
			return;

		/*
		 * This isn't the first frag, so we're missing the
		 * next level protocol header.  print the ip addr
		 * and the protocol.
		 */
		ND_PRINT("%s > %s:", ipaddr_string(ndo, ipds->ip->ip_src),
		          ipaddr_string(ndo, ipds->ip->ip_dst));
		if (!ndo->ndo_nflag && (p_name = netdb_protoname(ip_proto)) != NULL)
			ND_PRINT(" %s", p_name);
		else
			ND_PRINT(" ip-proto-%u", ip_proto);
	}
	return;

trunc:
	nd_print_trunc(ndo);
	return;
}

void
ipN_print(netdissect_options *ndo, const u_char *bp, u_int length)
{
	ndo->ndo_protocol = "ipN";
	if (length < 1) {
		ND_PRINT("truncated-ip %u", length);
		return;
	}

	ND_TCHECK_1(bp);
	switch (EXTRACT_U_1(bp) & 0xF0) {
	case 0x40:
		ip_print(ndo, bp, length);
		break;
	case 0x60:
		ip6_print(ndo, bp, length);
		break;
	default:
		ND_PRINT("unknown ip %u", (EXTRACT_U_1(bp) & 0xF0) >> 4);
		break;
	}
	return;

trunc:
	nd_print_trunc(ndo);
	return;
}
