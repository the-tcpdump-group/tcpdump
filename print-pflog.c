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

/* \summary: *BSD/Darwin packet filter log file printer */

#include <config.h>

#include "netdissect-stdinc.h"

#define ND_LONGJMP_FROM_TCHECK
#include "netdissect.h"
#include "extract.h"
#include "af.h"

/*
 * pflog headers, at least as they exist now.
 */
#define PFLOG_IFNAMSIZ		16
#define PFLOG_RULESET_NAME_SIZE	16

struct pf_addr {
	union {
		nd_ipv4		v4;
		nd_ipv6		v6;
	} pfa;		    /* 128-bit address */
#define v4	pfa.v4
#define v6	pfa.v6
};

struct pfloghdr {
	nd_uint8_t	length;
	nd_uint8_t	af;
	nd_uint8_t	action;
	nd_uint8_t	reason;
	char		ifname[PFLOG_IFNAMSIZ];
	char		ruleset[PFLOG_RULESET_NAME_SIZE];
	nd_uint32_t	rulenr;
	nd_uint32_t	subrulenr;
	nd_uint32_t	uid;
	nd_int32_t	pid;
	nd_uint32_t	rule_uid;
	nd_int32_t	rule_pid;
	nd_uint8_t	dir;
/* Minimum header length (without padding): 61 */
#define MIN_PFLOG_HDRLEN 61
#if defined(__OpenBSD__)
	nd_uint8_t	rewritten;
	nd_uint8_t	naf;
	nd_uint8_t	pad[1];
#else
	nd_uint8_t	pad[3];
#endif
#if defined(__FreeBSD__)
	nd_uint32_t	ridentifier;
	nd_uint8_t	reserve;
	nd_uint8_t	pad2[3];
#elif defined(__OpenBSD__)
	struct pf_addr	saddr;
	struct pf_addr	daddr;
	nd_uint16_t	sport;
	nd_uint16_t	dport;
#endif
};
#define MAX_PFLOG_HDRLEN 100	/* 61 + 3 + 16 + 16 + 2 + 2 */

/*
 * Reason values.
 */
#define PFRES_MATCH	0
#define PFRES_BADOFF	1
#define PFRES_FRAG	2
#define PFRES_SHORT	3
#define PFRES_NORM	4
#define PFRES_MEMORY	5
#define PFRES_TS	6
#define PFRES_CONGEST	7
#define PFRES_IPOPTIONS 8
#define PFRES_PROTCKSUM 9
#define PFRES_BADSTATE	10
#define PFRES_STATEINS	11
#define PFRES_MAXSTATES	12
#define PFRES_SRCLIMIT	13
#define PFRES_SYNPROXY	14
#if defined(__FreeBSD__)
#define PFRES_MAPFAILED	15
#elif defined(__NetBSD__)
#define PFRES_STATELOCKED 15
#elif defined(__OpenBSD__)
#define PFRES_TRANSLATE	15
#define PFRES_NOROUTE	16
#elif defined(__APPLE__)
#define PFRES_DUMMYNET  15
#endif

static const struct tok pf_reasons[] = {
	{ PFRES_MATCH,		"0(match)" },
	{ PFRES_BADOFF,		"1(bad-offset)" },
	{ PFRES_FRAG,		"2(fragment)" },
	{ PFRES_SHORT,		"3(short)" },
	{ PFRES_NORM,		"4(normalize)" },
	{ PFRES_MEMORY,		"5(memory)" },
	{ PFRES_TS,		"6(bad-timestamp)" },
	{ PFRES_CONGEST,	"7(congestion)" },
	{ PFRES_IPOPTIONS,	"8(ip-option)" },
	{ PFRES_PROTCKSUM,	"9(proto-cksum)" },
	{ PFRES_BADSTATE,	"10(state-mismatch)" },
	{ PFRES_STATEINS,	"11(state-insert)" },
	{ PFRES_MAXSTATES,	"12(state-limit)" },
	{ PFRES_SRCLIMIT,	"13(src-limit)" },
	{ PFRES_SYNPROXY,	"14(synproxy)" },
#if defined(__FreeBSD__)
	{ PFRES_MAPFAILED,	"15(map-failed)" },
#elif defined(__NetBSD__)
	{ PFRES_STATELOCKED,	"15(state-locked)" },
#elif defined(__OpenBSD__)
	{ PFRES_TRANSLATE,	"15(translate)" },
	{ PFRES_NOROUTE,	"16(no-route)" },
#elif defined(__APPLE__)
	{ PFRES_DUMMYNET,	"15(dummynet)" },
#endif
	{ 0,	NULL }
};

/*
 * Action values.
 */
#define PF_PASS			0
#define PF_DROP			1
#define PF_SCRUB		2
#define PF_NOSCRUB		3
#define PF_NAT			4
#define PF_NONAT		5
#define PF_BINAT		6
#define PF_NOBINAT		7
#define PF_RDR			8
#define PF_NORDR		9
#define PF_SYNPROXY_DROP	10
#if defined(__FreeBSD__)
#define PF_DEFER		11
#define PF_MATCH		12
#elif defined(__OpenBSD__)
#define PF_DEFER		11
#define PF_MATCH		12
#define PF_DIVERT		13
#define PF_RT			14
#define PF_AFRT			15
#elif defined(__APPLE__)
#define PF_DUMMYNET		11
#define PF_NODUMMYNET		12
#define PF_NAT64		13
#define PF_NONAT64		14
#endif

static const struct tok pf_actions[] = {
	{ PF_PASS,		"pass" },
	{ PF_DROP,		"block" },
	{ PF_SCRUB,		"scrub" },
	{ PF_NOSCRUB,		"noscrub" },
	{ PF_NAT,		"nat" },
	{ PF_NONAT,		"nonat" },
	{ PF_BINAT,		"binat" },
	{ PF_NOBINAT,		"nobinat" },
	{ PF_RDR,		"rdr" },
	{ PF_NORDR,		"nordr" },
	{ PF_SYNPROXY_DROP,	"synproxy-drop" },
#if defined(__FreeBSD__)
	{ PF_DEFER,		"defer" },
	{ PF_MATCH,		"match" },
#elif defined(__OpenBSD__)
	{ PF_DEFER,		"defer" },
	{ PF_MATCH,		"match" },
	{ PF_DIVERT,		"divert" },
	{ PF_RT,		"rt" },
	{ PF_AFRT,		"afrt" },
#elif defined(__APPLE__)
	{ PF_DUMMYNET,		"dummynet" },
	{ PF_NODUMMYNET,	"nodummynet" },
	{ PF_NAT64,		"nat64" },
	{ PF_NONAT64,		"nonat64" },
#endif
	{ 0,			NULL }
};

/*
 * Direction values.
 */
#define PF_INOUT	0
#define PF_IN		1
#define PF_OUT		2
#if defined(__OpenBSD__)
#define PF_FWD		3
#endif

static const struct tok pf_directions[] = {
	{ PF_INOUT,	"in/out" },
	{ PF_IN,	"in" },
	{ PF_OUT,	"out" },
#if defined(__OpenBSD__)
	{ PF_FWD,	"fwd" },
#endif
	{ 0,		NULL }
};

static void
pflog_print(netdissect_options *ndo, const struct pfloghdr *hdr)
{
	uint32_t rulenr, subrulenr;

	ndo->ndo_protocol = "pflog";
	rulenr = GET_BE_U_4(hdr->rulenr);
	subrulenr = GET_BE_U_4(hdr->subrulenr);
	if (subrulenr == (uint32_t)-1)
		ND_PRINT("rule %u/", rulenr);
	else {
		ND_PRINT("rule %u.", rulenr);
		nd_printjnp(ndo, (const u_char*)hdr->ruleset, PFLOG_RULESET_NAME_SIZE);
		ND_PRINT(".%u/", subrulenr);
	}

	ND_PRINT("%s: %s %s on ",
	    tok2str(pf_reasons, "unkn(%u)", GET_U_1(hdr->reason)),
	    tok2str(pf_actions, "unkn(%u)", GET_U_1(hdr->action)),
	    tok2str(pf_directions, "unkn(%u)", GET_U_1(hdr->dir)));
	nd_printjnp(ndo, (const u_char*)hdr->ifname, PFLOG_IFNAMSIZ);
	ND_PRINT(": ");
}

void
pflog_if_print(netdissect_options *ndo, const struct pcap_pkthdr *h,
               const u_char *p)
{
	u_int length = h->len;
	u_int hdrlen;
	u_int caplen = h->caplen;
	const struct pfloghdr *hdr;
	uint8_t af;

	ndo->ndo_protocol = "pflog";
	/* check length */
	ND_ICHECK_U(length, <, MIN_PFLOG_HDRLEN);

	hdr = (const struct pfloghdr *)p;
	hdrlen = GET_U_1(hdr->length);
	ND_ICHECK_U(hdrlen, <, MIN_PFLOG_HDRLEN);
	hdrlen = roundup2(hdrlen, 4);
	ND_ICHECK_U(hdrlen, >, MAX_PFLOG_HDRLEN);

	/* print what we know */
	ND_TCHECK_LEN(hdr, hdrlen);
	ndo->ndo_ll_hdr_len += hdrlen;
	if (ndo->ndo_eflag)
		pflog_print(ndo, hdr);

	/* skip to the real packet */
	af = GET_U_1(hdr->af);
	length -= hdrlen;
	caplen -= hdrlen;
	p += hdrlen;
	switch (af) {

		/*
		 * If there's a system that doesn't use the AF_INET
		 * from 4.2BSD, feel free to add its value to af.h
		 * and use it here.
		 *
		 * Hopefully, there isn't.
		 */
		case BSD_AF_INET:
		        ip_print(ndo, p, length);
			break;

		/*
		 * Try all AF_INET6 values for all systems with pflog,
		 * including Darwin.
		 */
		case BSD_AF_INET6_BSD:
		case BSD_AF_INET6_FREEBSD:
		case BSD_AF_INET6_DARWIN:
			ip6_print(ndo, p, length);
			break;

	default:
		/* address family not handled, print raw packet */
		if (!ndo->ndo_eflag)
			pflog_print(ndo, hdr);
		if (!ndo->ndo_suppress_default_print)
			ND_DEFAULTPRINT(p, caplen);
	}

	return;

invalid:
	nd_print_invalid(ndo);
}
