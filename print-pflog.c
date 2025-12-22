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

#include <limits.h>

#include "netdissect-stdinc.h"

#define ND_LONGJMP_FROM_TCHECK
#include "netdissect.h"
#include "extract.h"
#include "af.h"
#include "addrtostr.h"

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

/*
 * This header is:
 *
 *    61 bytes long on NetBSD, DragonFly BSD, and Darwin;
 *    84 bytes long on OpenBSD;
 *    72 bytes long on FreeBSD;
 *
 * which, unfortunately, does not allow us to distinguish, based on
 * the header length, between the three OSes listed as having 61-byte
 * headers.  As the action values differ between them, this makes it
 * impossible to correctly dissect the reason values that differ
 * between NetBSD and Darwin (reason value 15) without having some
 * way to explicitly tell tcpdump what to do.
 *
 * (We could, I guess, label reason value 15 as
 * "state-locked (NetBSD)/dummynet (macOS etc.)" or something such as
 * that.)
 */
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
	union {
		struct pflog_openbsd_only {
			nd_uint8_t	rewritten;
			nd_uint8_t	naf;
			nd_uint8_t	pad[1];
			struct pf_addr	saddr;
			struct pf_addr	daddr;
			nd_uint16_t	sport;
			nd_uint16_t	dport;
		} openbsd;
		struct pflog_freebsd_only {
			nd_uint8_t	pad[3];
			nd_uint32_t	ridentifier;
			nd_uint8_t	reserve;
		} freebsd;
	} u;
};

/*
 * FreeBSD header length.
 */
#define PFLOG_HEADER_LEN_FREEBSD	69

/*
 * OpenBSD header length.
 */
#define PFLOG_HEADER_LEN_OPENBSD	100

/*
 * DragonFly BSD, NetBSD and Darwin header length.
 * Older versions of FreeBSD and OpenBSD may have used this
 * as well.
 *
 * Unfortunately, this means we can't distinguish between Darwin, NetBSD,
 * and DragonFly BSD based on the header length.
 */
#define PFLOG_HEADER_LEN_OTHER		61

/*
 * These are the minimum and maximum pflog header lengths.
 */
#define MIN_PFLOG_HDRLEN 61
#define MAX_PFLOG_HDRLEN 100

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

/* FreeBSD */
#define PFRES_MAPFAILED	15

/* OpenBSD */
#define PFRES_TRANSLATE	15
#define PFRES_NOROUTE	16

/* NetBSD/Darwin */
#define PFRES_STATELOCKED_DUMMYNET 15	/* STATELOCKED on NetBSD, DUMMYNET on Darwin */
#define PFRES_INVPORT	16 /* INVPORT on Darwin */

static const struct tok pf_reasons_freebsd[] = {
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
	{ PFRES_MAPFAILED,	"15(map-failed)" },
	{ 0,	NULL }
};

static const struct tok pf_reasons_openbsd[] = {
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
	{ PFRES_TRANSLATE,	"15(translate)" },
	{ PFRES_NOROUTE,	"16(no-route)" },
	{ 0,	NULL }
};

static const struct tok pf_reasons_other[] = {
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
	{ PFRES_STATELOCKED_DUMMYNET,
				"15(state-locked (NetBSD)/dummynet(Darwin)" },
	{ PFRES_INVPORT,	"16(invalid-port (Darwin))" },
	{ 0,	NULL }
};

/*
 * Action values.
 */
#define PFACT_PASS		0
#define PFACT_DROP		1
#define PFACT_SCRUB		2
#define PFACT_NOSCRUB		3
#define PFACT_NAT		4
#define PFACT_NONAT		5
#define PFACT_BINAT		6
#define PFACT_NOBINAT		7
#define PFACT_RDR		8
#define PFACT_NORDR		9
#define PFACT_SYNPROXY_DROP	10

/* FreeBSD and OpenBSD */
#define PFACT_DEFER		11

/* FreeBSD */
#define PFACT_MATCH		12

/* OpenBSD */
#define PFACT_MATCH		12
#define PFACT_DIVERT		13
#define PFACT_RT		14
#define PFACT_AFRT		15

/* Darwin */
#define PFACT_DUMMYNET		11
#define PFACT_NODUMMYNET	12
#define PFACT_NAT64		13
#define PFACT_NONAT64		14

static const struct tok pf_actions_freebsd[] = {
	{ PFACT_PASS,		"pass" },
	{ PFACT_DROP,		"block" },
	{ PFACT_SCRUB,		"scrub" },
	{ PFACT_NOSCRUB,	"noscrub" },
	{ PFACT_NAT,		"nat" },
	{ PFACT_NONAT,		"nonat" },
	{ PFACT_BINAT,		"binat" },
	{ PFACT_NOBINAT,	"nobinat" },
	{ PFACT_RDR,		"rdr" },
	{ PFACT_NORDR,		"nordr" },
	{ PFACT_SYNPROXY_DROP,	"synproxy-drop" },
	{ PFACT_DEFER,		"defer" },
	{ PFACT_MATCH,		"match" },
	{ 0,			NULL }
};

static const struct tok pf_actions_openbsd[] = {
	{ PFACT_PASS,		"pass" },
	{ PFACT_DROP,		"block" },
	{ PFACT_SCRUB,		"scrub" },
	{ PFACT_NOSCRUB,	"noscrub" },
	{ PFACT_NAT,		"nat" },
	{ PFACT_NONAT,		"nonat" },
	{ PFACT_BINAT,		"binat" },
	{ PFACT_NOBINAT,	"nobinat" },
	{ PFACT_RDR,		"rdr" },
	{ PFACT_NORDR,		"nordr" },
	{ PFACT_SYNPROXY_DROP,	"synproxy-drop" },
	{ PFACT_DEFER,		"defer" },
	{ PFACT_MATCH,		"match" },
	{ PFACT_DIVERT,		"divert" },
	{ PFACT_RT,		"rt" },
	{ PFACT_AFRT,		"afrt" },
	{ 0,			NULL }
};

static const struct tok pf_actions_darwin[] = {
	{ PFACT_PASS,		"pass" },
	{ PFACT_DROP,		"block" },
	{ PFACT_SCRUB,		"scrub" },
	{ PFACT_NOSCRUB,	"noscrub" },
	{ PFACT_NAT,		"nat" },
	{ PFACT_NONAT,		"nonat" },
	{ PFACT_BINAT,		"binat" },
	{ PFACT_NOBINAT,	"nobinat" },
	{ PFACT_RDR,		"rdr" },
	{ PFACT_NORDR,		"nordr" },
	{ PFACT_SYNPROXY_DROP,	"synproxy-drop" },
	{ PFACT_DUMMYNET,	"dummynet (Darwin)" },
	{ PFACT_NODUMMYNET,	"nodummynet (Darwin)" },
	{ PFACT_NAT64,		"nat64 (Darwin)" },
	{ PFACT_NONAT64,	"nonat64 (Darwin)" },
	{ 0,			NULL }
};

/*
 * Direction values.
 */
#define PFDIR_INOUT	0
#define PFDIR_IN	1
#define PFDIR_OUT	2

/* OpenBSD */
#define PFDIR_FWD	3

static const struct tok pf_directions_freebsd[] = {
	{ PFDIR_INOUT,	"in/out" },
	{ PFDIR_IN,	"in" },
	{ PFDIR_OUT,	"out" },
	{ 0,		NULL }
};

static const struct tok pf_directions_openbsd[] = {
	{ PFDIR_INOUT,	"in/out" },
	{ PFDIR_IN,	"in" },
	{ PFDIR_OUT,	"out" },
	{ PFDIR_FWD,	"fwd" },
	{ 0,		NULL }
};

static const struct tok pf_directions_other[] = {
	{ PFDIR_INOUT,	"in/out" },
	{ PFDIR_IN,	"in" },
	{ PFDIR_OUT,	"out" },
	{ 0,		NULL }
};

static void
print_pf_addr(netdissect_options *ndo, const char *tag, u_int naf,
    const struct pf_addr *addr, const nd_uint16_t port)
{
	char buf[INET6_ADDRSTRLEN];
	uint16_t portnum;

	ND_PRINT("%s ", tag);
	ND_TCHECK_SIZE(addr);
	switch (naf) {

	case BSD_AF_INET:
		addrtostr(addr->v4, buf, sizeof(buf));
		break;

	case BSD_AF_INET6_BSD:
		addrtostr6(addr->v6, buf, sizeof(buf));
		break;

	default:
		strlcpy(buf, "?", sizeof(buf));
		break;
	}
	ND_PRINT("%s:", buf);
	portnum = GET_BE_U_2(port);
	ND_PRINT("%u", portnum);
}

static void
pflog_print(netdissect_options *ndo, const struct pfloghdr *hdr)
{
	uint8_t length;
	uint32_t rulenr, subrulenr;
	uint32_t uid;
	uint32_t ridentifier;

	ndo->ndo_protocol = "pflog";
	length = GET_U_1(hdr->length);

	rulenr = GET_BE_U_4(hdr->rulenr);
	subrulenr = GET_BE_U_4(hdr->subrulenr);
	ND_PRINT("rule ");
	if (rulenr != (uint32_t)-1) {
		ND_PRINT("%u", rulenr);
		if (hdr->ruleset[0] != '\0') {
			ND_PRINT(".");
			nd_printjnp(ndo, (const u_char*)hdr->ruleset, PFLOG_RULESET_NAME_SIZE);
		}
		if (subrulenr != (uint32_t)-1)
			ND_PRINT(".%u", subrulenr);
	}
	ND_PRINT("/");

	if (length == PFLOG_HEADER_LEN_FREEBSD)
		ND_PRINT("%s", tok2str(pf_reasons_freebsd, "unkn(%u)", GET_U_1(hdr->reason)));
	else if (length == PFLOG_HEADER_LEN_OPENBSD)
		ND_PRINT("%s", tok2str(pf_reasons_openbsd, "unkn(%u)", GET_U_1(hdr->reason)));
	else
		ND_PRINT("%s", tok2str(pf_reasons_other, "unkn(%u)", GET_U_1(hdr->reason)));

	/*
	 * In Darwin (macOS, etc.) and NetBSD, uid is set to
	 * UID_MAX if there's no UID, and UID_MAX is 2^31-1.
	 * UID_MAX is 2^31-1.
	 *
	 * In OpenBSD, uid is set to -1 if there's no UID, which
	 * means we'll see it as UINT_MAX, as we treat it as
	 * unsigned. UID_MAX is 2^32-1.
	 *
	 * In FreeBSD and DragonFly BSD, uid is set to UID_MAX
	 * if there's no UID. UID_MAX is 2^32-1.
	 *
	 * So:
	 *
	 *   For OpenBSD and FreeBSD, check only for 2^32-1 (0xFFFFFFFFU)
	 *   if there's no UID.
	 *
	 *   For other OSes, it's either NetBSD, DragonFly BSD, or Darwin,
	 *   check for both 2^31-1 (0x7FFFFFFFU) (NetBSD and Darwin) and
	 *   2^32-1 (0xFFFFFFFFU) (DragonFly BSD). That runs the risk of
	 *   the UID not being printed for a DragonFly BSD log if it's
	 *   0x7FFFFFFF, but that's *probably* not going to be the case.
	 */
	uid = GET_BE_U_4(hdr->uid);
	if (length == PFLOG_HEADER_LEN_FREEBSD ||
	    length == PFLOG_HEADER_LEN_OPENBSD) {
		if (uid != 0xFFFFFFFFU)
			ND_PRINT(" [uid %u]", uid);
	} else {
		if (uid != 0xFFFFFFFFU && uid != 0x7FFFFFFFU)
			ND_PRINT(" [uid %u]", uid);
	}

	if (length == PFLOG_HEADER_LEN_FREEBSD) {
		ridentifier = GET_BE_U_4(hdr->u.freebsd.ridentifier);
		if (ridentifier != 0)
			ND_PRINT(" [ridentifier %u]", ridentifier);
	}

	if (length == PFLOG_HEADER_LEN_FREEBSD) {
		ND_PRINT(": %s %s on ",
		    tok2str(pf_actions_freebsd, "unkn(%u)", GET_U_1(hdr->action)),
		    tok2str(pf_directions_freebsd, "unkn(%u)", GET_U_1(hdr->dir)));
	} else if (length == PFLOG_HEADER_LEN_OPENBSD) {
		ND_PRINT(": %s %s on ",
		    tok2str(pf_actions_openbsd, "unkn(%u)", GET_U_1(hdr->action)),
		    tok2str(pf_directions_openbsd, "unkn(%u)", GET_U_1(hdr->dir)));
	} else {
		/*
		 * We use the Darwin set of actions, as it's a superset
		 * of the NetBSD/DragonFly BSD set of actions.
		 */
		ND_PRINT(": %s %s on ",
		    tok2str(pf_actions_darwin, "unkn(%u)", GET_U_1(hdr->action)),
		    tok2str(pf_directions_other, "unkn(%u)", GET_U_1(hdr->dir)));
	}
	nd_printjnp(ndo, (const u_char*)hdr->ifname, PFLOG_IFNAMSIZ);
	ND_PRINT(": ");
	if (length == PFLOG_HEADER_LEN_OPENBSD) {
		if (ndo->ndo_vflag && GET_U_1(hdr->u.openbsd.rewritten)) {
			uint8_t naf;

			ND_PRINT("[rewritten: ");
			naf = GET_U_1(hdr->u.openbsd.naf);
			print_pf_addr(ndo, "src", naf, &hdr->u.openbsd.saddr,
			    hdr->u.openbsd.sport);
			ND_PRINT(", ");
			print_pf_addr(ndo, "src", naf, &hdr->u.openbsd.daddr,
			    hdr->u.openbsd.dport);
			ND_PRINT("; ");
		}
	}
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
	ND_ICHECK_U(hdrlen, >, MAX_PFLOG_HDRLEN);
	hdrlen = roundup2(hdrlen, 4);

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
