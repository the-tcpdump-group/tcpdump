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
 * OSPF support contributed by Jeffrey Honig (jch@mitchell.cit.cornell.edu)
 */

#ifndef lint
static const char rcsid[] _U_ =
    "@(#) $Header: /tcpdump/master/tcpdump/print-ospf6.c,v 1.15 2006-09-13 06:31:11 guy Exp $ (LBL)";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <tcpdump-stdinc.h>

#include <stdio.h>
#include <string.h>

#include "interface.h"
#include "addrtoname.h"
#include "extract.h"

#include "ospf.h"
#include "ospf6.h"

static const char tstr[] = " [|ospf3]";

static const struct tok ospf6_option_values[] = {
	{ OSPF6_OPTION_V6,	"V6" },
	{ OSPF6_OPTION_E,	"External" },
	{ OSPF6_OPTION_MC,	"Deprecated" },
	{ OSPF6_OPTION_N,	"NSSA" },
	{ OSPF6_OPTION_R,	"Router" },
	{ OSPF6_OPTION_DC,	"Demand Circuit" },
	{ OSPF6_OPTION_AF,	"AFs Support" },
	{ OSPF6_OPTION_L,	"LLS" },
	{ OSPF6_OPTION_AT,	"Authentication Trailer" },
	{ 0,			NULL }
};

static const struct tok ospf6_rla_flag_values[] = {
	{ RLA_FLAG_B,		"ABR" },
	{ RLA_FLAG_E,		"External" },
	{ RLA_FLAG_V,		"Virtual-Link Endpoint" },
	{ RLA_FLAG_W,		"Wildcard Receiver" },
        { RLA_FLAG_N,           "NSSA Translator" },
	{ 0,			NULL }
};

static const struct tok ospf6_asla_flag_values[] = {
	{ ASLA_FLAG_EXTERNAL,	"External Type 2" },
	{ ASLA_FLAG_FWDADDR,	"Forwarding" },
	{ ASLA_FLAG_ROUTETAG,	"Tag" },
	{ 0,			NULL }
};

static const struct tok ospf6_type_values[] = {
	{ OSPF_TYPE_HELLO,	"Hello" },
	{ OSPF_TYPE_DD,		"Database Description" },
	{ OSPF_TYPE_LS_REQ,	"LS-Request" },
	{ OSPF_TYPE_LS_UPDATE,	"LS-Update" },
	{ OSPF_TYPE_LS_ACK,	"LS-Ack" },
	{ 0,			NULL }
};

static const struct tok ospf6_lsa_values[] = {
	{ LS_TYPE_ROUTER,       "Router" },
	{ LS_TYPE_NETWORK,      "Network" },
	{ LS_TYPE_INTER_AP,     "Inter-Area Prefix" },
	{ LS_TYPE_INTER_AR,     "Inter-Area Router" },
	{ LS_TYPE_ASE,          "External" },
	{ LS_TYPE_GROUP,        "Deprecated" },
	{ LS_TYPE_NSSA,         "NSSA" },
	{ LS_TYPE_LINK,         "Link" },
	{ LS_TYPE_INTRA_AP,     "Intra-Area Prefix" },
        { LS_TYPE_INTRA_ATE,    "Intra-Area TE" },
        { LS_TYPE_GRACE,        "Grace" },
	{ LS_TYPE_RI,           "Router Information" },
	{ LS_TYPE_INTER_ASTE,   "Inter-AS-TE" },
	{ LS_TYPE_L1VPN,        "Layer 1 VPN" },
	{ 0,			NULL }
};

static const struct tok ospf6_ls_scope_values[] = {
	{ LS_SCOPE_LINKLOCAL,   "Link Local" },
	{ LS_SCOPE_AREA,        "Area Local" },
	{ LS_SCOPE_AS,          "Domain Wide" },
	{ 0,			NULL }
};

static const struct tok ospf6_dd_flag_values[] = {
	{ OSPF6_DB_INIT,	"Init" },
	{ OSPF6_DB_MORE,	"More" },
	{ OSPF6_DB_MASTER,	"Master" },
	{ OSPF6_DB_M6,		"IPv6 MTU" },
	{ 0,			NULL }
};

static const struct tok ospf6_lsa_prefix_option_values[] = {
        { LSA_PREFIX_OPT_NU, "No Unicast" },
        { LSA_PREFIX_OPT_LA, "Local address" },
        { LSA_PREFIX_OPT_MC, "Deprecated" },
        { LSA_PREFIX_OPT_P, "Propagate" },
        { LSA_PREFIX_OPT_DN, "Down" },
	{ 0, NULL }
};

static const struct tok ospf6_auth_type_str[] = {
	{ OSPF6_AUTH_TYPE_HMAC,        "HMAC" },
	{ 0, NULL }
};

static void
ospf6_print_ls_type(register u_int ls_type, register const rtrid_t *ls_stateid)
{
        printf("\n\t    %s LSA (%d), %s Scope%s, LSA-ID %s",
               tok2str(ospf6_lsa_values, "Unknown", ls_type & LS_TYPE_MASK),
               ls_type & LS_TYPE_MASK,
               tok2str(ospf6_ls_scope_values, "Unknown", ls_type & LS_SCOPE_MASK),
               ls_type &0x8000 ? ", transitive" : "", /* U-bit */
               ipaddr_string(ls_stateid));
}

static int
ospf6_print_lshdr(register const struct lsa6_hdr *lshp, const u_char *dataend)
{
	if ((u_char *)(lshp + 1) > dataend)
		goto trunc;
	TCHECK(lshp->ls_type);
	TCHECK(lshp->ls_seq);

	printf("\n\t  Advertising Router %s, seq 0x%08x, age %us, length %u",
               ipaddr_string(&lshp->ls_router),
               EXTRACT_32BITS(&lshp->ls_seq),
               EXTRACT_16BITS(&lshp->ls_age),
               EXTRACT_16BITS(&lshp->ls_length)-(u_int)sizeof(struct lsa6_hdr));

	ospf6_print_ls_type(EXTRACT_16BITS(&lshp->ls_type), &lshp->ls_stateid);

	return (0);
trunc:
	return (1);
}

static int
ospf6_print_lsaprefix(const u_int8_t *tptr, u_int lsa_length)
{
	const struct lsa6_prefix *lsapp = (struct lsa6_prefix *)tptr;
	u_int wordlen;
	struct in6_addr prefix;

	if (lsa_length < sizeof (*lsapp) - 4)
		goto trunc;
	lsa_length -= sizeof (*lsapp) - 4;
	TCHECK2(*lsapp, sizeof (*lsapp) - 4);
	wordlen = (lsapp->lsa_p_len + 31) / 32;
	if (wordlen * 4 > sizeof(struct in6_addr)) {
		printf(" bogus prefixlen /%d", lsapp->lsa_p_len);
		goto trunc;
	}
	if (lsa_length < wordlen * 4)
		goto trunc;
	lsa_length -= wordlen * 4;
	TCHECK2(lsapp->lsa_p_prefix, wordlen * 4);
	memset(&prefix, 0, sizeof(prefix));
	memcpy(&prefix, lsapp->lsa_p_prefix, wordlen * 4);
	printf("\n\t\t%s/%d", ip6addr_string(&prefix),
		lsapp->lsa_p_len);
        if (lsapp->lsa_p_opt) {
            printf(", Options [%s]",
                   bittok2str(ospf6_lsa_prefix_option_values,
                              "none", lsapp->lsa_p_opt));
        }
        printf(", metric %u", EXTRACT_16BITS(&lsapp->lsa_p_metric));
	return sizeof(*lsapp) - 4 + wordlen * 4;

trunc:
	return -1;
}


/*
 * Print a single link state advertisement.  If truncated return 1, else 0.
 */
static int
ospf6_print_lsa(register const struct lsa6 *lsap, const u_char *dataend)
{
	register const struct rlalink6 *rlp;
#if 0
	register const struct tos_metric *tosp;
#endif
	register const rtrid_t *ap;
#if 0
	register const struct aslametric *almp;
	register const struct mcla *mcp;
#endif
	register const struct llsa *llsap;
	register const struct lsa6_prefix *lsapp;
#if 0
	register const u_int32_t *lp;
#endif
	register u_int prefixes;
	register int bytelen;
	register u_int length, lsa_length;
	u_int32_t flags32;
	const u_int8_t *tptr;

	if (ospf6_print_lshdr(&lsap->ls_hdr, dataend))
		return (1);
	TCHECK(lsap->ls_hdr.ls_length);
        length = EXTRACT_16BITS(&lsap->ls_hdr.ls_length);

	/*
	 * The LSA length includes the length of the header;
	 * it must have a value that's at least that length.
	 * If it does, find the length of what follows the
	 * header.
	 */
        if (length < sizeof(struct lsa6_hdr) || (u_char *)lsap + length > dataend)
        	return (1);
        lsa_length = length - sizeof(struct lsa6_hdr);
        tptr = (u_int8_t *)lsap+sizeof(struct lsa6_hdr);

	switch (EXTRACT_16BITS(&lsap->ls_hdr.ls_type)) {
	case LS_TYPE_ROUTER | LS_SCOPE_AREA:
		if (lsa_length < sizeof (lsap->lsa_un.un_rla.rla_options))
			return (1);
		lsa_length -= sizeof (lsap->lsa_un.un_rla.rla_options);
		TCHECK(lsap->lsa_un.un_rla.rla_options);
                printf("\n\t      Options [%s]",
                       bittok2str(ospf6_option_values, "none",
                                  EXTRACT_32BITS(&lsap->lsa_un.un_rla.rla_options)));
                printf(", RLA-Flags [%s]",
                       bittok2str(ospf6_rla_flag_values, "none",
                                  lsap->lsa_un.un_rla.rla_flags));

		rlp = lsap->lsa_un.un_rla.rla_link;
		while (lsa_length != 0) {
			if (lsa_length < sizeof (*rlp))
				return (1);
			lsa_length -= sizeof (*rlp);
			TCHECK(*rlp);
			switch (rlp->link_type) {

			case RLA_TYPE_VIRTUAL:
				printf("\n\t      Virtual Link: Neighbor Router-ID %s"
                                       "\n\t      Neighbor Interface-ID %s, Interface %s",
                                       ipaddr_string(&rlp->link_nrtid),
                                       ipaddr_string(&rlp->link_nifid),
                                       ipaddr_string(&rlp->link_ifid));
                                break;

			case RLA_TYPE_ROUTER:
				printf("\n\t      Neighbor Router-ID %s"
                                       "\n\t      Neighbor Interface-ID %s, Interface %s",
                                       ipaddr_string(&rlp->link_nrtid),
                                       ipaddr_string(&rlp->link_nifid),
                                       ipaddr_string(&rlp->link_ifid));
				break;

			case RLA_TYPE_TRANSIT:
				printf("\n\t      Neighbor Network-ID %s"
                                       "\n\t      Neighbor Interface-ID %s, Interface %s",
				    ipaddr_string(&rlp->link_nrtid),
				    ipaddr_string(&rlp->link_nifid),
				    ipaddr_string(&rlp->link_ifid));
				break;

			default:
				printf("\n\t      Unknown Router Links Type 0x%02x",
				    rlp->link_type);
				return (0);
			}
			printf(", metric %d", EXTRACT_16BITS(&rlp->link_metric));
			rlp++;
		}
		break;

	case LS_TYPE_NETWORK | LS_SCOPE_AREA:
		if (lsa_length < sizeof (lsap->lsa_un.un_nla.nla_options))
			return (1);
		lsa_length -= sizeof (lsap->lsa_un.un_nla.nla_options);
		TCHECK(lsap->lsa_un.un_nla.nla_options);
                printf("\n\t      Options [%s]",
                       bittok2str(ospf6_option_values, "none",
                                  EXTRACT_32BITS(&lsap->lsa_un.un_nla.nla_options)));

		printf("\n\t      Connected Routers:");
		ap = lsap->lsa_un.un_nla.nla_router;
		while (lsa_length != 0) {
			if (lsa_length < sizeof (*ap))
				return (1);
			lsa_length -= sizeof (*ap);
			TCHECK(*ap);
			printf("\n\t\t%s", ipaddr_string(ap));
			++ap;
		}
		break;

	case LS_TYPE_INTER_AP | LS_SCOPE_AREA:
		if (lsa_length < sizeof (lsap->lsa_un.un_inter_ap.inter_ap_metric))
			return (1);
		lsa_length -= sizeof (lsap->lsa_un.un_inter_ap.inter_ap_metric);
		TCHECK(lsap->lsa_un.un_inter_ap.inter_ap_metric);
		printf(", metric %u",
			EXTRACT_32BITS(&lsap->lsa_un.un_inter_ap.inter_ap_metric) & SLA_MASK_METRIC);

		tptr = (u_int8_t *)lsap->lsa_un.un_inter_ap.inter_ap_prefix;
		while (lsa_length != 0) {
			bytelen = ospf6_print_lsaprefix(tptr, lsa_length);
			if (bytelen < 0)
				goto trunc;
			lsa_length -= bytelen;
			tptr += bytelen;
		}
		break;

	case LS_TYPE_ASE | LS_SCOPE_AS:
		if (lsa_length < sizeof (lsap->lsa_un.un_asla.asla_metric))
			return (1);
		lsa_length -= sizeof (lsap->lsa_un.un_asla.asla_metric);
		TCHECK(lsap->lsa_un.un_asla.asla_metric);
		flags32 = EXTRACT_32BITS(&lsap->lsa_un.un_asla.asla_metric);
                printf("\n\t     Flags [%s]",
                       bittok2str(ospf6_asla_flag_values, "none", flags32));
		printf(" metric %u",
		       EXTRACT_32BITS(&lsap->lsa_un.un_asla.asla_metric) &
		       ASLA_MASK_METRIC);

		tptr = (u_int8_t *)lsap->lsa_un.un_asla.asla_prefix;
		lsapp = (struct lsa6_prefix *)tptr;
		bytelen = ospf6_print_lsaprefix(tptr, lsa_length);
		if (bytelen < 0)
			goto trunc;
		lsa_length -= bytelen;
		tptr += bytelen;

		if ((flags32 & ASLA_FLAG_FWDADDR) != 0) {
			struct in6_addr *fwdaddr6;

			fwdaddr6 = (struct in6_addr *)tptr;
			if (lsa_length < sizeof (*fwdaddr6))
				return (1);
			lsa_length -= sizeof (*fwdaddr6);
			TCHECK(*fwdaddr6);
			printf(" forward %s",
			       ip6addr_string(fwdaddr6));
			tptr += sizeof(*fwdaddr6);
		}

		if ((flags32 & ASLA_FLAG_ROUTETAG) != 0) {
			if (lsa_length < sizeof (u_int32_t))
				return (1);
			lsa_length -= sizeof (u_int32_t);
			TCHECK(*(u_int32_t *)tptr);
			printf(" tag %s",
			       ipaddr_string((u_int32_t *)tptr));
			tptr += sizeof(u_int32_t);
		}

		if (lsapp->lsa_p_metric) {
			if (lsa_length < sizeof (u_int32_t))
				return (1);
			lsa_length -= sizeof (u_int32_t);
			TCHECK(*(u_int32_t *)tptr);
			printf(" RefLSID: %s",
			       ipaddr_string((u_int32_t *)tptr));
			tptr += sizeof(u_int32_t);
		}
		break;

	case LS_TYPE_LINK:
		/* Link LSA */
		llsap = &lsap->lsa_un.un_llsa;
		if (lsa_length < sizeof (llsap->llsa_priandopt))
			return (1);
		lsa_length -= sizeof (llsap->llsa_priandopt);
		TCHECK(llsap->llsa_priandopt);
                printf("\n\t      Options [%s]",
                       bittok2str(ospf6_option_values, "none",
                                  EXTRACT_32BITS(&llsap->llsa_options)));

		if (lsa_length < sizeof (llsap->llsa_lladdr) + sizeof (llsap->llsa_nprefix))
			return (1);
		lsa_length -= sizeof (llsap->llsa_lladdr) + sizeof (llsap->llsa_nprefix);
                prefixes = EXTRACT_32BITS(&llsap->llsa_nprefix);
		printf("\n\t      Priority %d, Link-local address %s, Prefixes %d:",
                       llsap->llsa_priority,
                       ip6addr_string(&llsap->llsa_lladdr),
                       prefixes);

		tptr = (u_int8_t *)llsap->llsa_prefix;
		while (prefixes > 0) {
			bytelen = ospf6_print_lsaprefix(tptr, lsa_length);
			if (bytelen < 0)
				goto trunc;
			prefixes--;
			lsa_length -= bytelen;
			tptr += bytelen;
		}
		break;

	case LS_TYPE_INTRA_AP | LS_SCOPE_AREA:
		/* Intra-Area-Prefix LSA */
		if (lsa_length < sizeof (lsap->lsa_un.un_intra_ap.intra_ap_rtid))
			return (1);
		lsa_length -= sizeof (lsap->lsa_un.un_intra_ap.intra_ap_rtid);
		TCHECK(lsap->lsa_un.un_intra_ap.intra_ap_rtid);
		ospf6_print_ls_type(
			EXTRACT_16BITS(&lsap->lsa_un.un_intra_ap.intra_ap_lstype),
			&lsap->lsa_un.un_intra_ap.intra_ap_lsid);

		if (lsa_length < sizeof (lsap->lsa_un.un_intra_ap.intra_ap_nprefix))
			return (1);
		lsa_length -= sizeof (lsap->lsa_un.un_intra_ap.intra_ap_nprefix);
		TCHECK(lsap->lsa_un.un_intra_ap.intra_ap_nprefix);
                prefixes = EXTRACT_16BITS(&lsap->lsa_un.un_intra_ap.intra_ap_nprefix);
		printf("\n\t      Prefixes %d:", prefixes);

		tptr = (u_int8_t *)lsap->lsa_un.un_intra_ap.intra_ap_prefix;
		while (prefixes > 0) {
			bytelen = ospf6_print_lsaprefix(tptr, lsa_length);
			if (bytelen < 0)
				goto trunc;
			prefixes--;
			lsa_length -= bytelen;
			tptr += bytelen;
		}
		break;

        case LS_TYPE_GRACE | LS_SCOPE_LINKLOCAL:
                if (ospf_print_grace_lsa(tptr, lsa_length) == -1) {
                    return 1;
                }
                break;

        case LS_TYPE_INTRA_ATE | LS_SCOPE_LINKLOCAL:
                if (ospf_print_te_lsa(tptr, lsa_length) == -1) {
                    return 1;
                }
                break;

	default:
                if(!print_unknown_data(gndo,tptr,
                                       "\n\t      ",
                                       lsa_length)) {
                    return (1);
                }
                break;
	}

	return (0);
trunc:
	return (1);
}

static int
ospf6_decode_v3(register const struct ospf6hdr *op,
    register const u_char *dataend)
{
	register const rtrid_t *ap;
	register const struct lsr6 *lsrp;
	register const struct lsa6_hdr *lshp;
	register const struct lsa6 *lsap;
	register int i;

	switch (op->ospf6_type) {

	case OSPF_TYPE_HELLO:
                printf("\n\tOptions [%s]",
                       bittok2str(ospf6_option_values, "none",
                                  EXTRACT_32BITS(&op->ospf6_hello.hello_options)));

                TCHECK(op->ospf6_hello.hello_deadint);
                printf("\n\t  Hello Timer %us, Dead Timer %us, Interface-ID %s, Priority %u",
                       EXTRACT_16BITS(&op->ospf6_hello.hello_helloint),
                       EXTRACT_16BITS(&op->ospf6_hello.hello_deadint),
                       ipaddr_string(&op->ospf6_hello.hello_ifid),
                       op->ospf6_hello.hello_priority);

		TCHECK(op->ospf6_hello.hello_dr);
		if (op->ospf6_hello.hello_dr != 0)
			printf("\n\t  Designated Router %s",
			    ipaddr_string(&op->ospf6_hello.hello_dr));
		TCHECK(op->ospf6_hello.hello_bdr);
		if (op->ospf6_hello.hello_bdr != 0)
			printf(", Backup Designated Router %s",
			    ipaddr_string(&op->ospf6_hello.hello_bdr));
		if (vflag > 1) {
			printf("\n\t  Neighbor List:");
			ap = op->ospf6_hello.hello_neighbor;
			while ((u_char *)ap < dataend) {
				TCHECK(*ap);
				printf("\n\t    %s", ipaddr_string(ap));
				++ap;
			}
		}
		break;	/* HELLO */

	case OSPF_TYPE_DD:
		TCHECK(op->ospf6_db.db_options);
                printf("\n\tOptions [%s]",
                       bittok2str(ospf6_option_values, "none",
                                  EXTRACT_32BITS(&op->ospf6_db.db_options)));
		TCHECK(op->ospf6_db.db_flags);
                printf(", DD Flags [%s]",
                       bittok2str(ospf6_dd_flag_values,"none",op->ospf6_db.db_flags));

		TCHECK(op->ospf6_db.db_seq);
		printf(", MTU %u, DD-Sequence 0x%08x",
                       EXTRACT_16BITS(&op->ospf6_db.db_mtu),
                       EXTRACT_32BITS(&op->ospf6_db.db_seq));
		if (vflag > 1) {
			/* Print all the LS adv's */
			lshp = op->ospf6_db.db_lshdr;
			while ((u_char *)lshp < dataend) {
				if (ospf6_print_lshdr(lshp++, dataend))
					goto trunc;
			}
		}
		break;

	case OSPF_TYPE_LS_REQ:
		if (vflag > 1) {
			lsrp = op->ospf6_lsr;
			while ((u_char *)lsrp < dataend) {
				TCHECK(*lsrp);
                                printf("\n\t  Advertising Router %s",
                                       ipaddr_string(&lsrp->ls_router));
				ospf6_print_ls_type(EXTRACT_16BITS(&lsrp->ls_type),
                                                    &lsrp->ls_stateid);
				++lsrp;
			}
		}
		break;

	case OSPF_TYPE_LS_UPDATE:
		if (vflag > 1) {
			lsap = op->ospf6_lsu.lsu_lsa;
			TCHECK(op->ospf6_lsu.lsu_count);
			i = EXTRACT_32BITS(&op->ospf6_lsu.lsu_count);
			while ((u_char *)lsap < dataend && i--) {
				if (ospf6_print_lsa(lsap, dataend))
					goto trunc;
				lsap = (struct lsa6 *)((u_char *)lsap +
				    EXTRACT_16BITS(&lsap->ls_hdr.ls_length));
			}
		}
		break;


	case OSPF_TYPE_LS_ACK:
		if (vflag > 1) {
			lshp = op->ospf6_lsa.lsa_lshdr;
			while ((u_char *)lshp < dataend) {
				if (ospf6_print_lshdr(lshp++, dataend))
					goto trunc;
			}
		}
		break;

	default:
		break;
	}
	return (0);
trunc:
	return (1);
}

/* RFC5613 Section 2.2 (w/o the TLVs) */
static int
ospf6_print_lls(const u_char *cp, const u_int len)
{
	uint16_t llsdatalen;

	if (len == 0)
		return 0;
	if (len < OSPF_LLS_HDRLEN)
		goto trunc;
	/* Checksum */
	TCHECK2(*cp, 2);
	printf("\n\tLLS Checksum 0x%04x", EXTRACT_16BITS(cp));
	cp += 2;
	/* LLS Data Length */
	TCHECK2(*cp, 2);
	llsdatalen = EXTRACT_16BITS(cp);
	printf(", Data Length %u", llsdatalen);
	if (llsdatalen < OSPF_LLS_HDRLEN || llsdatalen > len)
		goto trunc;
	cp += 2;
	/* LLS TLVs */
	TCHECK2(*cp, llsdatalen - OSPF_LLS_HDRLEN);
	/* FIXME: code in print-ospf.c can be reused to decode the TLVs */

	return llsdatalen;
trunc:
	return -1;
}

/* RFC6506 Section 4.1 */
static int
ospf6_decode_at(const u_char *cp, const u_int len)
{
	uint16_t authdatalen;

	if (len == 0)
		return 0;
	if (len < OSPF6_AT_HDRLEN)
		goto trunc;
	/* Authentication Type */
	TCHECK2(*cp, 2);
	printf("\n\tAuthentication Type %s", tok2str(ospf6_auth_type_str, "unknown (0x%04x)", EXTRACT_16BITS(cp)));
	cp += 2;
	/* Auth Data Len */
	TCHECK2(*cp, 2);
	authdatalen = EXTRACT_16BITS(cp);
	printf(", Length %u", authdatalen);
	if (authdatalen < OSPF6_AT_HDRLEN || authdatalen > len)
		goto trunc;
	cp += 2;
	/* Reserved */
	TCHECK2(*cp, 2);
	cp += 2;
	/* Security Association ID */
	TCHECK2(*cp, 2);
	printf(", SAID %u", EXTRACT_16BITS(cp));
	cp += 2;
	/* Cryptographic Sequence Number (High-Order 32 Bits) */
	TCHECK2(*cp, 4);
	printf(", CSN 0x%08x", EXTRACT_32BITS(cp));
	cp += 4;
	/* Cryptographic Sequence Number (Low-Order 32 Bits) */
	TCHECK2(*cp, 4);
	printf(":%08x", EXTRACT_32BITS(cp));
	cp += 4;
	/* Authentication Data */
	TCHECK2(*cp, authdatalen - OSPF6_AT_HDRLEN);
	if (vflag > 1)
		print_unknown_data(gndo,cp, "\n\tAuthentication Data ", authdatalen - OSPF6_AT_HDRLEN);
	return 0;

trunc:
	return 1;
}

/* The trailing data may include LLS and/or AT data (in this specific order).
 * LLS data may be present only in Hello and DBDesc packets with the L-bit set.
 * AT data may be present in Hello and DBDesc packets with the AT-bit set or in
 * any other packet type, thus decode the AT data regardless of the AT-bit.
 */
static int
ospf6_decode_v3_trailer(const struct ospf6hdr *op, const u_char *cp, const unsigned len)
{
	int llslen = 0;
	u_char lls_hello = op->ospf6_type == OSPF_TYPE_HELLO &&
	                   op->ospf6_hello.hello_options & OSPF6_OPTION_L;
	u_char lls_dd    = op->ospf6_type == OSPF_TYPE_DD &&
	                   op->ospf6_db.db_options & OSPF6_OPTION_L;

	if ((lls_hello || lls_dd) && (llslen = ospf6_print_lls(cp, len)) < 0)
		goto trunc;
	return ospf6_decode_at(cp + llslen, len - llslen);

trunc:
	return 1;
}

void
ospf6_print(register const u_char *bp, register u_int length)
{
	register const struct ospf6hdr *op;
	register const u_char *dataend;
	register const char *cp;
	uint16_t datalen;

	op = (struct ospf6hdr *)bp;

	/* If the type is valid translate it, or just print the type */
	/* value.  If it's not valid, say so and return */
	TCHECK(op->ospf6_type);
	cp = tok2str(ospf6_type_values, "unknown packet type (%u)", op->ospf6_type);
	printf("OSPFv%u, %s, length %d", op->ospf6_version, cp, length);
	if (*cp == 'u') {
		return;
        }

        if(!vflag) { /* non verbose - so lets bail out here */
                return;
        }

	/* OSPFv3 data always comes first and optional trailing data may follow. */
	TCHECK(op->ospf6_len);
	datalen = EXTRACT_16BITS(&op->ospf6_len);
	if (datalen > length) {
		printf(" [len %d]", datalen);
		return;
	}
	dataend = bp + datalen;

	TCHECK(op->ospf6_routerid);
	printf("\n\tRouter-ID %s", ipaddr_string(&op->ospf6_routerid));

	TCHECK(op->ospf6_areaid);
	if (op->ospf6_areaid != 0)
		printf(", Area %s", ipaddr_string(&op->ospf6_areaid));
	else
		printf(", Backbone Area");
	TCHECK(op->ospf6_instanceid);
	if (op->ospf6_instanceid)
		printf(", Instance %u", op->ospf6_instanceid);

	/* Do rest according to version.	 */
	switch (op->ospf6_version) {

	case 3:
		/* ospf version 3 */
		if (ospf6_decode_v3(op, dataend) ||
		    ospf6_decode_v3_trailer(op, dataend, length - datalen))
			goto trunc;
		break;
	}			/* end switch on version */

	return;
trunc:
	fputs(tstr, stdout);
}
