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

/* \summary: Open Shortest Path First (OSPF) printer */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "netdissect-stdinc.h"

#include "netdissect.h"
#include "addrtoname.h"
#include "extract.h"
#include "gmpls.h"

#include "ospf.h"


static const struct tok ospf_option_values[] = {
        { OSPF_OPTION_T,	"MultiTopology" }, /* draft-ietf-ospf-mt-09 */
	{ OSPF_OPTION_E,	"External" },
	{ OSPF_OPTION_MC,	"Multicast" },
	{ OSPF_OPTION_NP,	"NSSA" },
        { OSPF_OPTION_L,        "LLS" },
	{ OSPF_OPTION_DC,	"Demand Circuit" },
	{ OSPF_OPTION_O,	"Opaque" },
	{ OSPF_OPTION_DN,	"Up/Down" },
	{ 0,			NULL }
};

static const struct tok ospf_authtype_values[] = {
	{ OSPF_AUTH_NONE,	"none" },
	{ OSPF_AUTH_SIMPLE,	"simple" },
	{ OSPF_AUTH_MD5,	"MD5" },
	{ 0,			NULL }
};

static const struct tok ospf_rla_flag_values[] = {
	{ RLA_FLAG_B,		"ABR" },
	{ RLA_FLAG_E,		"ASBR" },
	{ RLA_FLAG_W1,		"Virtual" },
	{ RLA_FLAG_W2,		"W2" },
	{ 0,			NULL }
};

static const struct tok type2str[] = {
	{ OSPF_TYPE_HELLO,	"Hello" },
	{ OSPF_TYPE_DD,		"Database Description" },
	{ OSPF_TYPE_LS_REQ,	"LS-Request" },
	{ OSPF_TYPE_LS_UPDATE,	"LS-Update" },
	{ OSPF_TYPE_LS_ACK,	"LS-Ack" },
	{ 0,			NULL }
};

static const struct tok lsa_values[] = {
	{ LS_TYPE_ROUTER,       "Router" },
	{ LS_TYPE_NETWORK,      "Network" },
	{ LS_TYPE_SUM_IP,       "Summary" },
	{ LS_TYPE_SUM_ABR,      "ASBR Summary" },
	{ LS_TYPE_ASE,          "External" },
	{ LS_TYPE_GROUP,        "Multicast Group" },
	{ LS_TYPE_NSSA,         "NSSA" },
	{ LS_TYPE_OPAQUE_LL,    "Link Local Opaque" },
	{ LS_TYPE_OPAQUE_AL,    "Area Local Opaque" },
	{ LS_TYPE_OPAQUE_DW,    "Domain Wide Opaque" },
	{ 0,			NULL }
};

static const struct tok ospf_dd_flag_values[] = {
	{ OSPF_DB_INIT,	        "Init" },
	{ OSPF_DB_MORE,	        "More" },
	{ OSPF_DB_MASTER,	"Master" },
    { OSPF_DB_RESYNC,	"OOBResync" },
	{ 0,			NULL }
};

static const struct tok lsa_opaque_values[] = {
	{ LS_OPAQUE_TYPE_TE,    "Traffic Engineering" },
	{ LS_OPAQUE_TYPE_GRACE, "Graceful restart" },
	{ LS_OPAQUE_TYPE_RI,    "Router Information" },
	{ 0,			NULL }
};

static const struct tok lsa_opaque_te_tlv_values[] = {
	{ LS_OPAQUE_TE_TLV_ROUTER, "Router Address" },
	{ LS_OPAQUE_TE_TLV_LINK,   "Link" },
	{ 0,			NULL }
};

static const struct tok lsa_opaque_te_link_tlv_subtlv_values[] = {
	{ LS_OPAQUE_TE_LINK_SUBTLV_LINK_TYPE,            "Link Type" },
	{ LS_OPAQUE_TE_LINK_SUBTLV_LINK_ID,              "Link ID" },
	{ LS_OPAQUE_TE_LINK_SUBTLV_LOCAL_IP,             "Local Interface IP address" },
	{ LS_OPAQUE_TE_LINK_SUBTLV_REMOTE_IP,            "Remote Interface IP address" },
	{ LS_OPAQUE_TE_LINK_SUBTLV_TE_METRIC,            "Traffic Engineering Metric" },
	{ LS_OPAQUE_TE_LINK_SUBTLV_MAX_BW,               "Maximum Bandwidth" },
	{ LS_OPAQUE_TE_LINK_SUBTLV_MAX_RES_BW,           "Maximum Reservable Bandwidth" },
	{ LS_OPAQUE_TE_LINK_SUBTLV_UNRES_BW,             "Unreserved Bandwidth" },
	{ LS_OPAQUE_TE_LINK_SUBTLV_ADMIN_GROUP,          "Administrative Group" },
	{ LS_OPAQUE_TE_LINK_SUBTLV_LINK_LOCAL_REMOTE_ID, "Link Local/Remote Identifier" },
	{ LS_OPAQUE_TE_LINK_SUBTLV_LINK_PROTECTION_TYPE, "Link Protection Type" },
	{ LS_OPAQUE_TE_LINK_SUBTLV_INTF_SW_CAP_DESCR,    "Interface Switching Capability" },
	{ LS_OPAQUE_TE_LINK_SUBTLV_SHARED_RISK_GROUP,    "Shared Risk Link Group" },
	{ LS_OPAQUE_TE_LINK_SUBTLV_BW_CONSTRAINTS,       "Bandwidth Constraints" },
	{ 0,			NULL }
};

static const struct tok lsa_opaque_grace_tlv_values[] = {
	{ LS_OPAQUE_GRACE_TLV_PERIOD,             "Grace Period" },
	{ LS_OPAQUE_GRACE_TLV_REASON,             "Graceful restart Reason" },
	{ LS_OPAQUE_GRACE_TLV_INT_ADDRESS,        "IPv4 interface address" },
	{ 0,		        NULL }
};

static const struct tok lsa_opaque_grace_tlv_reason_values[] = {
	{ LS_OPAQUE_GRACE_TLV_REASON_UNKNOWN,     "Unknown" },
	{ LS_OPAQUE_GRACE_TLV_REASON_SW_RESTART,  "Software Restart" },
	{ LS_OPAQUE_GRACE_TLV_REASON_SW_UPGRADE,  "Software Reload/Upgrade" },
	{ LS_OPAQUE_GRACE_TLV_REASON_CP_SWITCH,   "Control Processor Switch" },
	{ 0,		        NULL }
};

static const struct tok lsa_opaque_te_tlv_link_type_sub_tlv_values[] = {
	{ LS_OPAQUE_TE_LINK_SUBTLV_LINK_TYPE_PTP, "Point-to-point" },
	{ LS_OPAQUE_TE_LINK_SUBTLV_LINK_TYPE_MA,  "Multi-Access" },
	{ 0,			NULL }
};

static const struct tok lsa_opaque_ri_tlv_values[] = {
	{ LS_OPAQUE_RI_TLV_CAP, "Router Capabilities" },
	{ 0,		        NULL }
};

static const struct tok lsa_opaque_ri_tlv_cap_values[] = {
	{ 1, "Reserved" },
	{ 2, "Reserved" },
	{ 4, "Reserved" },
	{ 8, "Reserved" },
	{ 16, "graceful restart capable" },
	{ 32, "graceful restart helper" },
	{ 64, "Stub router support" },
	{ 128, "Traffic engineering" },
	{ 256, "p2p over LAN" },
	{ 512, "path computation server" },
	{ 0,		        NULL }
};

static const struct tok ospf_lls_tlv_values[] = {
	{ OSPF_LLS_EO,	"Extended Options" },
	{ OSPF_LLS_MD5,	"MD5 Authentication" },
	{ 0,	NULL }
};

static const struct tok ospf_lls_eo_options[] = {
	{ OSPF_LLS_EO_LR,	"LSDB resync" },
	{ OSPF_LLS_EO_RS,	"Restart" },
	{ 0,	NULL }
};

int
ospf_grace_lsa_print(netdissect_options *ndo,
                     const u_char *tptr, u_int ls_length)
{
    u_int tlv_type, tlv_length;


    while (ls_length > 0) {
        ND_TCHECK_4(tptr);
        if (ls_length < 4) {
            ND_PRINT("\n\t    Remaining LS length %u < 4", ls_length);
            return -1;
        }
        tlv_type = EXTRACT_BE_U_2(tptr);
        tlv_length = EXTRACT_BE_U_2(tptr + 2);
        tptr+=4;
        ls_length-=4;

        ND_PRINT("\n\t    %s TLV (%u), length %u, value: ",
               tok2str(lsa_opaque_grace_tlv_values,"unknown",tlv_type),
               tlv_type,
               tlv_length);

        if (tlv_length > ls_length) {
            ND_PRINT("\n\t    Bogus length %u > %u", tlv_length,
                   ls_length);
            return -1;
        }

        /* Infinite loop protection. */
        if (tlv_type == 0 || tlv_length ==0) {
            return -1;
        }

        ND_TCHECK_LEN(tptr, tlv_length);
        switch(tlv_type) {

        case LS_OPAQUE_GRACE_TLV_PERIOD:
            if (tlv_length != 4) {
                ND_PRINT("\n\t    Bogus length %u != 4", tlv_length);
                return -1;
            }
            ND_PRINT("%us", EXTRACT_BE_U_4(tptr));
            break;

        case LS_OPAQUE_GRACE_TLV_REASON:
            if (tlv_length != 1) {
                ND_PRINT("\n\t    Bogus length %u != 1", tlv_length);
                return -1;
            }
            ND_PRINT("%s (%u)",
                   tok2str(lsa_opaque_grace_tlv_reason_values, "Unknown", EXTRACT_U_1(tptr)),
                   EXTRACT_U_1(tptr));
            break;

        case LS_OPAQUE_GRACE_TLV_INT_ADDRESS:
            if (tlv_length != 4) {
                ND_PRINT("\n\t    Bogus length %u != 4", tlv_length);
                return -1;
            }
            ND_PRINT("%s", ipaddr_string(ndo, tptr));
            break;

        default:
            if (ndo->ndo_vflag <= 1) {
                if (!print_unknown_data(ndo, tptr, "\n\t      ", tlv_length))
                    return -1;
            }
            break;

        }
        /* in OSPF everything has to be 32-bit aligned, including TLVs */
        if (tlv_length%4 != 0)
            tlv_length+=4-(tlv_length%4);
        ls_length-=tlv_length;
        tptr+=tlv_length;
    }

    return 0;
trunc:
    return -1;
}

int
ospf_te_lsa_print(netdissect_options *ndo,
                  const u_char *tptr, u_int ls_length)
{
    u_int tlv_type, tlv_length, subtlv_type, subtlv_length;
    u_int priority_level, te_class, count_srlg;
    union { /* int to float conversion buffer for several subTLVs */
        float f;
        uint32_t i;
    } bw;

    while (ls_length != 0) {
        ND_TCHECK_4(tptr);
        if (ls_length < 4) {
            ND_PRINT("\n\t    Remaining LS length %u < 4", ls_length);
            return -1;
        }
        tlv_type = EXTRACT_BE_U_2(tptr);
        tlv_length = EXTRACT_BE_U_2(tptr + 2);
        tptr+=4;
        ls_length-=4;

        ND_PRINT("\n\t    %s TLV (%u), length: %u",
               tok2str(lsa_opaque_te_tlv_values,"unknown",tlv_type),
               tlv_type,
               tlv_length);

        if (tlv_length > ls_length) {
            ND_PRINT("\n\t    Bogus length %u > %u", tlv_length,
                   ls_length);
            return -1;
        }

        /* Infinite loop protection. */
        if (tlv_type == 0 || tlv_length ==0) {
            return -1;
        }

        switch(tlv_type) {
        case LS_OPAQUE_TE_TLV_LINK:
            while (tlv_length >= sizeof(subtlv_type) + sizeof(subtlv_length)) {
                if (tlv_length < 4) {
                    ND_PRINT("\n\t    Remaining TLV length %u < 4",
                           tlv_length);
                    return -1;
                }
                ND_TCHECK_4(tptr);
                subtlv_type = EXTRACT_BE_U_2(tptr);
                subtlv_length = EXTRACT_BE_U_2(tptr + 2);
                tptr+=4;
                tlv_length-=4;

		/* Infinite loop protection */
		if (subtlv_type == 0 || subtlv_length == 0)
		    goto invalid;

                ND_PRINT("\n\t      %s subTLV (%u), length: %u",
                       tok2str(lsa_opaque_te_link_tlv_subtlv_values,"unknown",subtlv_type),
                       subtlv_type,
                       subtlv_length);

                ND_TCHECK_LEN(tptr, subtlv_length);
                switch(subtlv_type) {
                case LS_OPAQUE_TE_LINK_SUBTLV_ADMIN_GROUP:
		    if (subtlv_length != 4) {
			ND_PRINT(" != 4");
			goto invalid;
		    }
                    ND_PRINT(", 0x%08x", EXTRACT_BE_U_4(tptr));
                    break;
                case LS_OPAQUE_TE_LINK_SUBTLV_LINK_ID:
                case LS_OPAQUE_TE_LINK_SUBTLV_LINK_LOCAL_REMOTE_ID:
		    if (subtlv_length != 4 && subtlv_length != 8) {
			ND_PRINT(" != 4 && != 8");
			goto invalid;
		    }
                    ND_PRINT(", %s (0x%08x)",
                           ipaddr_string(ndo, tptr),
                           EXTRACT_BE_U_4(tptr));
                    if (subtlv_length == 8) /* rfc4203 */
                        ND_PRINT(", %s (0x%08x)",
                               ipaddr_string(ndo, tptr+4),
                               EXTRACT_BE_U_4(tptr + 4));
                    break;
                case LS_OPAQUE_TE_LINK_SUBTLV_LOCAL_IP:
                case LS_OPAQUE_TE_LINK_SUBTLV_REMOTE_IP:
		    if (subtlv_length != 4) {
			ND_PRINT(" != 4");
			goto invalid;
		    }
                    ND_PRINT(", %s", ipaddr_string(ndo, tptr));
                    break;
                case LS_OPAQUE_TE_LINK_SUBTLV_MAX_BW:
                case LS_OPAQUE_TE_LINK_SUBTLV_MAX_RES_BW:
		    if (subtlv_length != 4) {
			ND_PRINT(" != 4");
			goto invalid;
		    }
                    bw.i = EXTRACT_BE_U_4(tptr);
                    ND_PRINT(", %.3f Mbps", bw.f * 8 / 1000000);
                    break;
                case LS_OPAQUE_TE_LINK_SUBTLV_UNRES_BW:
		    if (subtlv_length != 32) {
			ND_PRINT(" != 32");
			goto invalid;
		    }
                    for (te_class = 0; te_class < 8; te_class++) {
                        bw.i = EXTRACT_BE_U_4(tptr + te_class * 4);
                        ND_PRINT("\n\t\tTE-Class %u: %.3f Mbps",
                               te_class,
                               bw.f * 8 / 1000000);
                    }
                    break;
                case LS_OPAQUE_TE_LINK_SUBTLV_BW_CONSTRAINTS:
		    if (subtlv_length < 4) {
			ND_PRINT(" < 4");
			goto invalid;
		    }
		    /* BC Model Id (1 octet) + Reserved (3 octets) */
                    ND_PRINT("\n\t\tBandwidth Constraints Model ID: %s (%u)",
                           tok2str(diffserv_te_bc_values, "unknown", EXTRACT_U_1(tptr)),
                           EXTRACT_U_1(tptr));
		    if (subtlv_length % 4 != 0) {
			ND_PRINT("\n\t\tlength %u != N x 4", subtlv_length);
			goto invalid;
		    }
		    if (subtlv_length > 36) {
			ND_PRINT("\n\t\tlength %u > 36", subtlv_length);
			goto invalid;
		    }
                    /* decode BCs until the subTLV ends */
                    for (te_class = 0; te_class < (subtlv_length-4)/4; te_class++) {
                        bw.i = EXTRACT_BE_U_4(tptr + 4 + te_class * 4);
                        ND_PRINT("\n\t\t  Bandwidth constraint CT%u: %.3f Mbps",
                               te_class,
                               bw.f * 8 / 1000000);
                    }
                    break;
                case LS_OPAQUE_TE_LINK_SUBTLV_TE_METRIC:
		    if (subtlv_length != 4) {
			ND_PRINT(" != 4");
			goto invalid;
		    }
                    ND_PRINT(", Metric %u", EXTRACT_BE_U_4(tptr));
                    break;
                case LS_OPAQUE_TE_LINK_SUBTLV_LINK_PROTECTION_TYPE:
		    /* Protection Cap (1 octet) + Reserved ((3 octets) */
		    if (subtlv_length != 4) {
			ND_PRINT(" != 4");
			goto invalid;
		    }
                    ND_PRINT(", %s",
                             bittok2str(gmpls_link_prot_values, "none", EXTRACT_U_1(tptr)));
                    break;
                case LS_OPAQUE_TE_LINK_SUBTLV_INTF_SW_CAP_DESCR:
		    if (subtlv_length < 36) {
			ND_PRINT(" < 36");
			goto invalid;
		    }
		    /* Switching Cap (1 octet) + Encoding (1) +  Reserved (2) */
                    ND_PRINT("\n\t\tInterface Switching Capability: %s",
                           tok2str(gmpls_switch_cap_values, "Unknown", EXTRACT_U_1((tptr))));
                    ND_PRINT("\n\t\tLSP Encoding: %s\n\t\tMax LSP Bandwidth:",
                           tok2str(gmpls_encoding_values, "Unknown", EXTRACT_U_1((tptr + 1))));
                    for (priority_level = 0; priority_level < 8; priority_level++) {
                        bw.i = EXTRACT_BE_U_4(tptr + 4 + (priority_level * 4));
                        ND_PRINT("\n\t\t  priority level %u: %.3f Mbps",
                               priority_level,
                               bw.f * 8 / 1000000);
                    }
                    break;
                case LS_OPAQUE_TE_LINK_SUBTLV_LINK_TYPE:
		    if (subtlv_length != 1) {
			ND_PRINT(" != 1");
			goto invalid;
		    }
                    ND_PRINT(", %s (%u)",
                           tok2str(lsa_opaque_te_tlv_link_type_sub_tlv_values,"unknown",EXTRACT_U_1(tptr)),
                           EXTRACT_U_1(tptr));
                    break;

                case LS_OPAQUE_TE_LINK_SUBTLV_SHARED_RISK_GROUP:
		    if (subtlv_length % 4 != 0) {
			ND_PRINT(" != N x 4");
			goto invalid;
		    }
                    count_srlg = subtlv_length / 4;
                    if (count_srlg != 0)
                        ND_PRINT("\n\t\t  Shared risk group: ");
                    while (count_srlg > 0) {
                        bw.i = EXTRACT_BE_U_4(tptr);
                        ND_PRINT("%u", bw.i);
                        tptr+=4;
                        count_srlg--;
                        if (count_srlg > 0)
                            ND_PRINT(", ");
                    }
                    break;

                default:
                    if (ndo->ndo_vflag <= 1) {
                        if (!print_unknown_data(ndo, tptr, "\n\t\t", subtlv_length))
                            return -1;
                    }
                    break;
                }
                /* in OSPF everything has to be 32-bit aligned, including subTLVs */
                if (subtlv_length%4 != 0)
                    subtlv_length+=4-(subtlv_length%4);

                tlv_length-=subtlv_length;
                tptr+=subtlv_length;

            }
            break;

        case LS_OPAQUE_TE_TLV_ROUTER:
            if (tlv_length < 4) {
                ND_PRINT("\n\t    TLV length %u < 4", tlv_length);
                return -1;
            }
            ND_TCHECK_4(tptr);
            ND_PRINT(", %s", ipaddr_string(ndo, tptr));
            break;

        default:
            if (ndo->ndo_vflag <= 1) {
                if (!print_unknown_data(ndo, tptr, "\n\t      ", tlv_length))
                    return -1;
            }
            break;
        }
        /* in OSPF everything has to be 32-bit aligned, including TLVs */
        if (tlv_length%4 != 0)
            tlv_length+=4-(tlv_length%4);
        ls_length-=tlv_length;
        tptr+=tlv_length;
    }
    return 0;
trunc:
    return -1;
invalid:
    ND_PRINT("%s", istr);
    return -1;
}

static int
ospf_print_lshdr(netdissect_options *ndo,
                 const struct lsa_hdr *lshp)
{
        u_int ls_type;
        u_int ls_length;

        ND_TCHECK_2(lshp->ls_length);
        ls_length = EXTRACT_BE_U_2(lshp->ls_length);
        if (ls_length < sizeof(struct lsa_hdr)) {
                ND_PRINT("\n\t    Bogus length %u < header (%lu)", ls_length,
                    (unsigned long)sizeof(struct lsa_hdr));
                return(-1);
        }

        ND_TCHECK_4(lshp->ls_seq); /* XXX - ls_length check checked this */
        ND_PRINT("\n\t  Advertising Router %s, seq 0x%08x, age %us, length %u",
                  ipaddr_string(ndo, lshp->ls_router),
                  EXTRACT_BE_U_4(lshp->ls_seq),
                  EXTRACT_BE_U_2(lshp->ls_age),
                  ls_length - (u_int)sizeof(struct lsa_hdr));

        ND_TCHECK_1(lshp->ls_type); /* XXX - ls_length check checked this */
        ls_type = EXTRACT_U_1(lshp->ls_type);
        switch (ls_type) {
        /* the LSA header for opaque LSAs was slightly changed */
        case LS_TYPE_OPAQUE_LL:
        case LS_TYPE_OPAQUE_AL:
        case LS_TYPE_OPAQUE_DW:
            ND_PRINT("\n\t    %s LSA (%u), Opaque-Type %s LSA (%u), Opaque-ID %u",
                   tok2str(lsa_values,"unknown",ls_type),
                   ls_type,

		   tok2str(lsa_opaque_values,
			   "unknown",
			   EXTRACT_U_1(lshp->un_lsa_id.opaque_field.opaque_type)),
		   EXTRACT_U_1(lshp->un_lsa_id.opaque_field.opaque_type),
		   EXTRACT_BE_U_3(lshp->un_lsa_id.opaque_field.opaque_id)

                   );
            break;

        /* all other LSA types use regular style LSA headers */
        default:
            ND_PRINT("\n\t    %s LSA (%u), LSA-ID: %s",
                   tok2str(lsa_values,"unknown",ls_type),
                   ls_type,
                   ipaddr_string(ndo, lshp->un_lsa_id.lsa_id));
            break;
        }

        ND_TCHECK_1(lshp->ls_options); /* XXX - ls_length check checked this */
        ND_PRINT("\n\t    Options: [%s]", bittok2str(ospf_option_values, "none", EXTRACT_U_1(lshp->ls_options)));

        return (ls_length);
trunc:
	return (-1);
}

/* draft-ietf-ospf-mt-09 */
static const struct tok ospf_topology_values[] = {
    { 0, "default" },
    { 1, "multicast" },
    { 2, "management" },
    { 0, NULL }
};

/*
 * Print all the per-topology metrics.
 */
static int
ospf_print_tos_metrics(netdissect_options *ndo,
                       const union un_tos *tos)
{
    u_int metric_count;
    u_int toscount;
    u_int tos_type;

    toscount = EXTRACT_U_1(tos->link.link_tos_count)+1;
    metric_count = 0;

    /*
     * All but the first metric contain a valid topology id.
     */
    while (toscount != 0) {
        ND_TCHECK_SIZE(tos);
        tos_type = EXTRACT_U_1(tos->metrics.tos_type);
        ND_PRINT("\n\t\ttopology %s (%u), metric %u",
               tok2str(ospf_topology_values, "Unknown",
                       metric_count ? tos_type : 0),
               metric_count ? tos_type : 0,
               EXTRACT_BE_U_2(tos->metrics.tos_metric));
        metric_count++;
        tos++;
        toscount--;
    }
    return 0;
trunc:
    return 1;
}

/*
 * Print a single link state advertisement.  If truncated or if LSA length
 * field is less than the length of the LSA header, return NULl, else
 * return pointer to data past end of LSA.
 */
static const uint8_t *
ospf_print_lsa(netdissect_options *ndo,
               const struct lsa *lsap)
{
	const uint8_t *ls_end;
	const struct rlalink *rlp;
	const nd_ipv4 *ap;
	const struct aslametric *almp;
	const struct mcla *mcp;
	const uint8_t *lp;
	int j, tlv_type, tlv_length, topology;
	int ls_length;
	const uint8_t *tptr;

	tptr = (const uint8_t *)lsap->lsa_un.un_unknown; /* squelch compiler warnings */
        ls_length = ospf_print_lshdr(ndo, &lsap->ls_hdr);
        if (ls_length == -1)
                return(NULL);
	ls_end = (const uint8_t *)lsap + ls_length;
	ls_length -= sizeof(struct lsa_hdr);

	switch (EXTRACT_U_1(lsap->ls_hdr.ls_type)) {

	case LS_TYPE_ROUTER:
		ND_TCHECK_1(lsap->lsa_un.un_rla.rla_flags);
		ND_PRINT("\n\t    Router LSA Options: [%s]",
		          bittok2str(ospf_rla_flag_values, "none", EXTRACT_U_1(lsap->lsa_un.un_rla.rla_flags)));

		ND_TCHECK_2(lsap->lsa_un.un_rla.rla_count);
		j = EXTRACT_BE_U_2(lsap->lsa_un.un_rla.rla_count);
		ND_TCHECK_SIZE(lsap->lsa_un.un_rla.rla_link);
		rlp = lsap->lsa_un.un_rla.rla_link;
		while (j--) {
			ND_TCHECK_SIZE(rlp);
			switch (EXTRACT_U_1(rlp->un_tos.link.link_type)) {

			case RLA_TYPE_VIRTUAL:
				ND_PRINT("\n\t      Virtual Link: Neighbor Router-ID: %s, Interface Address: %s",
				    ipaddr_string(ndo, rlp->link_id),
				    ipaddr_string(ndo, rlp->link_data));
				break;

			case RLA_TYPE_ROUTER:
				ND_PRINT("\n\t      Neighbor Router-ID: %s, Interface Address: %s",
				    ipaddr_string(ndo, rlp->link_id),
				    ipaddr_string(ndo, rlp->link_data));
				break;

			case RLA_TYPE_TRANSIT:
				ND_PRINT("\n\t      Neighbor Network-ID: %s, Interface Address: %s",
				    ipaddr_string(ndo, rlp->link_id),
				    ipaddr_string(ndo, rlp->link_data));
				break;

			case RLA_TYPE_STUB:
				ND_PRINT("\n\t      Stub Network: %s, Mask: %s",
				    ipaddr_string(ndo, rlp->link_id),
				    ipaddr_string(ndo, rlp->link_data));
				break;

			default:
				ND_PRINT("\n\t      Unknown Router Link Type (%u)",
				    EXTRACT_U_1(rlp->un_tos.link.link_type));
				return (ls_end);
			}

			if (ospf_print_tos_metrics(ndo, &rlp->un_tos))
				goto trunc;

			rlp = (const struct rlalink *)((const u_char *)(rlp + 1) +
			    (EXTRACT_U_1(rlp->un_tos.link.link_tos_count) * sizeof(union un_tos)));
		}
		break;

	case LS_TYPE_NETWORK:
		ND_TCHECK_4(lsap->lsa_un.un_nla.nla_mask);
		ND_PRINT("\n\t    Mask %s\n\t    Connected Routers:",
		    ipaddr_string(ndo, lsap->lsa_un.un_nla.nla_mask));
		ap = lsap->lsa_un.un_nla.nla_router;
		while ((const u_char *)ap < ls_end) {
			ND_TCHECK_SIZE(ap);
			ND_PRINT("\n\t      %s", ipaddr_string(ndo, *ap));
			++ap;
		}
		break;

	case LS_TYPE_SUM_IP:
		ND_TCHECK_4(lsap->lsa_un.un_nla.nla_mask);
		ND_PRINT("\n\t    Mask %s",
		    ipaddr_string(ndo, lsap->lsa_un.un_sla.sla_mask));
		ND_TCHECK_SIZE(lsap->lsa_un.un_sla.sla_tosmetric);
		lp = (const uint8_t *)lsap->lsa_un.un_sla.sla_tosmetric;
		while (lp < ls_end) {
			uint32_t ul;

			ND_TCHECK_4(lp);
			ul = EXTRACT_BE_U_4(lp);
                        topology = (ul & SLA_MASK_TOS) >> SLA_SHIFT_TOS;
			ND_PRINT("\n\t\ttopology %s (%u) metric %u",
                               tok2str(ospf_topology_values, "Unknown", topology),
                               topology,
                               ul & SLA_MASK_METRIC);
			lp += 4;
		}
		break;

	case LS_TYPE_SUM_ABR:
		ND_TCHECK_SIZE(lsap->lsa_un.un_sla.sla_tosmetric);
		lp = (const uint8_t *)lsap->lsa_un.un_sla.sla_tosmetric;
		while (lp < ls_end) {
			uint32_t ul;

			ND_TCHECK_4(lp);
			ul = EXTRACT_BE_U_4(lp);
                        topology = (ul & SLA_MASK_TOS) >> SLA_SHIFT_TOS;
			ND_PRINT("\n\t\ttopology %s (%u) metric %u",
                               tok2str(ospf_topology_values, "Unknown", topology),
                               topology,
                               ul & SLA_MASK_METRIC);
			lp += 4;
		}
		break;

	case LS_TYPE_ASE:
        case LS_TYPE_NSSA: /* fall through - those LSAs share the same format */
		ND_TCHECK_4(lsap->lsa_un.un_nla.nla_mask);
		ND_PRINT("\n\t    Mask %s",
		    ipaddr_string(ndo, lsap->lsa_un.un_asla.asla_mask));

		ND_TCHECK_SIZE(lsap->lsa_un.un_sla.sla_tosmetric);
		almp = lsap->lsa_un.un_asla.asla_metric;
		while ((const u_char *)almp < ls_end) {
			uint32_t ul;

			ND_TCHECK_4(almp->asla_tosmetric);
			ul = EXTRACT_BE_U_4(almp->asla_tosmetric);
                        topology = ((ul & ASLA_MASK_TOS) >> ASLA_SHIFT_TOS);
			ND_PRINT("\n\t\ttopology %s (%u), type %u, metric",
                               tok2str(ospf_topology_values, "Unknown", topology),
                               topology,
                               (ul & ASLA_FLAG_EXTERNAL) ? 2 : 1);
			if ((ul & ASLA_MASK_METRIC) == 0xffffff)
				ND_PRINT(" infinite");
			else
				ND_PRINT(" %u", (ul & ASLA_MASK_METRIC));

			ND_TCHECK_4(almp->asla_forward);
			if (EXTRACT_IPV4_TO_NETWORK_ORDER(almp->asla_forward) != 0) {
				ND_PRINT(", forward %s", ipaddr_string(ndo, almp->asla_forward));
			}
			ND_TCHECK_4(almp->asla_tag);
			if (EXTRACT_IPV4_TO_NETWORK_ORDER(almp->asla_tag) != 0) {
				ND_PRINT(", tag %s", ipaddr_string(ndo, almp->asla_tag));
			}
			++almp;
		}
		break;

	case LS_TYPE_GROUP:
		/* Multicast extensions as of 23 July 1991 */
		mcp = lsap->lsa_un.un_mcla;
		while ((const u_char *)mcp < ls_end) {
			ND_TCHECK_4(mcp->mcla_vid);
			switch (EXTRACT_BE_U_4(mcp->mcla_vtype)) {

			case MCLA_VERTEX_ROUTER:
				ND_PRINT("\n\t    Router Router-ID %s",
				    ipaddr_string(ndo, mcp->mcla_vid));
				break;

			case MCLA_VERTEX_NETWORK:
				ND_PRINT("\n\t    Network Designated Router %s",
				    ipaddr_string(ndo, mcp->mcla_vid));
				break;

			default:
				ND_PRINT("\n\t    unknown VertexType (%u)",
				    EXTRACT_BE_U_4(mcp->mcla_vtype));
				break;
			}
		++mcp;
		}
		break;

	case LS_TYPE_OPAQUE_LL: /* fall through */
	case LS_TYPE_OPAQUE_AL:
	case LS_TYPE_OPAQUE_DW:

	    switch (EXTRACT_U_1(lsap->ls_hdr.un_lsa_id.opaque_field.opaque_type)) {
            case LS_OPAQUE_TYPE_RI:
		tptr = (const uint8_t *)(lsap->lsa_un.un_ri_tlv);

		while (ls_length != 0) {
                    ND_TCHECK_4(tptr);
		    if (ls_length < 4) {
                        ND_PRINT("\n\t    Remaining LS length %u < 4", ls_length);
                        return(ls_end);
                    }
                    tlv_type = EXTRACT_BE_U_2(tptr);
                    tlv_length = EXTRACT_BE_U_2(tptr + 2);
                    tptr+=4;
                    ls_length-=4;

                    ND_PRINT("\n\t    %s TLV (%u), length: %u, value: ",
                           tok2str(lsa_opaque_ri_tlv_values,"unknown",tlv_type),
                           tlv_type,
                           tlv_length);

                    if (tlv_length > ls_length) {
                        ND_PRINT("\n\t    Bogus length %u > %u", tlv_length,
                            ls_length);
                        return(ls_end);
                    }
                    ND_TCHECK_LEN(tptr, tlv_length);
                    switch(tlv_type) {

                    case LS_OPAQUE_RI_TLV_CAP:
                        if (tlv_length != 4) {
                            ND_PRINT("\n\t    Bogus length %u != 4", tlv_length);
                            return(ls_end);
                        }
                        ND_PRINT("Capabilities: %s",
                               bittok2str(lsa_opaque_ri_tlv_cap_values, "Unknown", EXTRACT_BE_U_4(tptr)));
                        break;
                    default:
                        if (ndo->ndo_vflag <= 1) {
                            if (!print_unknown_data(ndo, tptr, "\n\t      ", tlv_length))
                                return(ls_end);
                        }
                        break;

                    }
                    tptr+=tlv_length;
                    ls_length-=tlv_length;
                }
                break;

            case LS_OPAQUE_TYPE_GRACE:
                if (ospf_grace_lsa_print(ndo, (const u_char *)(lsap->lsa_un.un_grace_tlv),
                                         ls_length) == -1) {
                    return(ls_end);
                }
                break;

	    case LS_OPAQUE_TYPE_TE:
                if (ospf_te_lsa_print(ndo, (const u_char *)(lsap->lsa_un.un_te_lsa_tlv),
                                      ls_length) == -1) {
                    return(ls_end);
                }
                break;

            default:
                if (ndo->ndo_vflag <= 1) {
                    if (!print_unknown_data(ndo, (const uint8_t *)lsap->lsa_un.un_unknown,
                                           "\n\t    ", ls_length))
                        return(ls_end);
                }
                break;
            }
        }

        /* do we want to see an additionally hexdump ? */
        if (ndo->ndo_vflag> 1)
            if (!print_unknown_data(ndo, (const uint8_t *)lsap->lsa_un.un_unknown,
                                   "\n\t    ", ls_length)) {
                return(ls_end);
            }

	return (ls_end);
trunc:
	return (NULL);
}

static int
ospf_decode_lls(netdissect_options *ndo,
                const struct ospfhdr *op, u_int length)
{
    const u_char *dptr;
    const u_char *dataend;
    u_int length2;
    uint16_t lls_type, lls_len;
    uint32_t lls_flags;

    switch (EXTRACT_U_1(op->ospf_type)) {

    case OSPF_TYPE_HELLO:
        if (!(EXTRACT_U_1(op->ospf_hello.hello_options) & OSPF_OPTION_L))
            return (0);
        break;

    case OSPF_TYPE_DD:
        if (!(EXTRACT_U_1(op->ospf_db.db_options) & OSPF_OPTION_L))
            return (0);
        break;

    default:
        return (0);
    }

    /* dig deeper if LLS data is available; see RFC4813 */
    length2 = EXTRACT_BE_U_2(op->ospf_len);
    dptr = (const u_char *)op + length2;
    dataend = (const u_char *)op + length;

    if (EXTRACT_BE_U_2(op->ospf_authtype) == OSPF_AUTH_MD5) {
        dptr = dptr + op->ospf_authdata[3];
        length2 += op->ospf_authdata[3];
    }
    if (length2 >= length) {
        ND_PRINT("\n\t[LLS truncated]");
        return (1);
    }
    ND_TCHECK_2(dptr);
    ND_PRINT("\n\t  LLS: checksum: 0x%04x", (u_int) EXTRACT_BE_U_2(dptr));

    dptr += 2;
    ND_TCHECK_2(dptr);
    length2 = EXTRACT_BE_U_2(dptr);
    ND_PRINT(", length: %u", length2);

    dptr += 2;
    ND_TCHECK_1(dptr);
    while (dptr < dataend) {
        ND_TCHECK_2(dptr);
        lls_type = EXTRACT_BE_U_2(dptr);
        ND_PRINT("\n\t    %s (%u)",
               tok2str(ospf_lls_tlv_values,"Unknown TLV",lls_type),
               lls_type);
        dptr += 2;
        ND_TCHECK_2(dptr);
        lls_len = EXTRACT_BE_U_2(dptr);
        ND_PRINT(", length: %u", lls_len);
        dptr += 2;
        switch (lls_type) {

        case OSPF_LLS_EO:
            if (lls_len != 4) {
                ND_PRINT(" [should be 4]");
                lls_len = 4;
            }
            ND_TCHECK_4(dptr);
            lls_flags = EXTRACT_BE_U_4(dptr);
            ND_PRINT("\n\t      Options: 0x%08x [%s]", lls_flags,
                   bittok2str(ospf_lls_eo_options, "?", lls_flags));

            break;

        case OSPF_LLS_MD5:
            if (lls_len != 20) {
                ND_PRINT(" [should be 20]");
                lls_len = 20;
            }
            ND_TCHECK_4(dptr);
            ND_PRINT("\n\t      Sequence number: 0x%08x", EXTRACT_BE_U_4(dptr));
            break;
        }

        dptr += lls_len;
    }

    return (0);
trunc:
    return (1);
}

static int
ospf_decode_v2(netdissect_options *ndo,
               const struct ospfhdr *op, const u_char *dataend)
{
	const nd_ipv4 *ap;
	const struct lsr *lsrp;
	const struct lsa_hdr *lshp;
	const struct lsa *lsap;
	uint32_t lsa_count,lsa_count_max;

	switch (EXTRACT_U_1(op->ospf_type)) {

	case OSPF_TYPE_HELLO:
		ND_TCHECK_1(op->ospf_hello.hello_options);
		ND_PRINT("\n\tOptions [%s]",
		          bittok2str(ospf_option_values,"none",EXTRACT_U_1(op->ospf_hello.hello_options)));

		ND_TCHECK_4(op->ospf_hello.hello_deadint);
		ND_PRINT("\n\t  Hello Timer %us, Dead Timer %us, Mask %s, Priority %u",
		          EXTRACT_BE_U_2(op->ospf_hello.hello_helloint),
		          EXTRACT_BE_U_4(op->ospf_hello.hello_deadint),
		          ipaddr_string(ndo, op->ospf_hello.hello_mask),
		          EXTRACT_U_1(op->ospf_hello.hello_priority));

		ND_TCHECK_4(op->ospf_hello.hello_dr);
		if (EXTRACT_IPV4_TO_NETWORK_ORDER(op->ospf_hello.hello_dr) != 0)
			ND_PRINT("\n\t  Designated Router %s",
			    ipaddr_string(ndo, op->ospf_hello.hello_dr));

		ND_TCHECK_4(op->ospf_hello.hello_bdr);
		if (EXTRACT_IPV4_TO_NETWORK_ORDER(op->ospf_hello.hello_bdr) != 0)
			ND_PRINT(", Backup Designated Router %s",
			          ipaddr_string(ndo, op->ospf_hello.hello_bdr));

		ap = op->ospf_hello.hello_neighbor;
		if ((const u_char *)ap < dataend)
			ND_PRINT("\n\t  Neighbor List:");
		while ((const u_char *)ap < dataend) {
			ND_TCHECK_SIZE(ap);
			ND_PRINT("\n\t    %s", ipaddr_string(ndo, *ap));
			++ap;
		}
		break;	/* HELLO */

	case OSPF_TYPE_DD:
		ND_TCHECK_1(op->ospf_db.db_options);
		ND_PRINT("\n\tOptions [%s]",
		          bittok2str(ospf_option_values, "none", EXTRACT_U_1(op->ospf_db.db_options)));
		ND_TCHECK_1(op->ospf_db.db_flags);
		ND_PRINT(", DD Flags [%s]",
		          bittok2str(ospf_dd_flag_values, "none", EXTRACT_U_1(op->ospf_db.db_flags)));
		ND_TCHECK_2(op->ospf_db.db_ifmtu);
		if (EXTRACT_BE_U_2(op->ospf_db.db_ifmtu)) {
			ND_PRINT(", MTU: %u", EXTRACT_BE_U_2(op->ospf_db.db_ifmtu));
		}
		ND_TCHECK_4(op->ospf_db.db_seq);
		ND_PRINT(", Sequence: 0x%08x", EXTRACT_BE_U_4(op->ospf_db.db_seq));

		/* Print all the LS adv's */
		lshp = op->ospf_db.db_lshdr;
		while (((const u_char *)lshp < dataend) && ospf_print_lshdr(ndo, lshp) != -1) {
			++lshp;
		}
		break;

	case OSPF_TYPE_LS_REQ:
                lsrp = op->ospf_lsr;
                while ((const u_char *)lsrp < dataend) {
                    ND_TCHECK_SIZE(lsrp);

                    ND_PRINT("\n\t  Advertising Router: %s, %s LSA (%u)",
                           ipaddr_string(ndo, lsrp->ls_router),
                           tok2str(lsa_values,"unknown",EXTRACT_BE_U_4(lsrp->ls_type)),
                           EXTRACT_BE_U_4(lsrp->ls_type));

                    switch (EXTRACT_BE_U_4(lsrp->ls_type)) {
                        /* the LSA header for opaque LSAs was slightly changed */
                    case LS_TYPE_OPAQUE_LL:
                    case LS_TYPE_OPAQUE_AL:
                    case LS_TYPE_OPAQUE_DW:
                        ND_PRINT(", Opaque-Type: %s LSA (%u), Opaque-ID: %u",
                               tok2str(lsa_opaque_values, "unknown",EXTRACT_U_1(lsrp->un_ls_stateid.opaque_field.opaque_type)),
                               EXTRACT_U_1(lsrp->un_ls_stateid.opaque_field.opaque_type),
                               EXTRACT_BE_U_3(lsrp->un_ls_stateid.opaque_field.opaque_id));
                        break;
                    default:
                        ND_PRINT(", LSA-ID: %s",
                               ipaddr_string(ndo, lsrp->un_ls_stateid.ls_stateid));
                        break;
                    }

                    ++lsrp;
                }
		break;

	case OSPF_TYPE_LS_UPDATE:
                lsap = op->ospf_lsu.lsu_lsa;
                ND_TCHECK_4(op->ospf_lsu.lsu_count);
                lsa_count_max = EXTRACT_BE_U_4(op->ospf_lsu.lsu_count);
                ND_PRINT(", %u LSA%s", lsa_count_max, PLURAL_SUFFIX(lsa_count_max));
                for (lsa_count=1;lsa_count <= lsa_count_max;lsa_count++) {
                    ND_PRINT("\n\t  LSA #%u", lsa_count);
                        lsap = (const struct lsa *)ospf_print_lsa(ndo, lsap);
                        if (lsap == NULL)
                                goto trunc;
                }
		break;

	case OSPF_TYPE_LS_ACK:
                lshp = op->ospf_lsa.lsa_lshdr;
                while (ospf_print_lshdr(ndo, lshp) != -1) {
                    ++lshp;
                }
                break;

	default:
		break;
	}
	return (0);
trunc:
	return (1);
}

void
ospf_print(netdissect_options *ndo,
           const u_char *bp, u_int length,
           const u_char *bp2 _U_)
{
	const struct ospfhdr *op;
	const u_char *dataend;
	const char *cp;

	ndo->ndo_protocol = "ospf2";
	op = (const struct ospfhdr *)bp;

	/* XXX Before we do anything else, strip off the MD5 trailer */
	ND_TCHECK_2(op->ospf_authtype);
	if (EXTRACT_BE_U_2(op->ospf_authtype) == OSPF_AUTH_MD5) {
		length -= OSPF_AUTH_MD5_LEN;
		ndo->ndo_snapend -= OSPF_AUTH_MD5_LEN;
	}

	/* If the type is valid translate it, or just print the type */
	/* value.  If it's not valid, say so and return */
	ND_TCHECK_1(op->ospf_type);
	cp = tok2str(type2str, "unknown LS-type %u", EXTRACT_U_1(op->ospf_type));
	ND_PRINT("OSPFv%u, %s, length %u", EXTRACT_U_1(op->ospf_version), cp, length);
	if (*cp == 'u')
		return;

	if (!ndo->ndo_vflag) { /* non verbose - so lets bail out here */
		return;
	}

	ND_TCHECK_2(op->ospf_len);
	if (length != EXTRACT_BE_U_2(op->ospf_len)) {
		ND_PRINT(" [len %u]", EXTRACT_BE_U_2(op->ospf_len));
	}

	if (length > EXTRACT_BE_U_2(op->ospf_len)) {
		dataend = bp + EXTRACT_BE_U_2(op->ospf_len);
	} else {
		dataend = bp + length;
	}

	ND_TCHECK_4(op->ospf_routerid);
	ND_PRINT("\n\tRouter-ID %s", ipaddr_string(ndo, op->ospf_routerid));

	ND_TCHECK_4(op->ospf_areaid);
	if (EXTRACT_IPV4_TO_NETWORK_ORDER(op->ospf_areaid) != 0)
		ND_PRINT(", Area %s", ipaddr_string(ndo, op->ospf_areaid));
	else
		ND_PRINT(", Backbone Area");

	if (ndo->ndo_vflag) {
		/* Print authentication data (should we really do this?) */
		ND_TCHECK_LEN(op->ospf_authdata, sizeof(op->ospf_authdata));

		ND_PRINT(", Authentication Type: %s (%u)",
		          tok2str(ospf_authtype_values, "unknown", EXTRACT_BE_U_2(op->ospf_authtype)),
		          EXTRACT_BE_U_2(op->ospf_authtype));

		switch (EXTRACT_BE_U_2(op->ospf_authtype)) {

		case OSPF_AUTH_NONE:
			break;

		case OSPF_AUTH_SIMPLE:
			ND_PRINT("\n\tSimple text password: ");
			(void)nd_printzp(ndo, op->ospf_authdata, OSPF_AUTH_SIMPLE_LEN, NULL);
			break;

		case OSPF_AUTH_MD5:
			ND_PRINT("\n\tKey-ID: %u, Auth-Length: %u, Crypto Sequence Number: 0x%08x",
			          *((op->ospf_authdata) + 2),
			          *((op->ospf_authdata) + 3),
			          EXTRACT_BE_U_4((op->ospf_authdata) + 4));
			break;

		default:
			return;
		}
	}
	/* Do rest according to version.	 */
	switch (EXTRACT_U_1(op->ospf_version)) {

	case 2:
		/* ospf version 2 */
		if (ospf_decode_v2(ndo, op, dataend))
			goto trunc;
		if (length > EXTRACT_BE_U_2(op->ospf_len)) {
			if (ospf_decode_lls(ndo, op, length))
				goto trunc;
		}
		break;

	default:
		ND_PRINT(" ospf [version %u]", EXTRACT_U_1(op->ospf_version));
		break;
	}			/* end switch on version */

	return;
trunc:
	nd_print_trunc(ndo);
}
