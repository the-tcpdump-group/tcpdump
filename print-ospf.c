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

#include <config.h>

#include "netdissect-stdinc.h"

#include "netdissect.h"
#include "addrtoname.h"
#include "extract.h"
#include "gmpls.h"

#include "ospf.h"

static const struct tok ospf_option_values[] = {
	{ OSPF_OPTION_MT,	"MultiTopology" }, /* draft-ietf-ospf-mt-09 */
	{ OSPF_OPTION_E,	"External" },
	{ OSPF_OPTION_MC,	"Multicast" },
	{ OSPF_OPTION_NP,	"NSSA" },
	{ OSPF_OPTION_L,	"LLS" },
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
	{ RLA_FLAG_V,		"Virtual" },
	{ RLA_FLAG_W,		"Wildcard" },
	{ RLA_FLAG_NT,		"Nt" },
	{ RLA_FLAG_H,		"Host" },
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
	{ LS_OPAQUE_TYPE_EP,    "Extended Prefix" },
	{ LS_OPAQUE_TYPE_EL,    "Extended Link" },
	{ 0,			NULL }
};

static const struct tok lsa_opaque_ri_sid_subtlv_values[] = {
	{ LS_OPAQUE_RI_SUBTLV_SID_LABEL, "SID/Label" },
	{ 0,		        NULL }
};

static const struct tok lsa_opaque_te_tlv_values[] = {
	{ LS_OPAQUE_TE_TLV_ROUTER, "Router Address" },
	{ LS_OPAQUE_TE_TLV_LINK,   "Link" },
	{ 0,			NULL }
};

static const struct tok lsa_opaque_ep_extd_prefix_subtlv_values[] = {
	{ LS_OPAQUE_EP_SUBTLV_PREFIX_SID, "Prefix-SID" },
	{ 0,		        NULL }
};

static const struct tok ep_range_tlv_prefix_sid_subtlv_flag_values[] = {
	{ 0x40, "No-PHP"},
	{ 0x20, "Mapping-Server"},
	{ 0x10, "Explicit-NULL"},
	{ 0x08, "Value"},
	{ 0x04, "Local"},
	{ 0,			NULL}
};

static const struct tok lsa_opaque_ep_route_type_values[] = {
	{ 0, "Unspecified" },
	{ 1, "Intra-Area" },
	{ 3, "Inter-Area" },
	{ 5, "AS External" },
	{ 7, "NSSA External" },
	{ 0,			NULL }
};

static const struct tok lsa_opaque_ep_tlv_values[] = {
	{ LS_OPAQUE_EP_EXTD_PREFIX_TLV,       "Extended Prefix" },
	{ LS_OPAQUE_EP_EXTD_PREFIX_RANGE_TLV, "Extended Prefix Range" },
	{ 0,			NULL }
};

static const struct tok ep_tlv_flag_values[] = {
	{ 0x80, "Inter-Area"},
	{ 0,			NULL}
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
	{ LS_OPAQUE_RI_TLV_SR_ALGO, "SR-Algorithm" },
	{ LS_OPAQUE_RI_TLV_HOSTNAME, "Hostname" },
	{ LS_OPAQUE_RI_TLV_SID_LABEL_RANGE, "SID/Label Range" },
	{ LS_OPAQUE_RI_TLV_SR_LOCAL_BLOCK, "SR Local Block" },
	{ LS_OPAQUE_RI_TLV_SRMS_PREFERENCE, "SRMS Preference" },
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

static const struct tok lsa_opaque_ri_tlv_sr_algos[] = {
	{ 0, "Shortest Path First" },
	{ 1, "Strict Shortest Path First" },
	{ 0,                    NULL }
};

static const struct tok lsa_opaque_el_tlv_values[] = {
        { LS_OPAQUE_EXTENDED_LINK_TLV, "Extended Link" },
        { 0,                    NULL }
};

static const struct tok lsa_opaque_extended_link_link_type_values[] = {
        { RLA_TYPE_ROUTER,  "Point-to-Point Link" },
        { RLA_TYPE_TRANSIT, "Link to Transit Network" },
        { RLA_TYPE_STUB,    "Link to Stub Network" },
        { RLA_TYPE_VIRTUAL, "Virtual Link" },
        { 0,                    NULL }
};

static const struct tok lsa_opaque_extended_link_subtlv_adj_sid_flag_values[] = {
        { LS_OPAQUE_EXTENDED_LINK_SUBTLV_ADJ_SID_FLAG_B, "Backup" },
        { LS_OPAQUE_EXTENDED_LINK_SUBTLV_ADJ_SID_FLAG_V, "Value/Index" },
        { LS_OPAQUE_EXTENDED_LINK_SUBTLV_ADJ_SID_FLAG_L, "Local/Global" },
        { LS_OPAQUE_EXTENDED_LINK_SUBTLV_ADJ_SID_FLAG_G, "Group" },
        { LS_OPAQUE_EXTENDED_LINK_SUBTLV_ADJ_SID_FLAG_P, "Persistent" },
        { 0,                    NULL }
};

static const struct tok lsa_opaque_extended_link_subtlv_values[] = {
        { LS_OPAQUE_EXTENDED_LINK_SUBTLV_ADJ_SID, "Adj-SID Sub-TLV" },
        { 0,                    NULL }
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

    while (ls_length != 0) {
        ND_TCHECK_4(tptr);
        if (ls_length < 4) {
            ND_PRINT("\n\t    Remaining LS length %u < 4", ls_length);
            return -1;
        }
        tlv_type = GET_BE_U_2(tptr);
        tlv_length = GET_BE_U_2(tptr + 2);
        tptr += 4;
        ls_length -= 4;

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
        if (tlv_type == 0 || tlv_length == 0) {
	    nd_print_invalid(ndo);
            return -1;
        }

        ND_TCHECK_LEN(tptr, tlv_length);
        switch(tlv_type) {

        case LS_OPAQUE_GRACE_TLV_PERIOD:
            if (tlv_length != 4) {
                ND_PRINT("\n\t    Bogus length %u != 4", tlv_length);
                return -1;
            }
            ND_PRINT("%us", GET_BE_U_4(tptr));
            break;

        case LS_OPAQUE_GRACE_TLV_REASON:
            if (tlv_length != 1) {
                ND_PRINT("\n\t    Bogus length %u != 1", tlv_length);
                return -1;
            }
            ND_PRINT("%s (%u)",
                   tok2str(lsa_opaque_grace_tlv_reason_values, "Unknown", GET_U_1(tptr)),
                   GET_U_1(tptr));
            break;

        case LS_OPAQUE_GRACE_TLV_INT_ADDRESS:
            if (tlv_length != 4) {
                ND_PRINT("\n\t    Bogus length %u != 4", tlv_length);
                return -1;
            }
            ND_PRINT("%s", GET_IPADDR_STRING(tptr));
            break;

        default:
            if (ndo->ndo_vflag <= 1) {
                if (!print_unknown_data(ndo, tptr, "\n\t      ", tlv_length))
                    return -1;
            }
            break;

        }
        /* in OSPF everything has to be 32-bit aligned, including TLVs */
        if (tlv_length % 4 != 0) {
            tlv_length += 4 - (tlv_length % 4);
            if (tlv_length > ls_length) {
                ND_PRINT("\n\t    Bogus padded length %u > %u", tlv_length,
                       ls_length);
                return -1;
            }
        }
        ls_length -= tlv_length;
        tptr += tlv_length;
    }

    return 0;
trunc:
    nd_print_trunc(ndo);
    return -1;
}

static int
ospf_te_tlv_link_print(netdissect_options *ndo,
                       const u_char *tptr, u_int tlv_length)
{
    u_int subtlv_type, subtlv_length;
    u_int priority_level, te_class, count_srlg;

    while (tlv_length != 0) {
        if (tlv_length < 4) {
            ND_PRINT("\n\t    Remaining TLV length %u < 4",
                   tlv_length);
            return -1;
        }
        subtlv_type = GET_BE_U_2(tptr);
        subtlv_length = GET_BE_U_2(tptr + 2);
        tptr += 4;
        tlv_length -= 4;

        /* Infinite loop protection */
        if (subtlv_type == 0 || subtlv_length == 0)
            goto invalid;

        ND_PRINT("\n\t      %s subTLV (%u), length: %u",
               tok2str(lsa_opaque_te_link_tlv_subtlv_values,"unknown",subtlv_type),
               subtlv_type,
               subtlv_length);

        if (tlv_length < subtlv_length) {
            ND_PRINT("\n\t    Remaining TLV length %u < %u",
                   tlv_length, subtlv_length);
            return -1;
        }
        ND_TCHECK_LEN(tptr, subtlv_length);
        switch(subtlv_type) {
        case LS_OPAQUE_TE_LINK_SUBTLV_ADMIN_GROUP:
            if (subtlv_length != 4) {
                ND_PRINT(" != 4");
                goto invalid;
            }
            ND_PRINT(", 0x%08x", GET_BE_U_4(tptr));
            break;
        case LS_OPAQUE_TE_LINK_SUBTLV_LINK_ID:
        case LS_OPAQUE_TE_LINK_SUBTLV_LINK_LOCAL_REMOTE_ID:
            if (subtlv_length != 4 && subtlv_length != 8) {
                ND_PRINT(" != 4 && != 8");
                goto invalid;
            }
            ND_PRINT(", %s (0x%08x)",
                   GET_IPADDR_STRING(tptr),
                   GET_BE_U_4(tptr));
            if (subtlv_length == 8) /* rfc4203 */
                ND_PRINT(", %s (0x%08x)",
                       GET_IPADDR_STRING(tptr + 4),
                       GET_BE_U_4(tptr + 4));
            break;
        case LS_OPAQUE_TE_LINK_SUBTLV_LOCAL_IP:
        case LS_OPAQUE_TE_LINK_SUBTLV_REMOTE_IP:
            if (subtlv_length != 4) {
                ND_PRINT(" != 4");
                goto invalid;
            }
            ND_PRINT(", %s", GET_IPADDR_STRING(tptr));
            break;
        case LS_OPAQUE_TE_LINK_SUBTLV_MAX_BW:
        case LS_OPAQUE_TE_LINK_SUBTLV_MAX_RES_BW:
            if (subtlv_length != 4) {
                ND_PRINT(" != 4");
                goto invalid;
            }
            ND_PRINT(", %.3f Mbps", GET_BE_F_4(tptr) * 8 / 1000000);
            break;
        case LS_OPAQUE_TE_LINK_SUBTLV_UNRES_BW:
            if (subtlv_length != 32) {
                ND_PRINT(" != 32");
                goto invalid;
            }
            for (te_class = 0; te_class < 8; te_class++) {
                ND_PRINT("\n\t\tTE-Class %u: %.3f Mbps",
                       te_class,
                       GET_BE_F_4(tptr + te_class * 4) * 8 / 1000000);
            }
            break;
        case LS_OPAQUE_TE_LINK_SUBTLV_BW_CONSTRAINTS:
            if (subtlv_length < 4) {
                ND_PRINT(" < 4");
                goto invalid;
            }
            /* BC Model Id (1 octet) + Reserved (3 octets) */
            ND_PRINT("\n\t\tBandwidth Constraints Model ID: %s (%u)",
                   tok2str(diffserv_te_bc_values, "unknown", GET_U_1(tptr)),
                   GET_U_1(tptr));
            if (subtlv_length % 4 != 0) {
                ND_PRINT("\n\t\tlength %u != N x 4", subtlv_length);
                goto invalid;
            }
            if (subtlv_length > 36) {
                ND_PRINT("\n\t\tlength %u > 36", subtlv_length);
                goto invalid;
            }
            /* decode BCs until the subTLV ends */
            for (te_class = 0; te_class < (subtlv_length - 4) / 4; te_class++) {
                ND_PRINT("\n\t\t  Bandwidth constraint CT%u: %.3f Mbps",
                       te_class,
                       GET_BE_F_4(tptr + 4 + te_class * 4) * 8 / 1000000);
            }
            break;
        case LS_OPAQUE_TE_LINK_SUBTLV_TE_METRIC:
            if (subtlv_length != 4) {
                ND_PRINT(" != 4");
                goto invalid;
            }
            ND_PRINT(", Metric %u", GET_BE_U_4(tptr));
            break;
        case LS_OPAQUE_TE_LINK_SUBTLV_LINK_PROTECTION_TYPE:
            /* Protection Cap (1 octet) + Reserved ((3 octets) */
            if (subtlv_length != 4) {
                ND_PRINT(" != 4");
                goto invalid;
            }
            ND_PRINT(", %s",
                     bittok2str(gmpls_link_prot_values, "none", GET_U_1(tptr)));
            break;
        case LS_OPAQUE_TE_LINK_SUBTLV_INTF_SW_CAP_DESCR:
            if (subtlv_length < 36) {
                ND_PRINT(" < 36");
                goto invalid;
            }
            /* Switching Cap (1 octet) + Encoding (1) +  Reserved (2) */
            ND_PRINT("\n\t\tInterface Switching Capability: %s",
                   tok2str(gmpls_switch_cap_values, "Unknown", GET_U_1((tptr))));
            ND_PRINT("\n\t\tLSP Encoding: %s\n\t\tMax LSP Bandwidth:",
                   tok2str(gmpls_encoding_values, "Unknown", GET_U_1((tptr + 1))));
            for (priority_level = 0; priority_level < 8; priority_level++) {
                ND_PRINT("\n\t\t  priority level %u: %.3f Mbps",
                       priority_level,
                       GET_BE_F_4(tptr + 4 + (priority_level * 4)) * 8 / 1000000);
            }
            break;
        case LS_OPAQUE_TE_LINK_SUBTLV_LINK_TYPE:
            if (subtlv_length != 1) {
                ND_PRINT(" != 1");
                goto invalid;
            }
            ND_PRINT(", %s (%u)",
                   tok2str(lsa_opaque_te_tlv_link_type_sub_tlv_values,"unknown",GET_U_1(tptr)),
                   GET_U_1(tptr));
            break;
        case LS_OPAQUE_TE_LINK_SUBTLV_SHARED_RISK_GROUP:
            if (subtlv_length % 4 != 0) {
                ND_PRINT(" != N x 4");
                goto invalid;
            }
            count_srlg = subtlv_length / 4;
            if (count_srlg != 0)
                ND_PRINT("\n\t\t  Shared risk group: ");
            while (count_srlg != 0) {
                ND_PRINT("%u", GET_BE_U_4(tptr));
                tptr += 4;
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
        if (subtlv_length % 4 != 0) {
            subtlv_length += 4 - (subtlv_length % 4);

            if (tlv_length < subtlv_length) {
                ND_PRINT("\n\t    Remaining TLV length %u < %u",
                        tlv_length, subtlv_length);
                return -1;
            }
        }
        tlv_length -= subtlv_length;
        tptr += subtlv_length;
    }
    return 0;
trunc:
    nd_print_trunc(ndo);
    return -1;
invalid:
    nd_print_invalid(ndo);
    return -1;
}

int
ospf_te_lsa_print(netdissect_options *ndo,
                  const u_char *tptr, u_int ls_length)
{
    u_int tlv_type, tlv_length;

    while (ls_length != 0) {
        ND_TCHECK_4(tptr);
        if (ls_length < 4) {
            ND_PRINT("\n\t    Remaining LS length %u < 4", ls_length);
            return -1;
        }
        tlv_type = GET_BE_U_2(tptr);
        tlv_length = GET_BE_U_2(tptr + 2);
        tptr += 4;
        ls_length -= 4;

        ND_PRINT("\n\t    %s TLV (%u), length: %u",
               tok2str(lsa_opaque_te_tlv_values,"unknown",tlv_type),
               tlv_type,
               tlv_length);

        if (tlv_length > ls_length) {
            ND_PRINT("\n\t    Bogus length %u > %u", tlv_length,
                   ls_length);
            goto invalid;
        }

        /* Infinite loop protection. */
        if (tlv_type == 0 || tlv_length == 0) {
	    nd_print_invalid(ndo);
            goto invalid;
        }

        switch(tlv_type) {
        case LS_OPAQUE_TE_TLV_LINK:
            if (ospf_te_tlv_link_print(ndo, tptr, tlv_length) == -1)
                return -1;
            break;

        case LS_OPAQUE_TE_TLV_ROUTER:
            if (tlv_length < 4) {
                ND_PRINT("\n\t    TLV length %u < 4", tlv_length);
                goto invalid;
            }
            ND_PRINT(", %s", GET_IPADDR_STRING(tptr));
            break;

        default:
            if (ndo->ndo_vflag <= 1) {
                if (!print_unknown_data(ndo, tptr, "\n\t      ", tlv_length))
                    goto invalid;
            }
            break;
        }
        /* in OSPF everything has to be 32-bit aligned, including TLVs */
        if (tlv_length % 4 != 0) {
            tlv_length += 4 - (tlv_length % 4);
            if (tlv_length > ls_length) {
                ND_PRINT("\n\t    Bogus padded length %u > %u", tlv_length,
                       ls_length);
                goto invalid;
            }
        }
        ls_length -= tlv_length;
        tptr += tlv_length;
    }
    return 0;
trunc:
    nd_print_trunc(ndo);
    return -1;
invalid:
    nd_print_invalid(ndo);
    return -1;
}

static int
ospf_print_lshdr(netdissect_options *ndo,
                 const struct lsa_hdr *lshp)
{
        u_int ls_type;
        u_int ls_length;

        ls_length = GET_BE_U_2(lshp->ls_length);
        if (ls_length < sizeof(struct lsa_hdr)) {
                ND_PRINT("\n\t    Bogus length %u < header (%zu)", ls_length,
                    sizeof(struct lsa_hdr));
                return(-1);
        }
        ND_PRINT("\n\t  Advertising Router %s, seq 0x%08x, age %us, length %zu",
                  GET_IPADDR_STRING(lshp->ls_router),
                  GET_BE_U_4(lshp->ls_seq),
                  GET_BE_U_2(lshp->ls_age),
                  ls_length - sizeof(struct lsa_hdr));
        ls_type = GET_U_1(lshp->ls_type);
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
			   GET_U_1(lshp->un_lsa_id.opaque_field.opaque_type)),
		   GET_U_1(lshp->un_lsa_id.opaque_field.opaque_type),
		   GET_BE_U_3(lshp->un_lsa_id.opaque_field.opaque_id)

                   );
            break;

        /* all other LSA types use regular style LSA headers */
        default:
            ND_PRINT("\n\t    %s LSA (%u), LSA-ID: %s",
                   tok2str(lsa_values,"unknown",ls_type),
                   ls_type,
                   GET_IPADDR_STRING(lshp->un_lsa_id.lsa_id));
            break;
        }
        ND_PRINT("\n\t    Options: [%s]",
		 bittok2str(ospf_option_values, "none", GET_U_1(lshp->ls_options)));

        return (ls_length);
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
static void
ospf_print_tos_metrics(netdissect_options *ndo,
                       const union un_tos *tos)
{
    u_int metric_count;
    u_int toscount;
    u_int tos_type;

    toscount = GET_U_1(tos->link.link_tos_count) + 1;
    metric_count = 0;

    /*
     * All but the first metric contain a valid topology id.
     */
    while (toscount != 0) {
        tos_type = GET_U_1(tos->metrics.tos_type);
        ND_PRINT("\n\t\ttopology %s (%u), metric %u",
               tok2str(ospf_topology_values, "Unknown",
                       metric_count ? tos_type : 0),
               metric_count ? tos_type : 0,
               GET_BE_U_2(tos->metrics.tos_metric));
        metric_count++;
        tos++;
        toscount--;
    }
}

/*
 * The SID/Label Range TLV
 * https://datatracker.ietf.org/doc/html/rfc8665#section-3.2
 * and the SR Local Block TLV
 * https://datatracker.ietf.org/doc/html/rfc8665#section-3.3
 * have the same contents, so this function is used to
 * print both.
 */
static int
ospf_print_ri_lsa_sid_label_range_tlv(netdissect_options *ndo, const uint8_t *tptr,
				      u_int tlv_length)
{
    u_int subtlv_type, subtlv_length;

    while (tlv_length >= 4) {

	subtlv_type = GET_BE_U_2(tptr);
	subtlv_length = GET_BE_U_2(tptr + 2);
	tptr += 4;
	tlv_length -= 4;

	/* Infinite loop protection. */
	if (subtlv_type == 0 || subtlv_length == 0) {
	    nd_print_invalid(ndo);
	    return -1;
	}

	ND_PRINT("\n\t      %s subTLV (%u), length: %u, value: ",
		 tok2str(lsa_opaque_ri_sid_subtlv_values,"unknown",subtlv_type),
		 subtlv_type,
		 subtlv_length);

	if (tlv_length < subtlv_length) {
	    ND_PRINT("\n\t    Remaining TLV length %u < %u",
		tlv_length, subtlv_length);
	    return -1;
	}

	switch (subtlv_type) {
	case LS_OPAQUE_RI_SUBTLV_SID_LABEL:
	    if (subtlv_length == 3) {
		ND_PRINT("\n\t\tLabel: %u", GET_BE_U_3(tptr));
	    } else if (subtlv_length == 4) {
		ND_PRINT("\n\t\tSID: %u", GET_BE_U_4(tptr));
	    } else {
		ND_PRINT("\n\t\tBogus subTLV length %u", subtlv_length);
	    }
	    break;

	default:
	    if (ndo->ndo_vflag <= 1) {
		if (!print_unknown_data(ndo, tptr, "\n\t\t", subtlv_length))
		    return -1;
	    }
	}

	/* in OSPF everything has to be 32-bit aligned, including subTLVs */
	if (subtlv_length % 4) {
	    subtlv_length += (4 - (subtlv_length % 4));
	    if (tlv_length < subtlv_length) {
		ND_PRINT("\n\t    Remaining TLV length %u < %u",
		    tlv_length, subtlv_length);
		return -1;
	    }
	}
	tptr += subtlv_length;
	tlv_length -= subtlv_length;
    }
    return 0;
}

static int
ospf_print_ep_lsa_extd_prefix_tlv(netdissect_options *ndo, const uint8_t *tptr,
				  u_int tlv_length)
{
    u_int subtlv_type, subtlv_length;
    uint8_t flags, mt_id, algo;

    while (tlv_length >= 4) {
	subtlv_type = GET_BE_U_2(tptr);
	subtlv_length = GET_BE_U_2(tptr + 2);
	tptr += 4;
	tlv_length -= 4;

	/* Infinite loop protection. */
	if (subtlv_type == 0 || subtlv_length == 0) {
	    nd_print_invalid(ndo);
	    return -1;
	}

	ND_PRINT("\n\t\t%s subTLV (%u), length: %u, value: ",
		 tok2str(lsa_opaque_ep_extd_prefix_subtlv_values,"unknown",subtlv_type),
		 subtlv_type,
		 subtlv_length);

	if (tlv_length < subtlv_length) {
            ND_PRINT("\n\t    Remaining TLV length %u < %u",
                tlv_length, subtlv_length);
	    return -1;
	}

	switch (subtlv_type) {
	case LS_OPAQUE_EP_SUBTLV_PREFIX_SID:
	    flags = GET_U_1(tptr);
	    mt_id = GET_U_1(tptr + 2);
	    algo = GET_U_1(tptr + 3);

	    if (subtlv_length == 7) {
		ND_PRINT("\n\t\t  Label: %u", GET_BE_U_3(tptr + 4));
	    } else if (subtlv_length == 8) {
		ND_PRINT("\n\t\t  Index: %u", GET_BE_U_4(tptr + 4));
	    } else {
		ND_PRINT("\n\t\tBogus subTLV length %u", subtlv_length);
		break;
	    }
	    ND_PRINT( ", MT-ID: %u, Algorithm: %s (%u), Flags [%s]",
		      mt_id, tok2str(lsa_opaque_ri_tlv_sr_algos, "Unknown", algo), algo,
		 bittok2str(ep_range_tlv_prefix_sid_subtlv_flag_values, "none", flags));
	    break;

	default:
	    if (ndo->ndo_vflag <= 1) {
		if (!print_unknown_data(ndo, tptr, "\n\t\t", subtlv_length))
		    return -1;
	    }
	}

	/* in OSPF everything has to be 32-bit aligned, including subTLVs */
	if (subtlv_length % 4) {
	    subtlv_length += (4 - (subtlv_length % 4));
	    if (tlv_length < subtlv_length) {
		ND_PRINT("\n\t    Remaining TLV length %u < %u",
		    tlv_length, subtlv_length);
		return -1;
	    }
	}
	tptr += subtlv_length;
	tlv_length -= subtlv_length;
    }
    return 0;
}

static int
ospf_ep_lsa_print(netdissect_options *ndo, const uint8_t *tptr, u_int lsa_length)
{
    u_int tlv_type, tlv_length;
    uint16_t range_size;
    uint8_t af, prefix_length, route_type, flags;

    while (lsa_length >= 4) {

	tlv_type = GET_BE_U_2(tptr);
	tlv_length = GET_BE_U_2(tptr + 2);
	tptr += 4;
	lsa_length -= 4;

	/* Infinite loop protection. */
	if (tlv_type == 0 || tlv_length == 0) {
	    nd_print_invalid(ndo);
	    return -1;
	}

	ND_PRINT("\n\t    %s TLV (%u), length: %u, value: ",
		 tok2str(lsa_opaque_ep_tlv_values,"unknown",tlv_type),
		 tlv_type,
		 tlv_length);

	if (tlv_length > lsa_length) {
	    ND_PRINT("\n\t    Bogus length %u > %u",
		tlv_length, lsa_length);
	    return -1;
	}

	switch (tlv_type) {
	case LS_OPAQUE_EP_EXTD_PREFIX_TLV:
	    prefix_length = GET_U_1(tptr + 1);
	    af = GET_U_1(tptr + 2);
	    route_type = GET_U_1(tptr);
	    flags = GET_U_1(tptr + 3);

	    if (af != 0) {
		ND_PRINT("\n\t      Bogus AF %u", af);
		return -1;
	    }

	    if (prefix_length > 32) {
		ND_PRINT("\n\t      IPv4 prefix: bad bit length %u", prefix_length);
		return -1;
	    }

	    ND_PRINT("\n\t      IPv4 prefix: %15s/%u, Route Type: %s, Flags [%s]",
		     GET_IPADDR_STRING(tptr + 4), prefix_length,
		     tok2str(lsa_opaque_ep_route_type_values, "Unknown", route_type),
		     bittok2str(ep_tlv_flag_values, "none", flags));

	    /* subTLVs present ? */
	    if (tlv_length > 12) {
		if (ospf_print_ep_lsa_extd_prefix_tlv(ndo, tptr + 8, tlv_length - 8) == -1) {
		    return -1;
		}
	    }
	    break;

	case LS_OPAQUE_EP_EXTD_PREFIX_RANGE_TLV:
	    prefix_length = GET_U_1(tptr);
	    af = GET_U_1(tptr + 1);
	    range_size = GET_BE_U_2(tptr + 2);
	    flags = GET_U_1(tptr + 4);

	    if (af != 0) {
		ND_PRINT("\n\t      Bogus AF %u", af);
		return -1;
	    }

	    if (prefix_length > 32) {
		ND_PRINT("\n\t      IPv4 prefix: bad bit length %u", prefix_length);
		return -1;
	    }

	    ND_PRINT("\n\t      IPv4 prefix: %15s/%u, Range size: %u, Flags [%s]",
		     GET_IPADDR_STRING(tptr + 8), prefix_length,
		     range_size,
		     bittok2str(ep_tlv_flag_values, "none", flags));

	    /* subTLVs present ? */
	    if (tlv_length > 12) {
		if (ospf_print_ep_lsa_extd_prefix_tlv(ndo, tptr + 12, tlv_length - 12) == -1) {
		    return -1;
		}
	    }
	    break;

	default:
	    if (ndo->ndo_vflag <= 1) {
		if (!print_unknown_data(ndo, tptr, "\n\t\t", tlv_length))
		    return -1;
	    }
	}

	/* in OSPF everything has to be 32-bit aligned, including TLVs */
	if (tlv_length % 4) {
	    tlv_length += (4 - (tlv_length % 4));
	    if (tlv_length > lsa_length) {
		ND_PRINT("\n\t    Bogus padded length %u > %u", tlv_length,
		    lsa_length);
		return -1;
	    }
	}
	tptr += tlv_length;
	lsa_length -= tlv_length;
    }
    return 0;
}

static int
ospf_el_lsa_print(netdissect_options *ndo, const uint8_t *tptr, u_int lsa_length)
{
    u_int tlv_type, tlv_length, link_type, sub_tlv_flags;
    u_int sub_tlv_type, sub_tlv_length, sub_tlv_remaining;
    const uint8_t *sub_tlv_tptr;
    u_int vflag, lflag;

    while (lsa_length >= 4) {
	tlv_type = GET_BE_U_2(tptr);
	tlv_length = GET_BE_U_2(tptr+2);
	tptr+=4;
	lsa_length-=4;

	/* Infinite loop protection. */
	if (tlv_type == 0 || tlv_length == 0) {
	    return -1;
	}

	ND_PRINT("\n\t    %s TLV (%u), length: %u, value: ",
		 tok2str(lsa_opaque_el_tlv_values,"unknown",tlv_type),
		 tlv_type,
		 tlv_length);

	switch (tlv_type) {
        case LS_OPAQUE_EXTENDED_LINK_TLV:
            link_type = GET_U_1(tptr);

            ND_PRINT("\n\t      Link Type: %s (%u)",
                tok2str(lsa_opaque_extended_link_link_type_values,"unknown",link_type),
                link_type);
            ND_PRINT("\n\t      Reserved: %u", GET_BE_U_3(tptr+1));
            ND_PRINT("\n\t      Link ID: %s", GET_IPADDR_STRING(tptr+4));
            ND_PRINT("\n\t      Link Data: %s", GET_IPADDR_STRING(tptr+8));

            sub_tlv_tptr = tptr + 12;
            sub_tlv_remaining = tlv_length - 12;

            while(sub_tlv_remaining > 0) {
                sub_tlv_type = GET_BE_U_2(sub_tlv_tptr);
                sub_tlv_length = GET_BE_U_2(sub_tlv_tptr + 2);
                sub_tlv_remaining-=4;
                sub_tlv_tptr+=4;

                ND_PRINT("\n\t      %s (%u), length: %u, value: ",
                    tok2str(lsa_opaque_extended_link_subtlv_values,"unknown",sub_tlv_type),
                    sub_tlv_type,
                    sub_tlv_length);

                switch(sub_tlv_type){

                case LS_OPAQUE_EXTENDED_LINK_SUBTLV_ADJ_SID:
                    sub_tlv_flags = GET_U_1(sub_tlv_tptr);

                    ND_PRINT("\n\t        Flags: [%s]",
                        bittok2str(lsa_opaque_extended_link_subtlv_adj_sid_flag_values, "none", sub_tlv_flags));
                    ND_PRINT("\n\t        Reserved: %u", GET_U_1(sub_tlv_tptr+1));
                    ND_PRINT("\n\t        MT-ID: %u", GET_U_1(sub_tlv_tptr+2));
                    ND_PRINT("\n\t        Weight: %u", GET_U_1(sub_tlv_tptr+3));

                    vflag = sub_tlv_flags & LS_OPAQUE_EXTENDED_LINK_SUBTLV_ADJ_SID_FLAG_V;
                    lflag = sub_tlv_flags & LS_OPAQUE_EXTENDED_LINK_SUBTLV_ADJ_SID_FLAG_L;
                    if (vflag && lflag) {
                        ND_PRINT("\n\t        SID/Label: %u",GET_BE_U_3(sub_tlv_tptr + 4));
                    }
                    else if ( !vflag && !lflag ) {
                        ND_PRINT("\n\t        SID/Label: %u",GET_BE_U_4(sub_tlv_tptr + 4));
                    }
                    else {
                        ND_PRINT("\n\t        Invalid V-Flag and L-flag combination");
                        if (!print_unknown_data(ndo, sub_tlv_tptr, "\n\t      ", sub_tlv_length))
                            return(-1);
                    }
                    break;

                default:
                    if (ndo->ndo_vflag <= 1) {
                        if (!print_unknown_data(ndo, sub_tlv_tptr, "\n\t      ", sub_tlv_length))
                            return(-1);
                    }
                    break;
                }

                if (sub_tlv_length % 4) {
                    sub_tlv_length += (4 - (sub_tlv_length % 4));
                }
                sub_tlv_tptr+=sub_tlv_length;
                sub_tlv_remaining-=sub_tlv_length;
            }
            break;
	default:
	    if (ndo->ndo_vflag <= 1) {
		if (!print_unknown_data(ndo, tptr, "\n\t      ", tlv_length))
		    return -1;
	    }
	}

	/* in OSPF everything has to be 32-bit aligned, including TLVs */
	if (tlv_length % 4) {
	    tlv_length += (4 - (tlv_length % 4));
	}
	tptr+=tlv_length;
	lsa_length-=tlv_length;
    }
    return 0;
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
	u_int tlv_type, tlv_length, rla_count, topology, num_tlv;
	int ospf_print_lshdr_ret;
	u_int ls_length;
	const uint8_t *tptr;

	tptr = (const uint8_t *)lsap->lsa_un.un_unknown; /* squelch compiler warnings */
	ospf_print_lshdr_ret = ospf_print_lshdr(ndo, &lsap->ls_hdr);
	if (ospf_print_lshdr_ret < 0)
		return(NULL);
	ls_length = (u_int)ospf_print_lshdr_ret;
	ls_end = (const uint8_t *)lsap + ls_length;
	/*
	 * ospf_print_lshdr() returns -1 if the length is too short,
	 * so we know ls_length is >= sizeof(struct lsa_hdr).
	 */
	ls_length -= sizeof(struct lsa_hdr);

	switch (GET_U_1(lsap->ls_hdr.ls_type)) {

	case LS_TYPE_ROUTER:
		ND_PRINT("\n\t    Router LSA Options: [%s]",
		          bittok2str(ospf_rla_flag_values, "none", GET_U_1(lsap->lsa_un.un_rla.rla_flags)));

		rla_count = GET_BE_U_2(lsap->lsa_un.un_rla.rla_count);
		ND_TCHECK_SIZE(lsap->lsa_un.un_rla.rla_link);
		rlp = lsap->lsa_un.un_rla.rla_link;
		for (u_int i = rla_count; i != 0; i--) {
			ND_TCHECK_SIZE(rlp);
			switch (GET_U_1(rlp->un_tos.link.link_type)) {

			case RLA_TYPE_VIRTUAL:
				ND_PRINT("\n\t      Virtual Link: Neighbor Router-ID: %s, Interface Address: %s",
				    GET_IPADDR_STRING(rlp->link_id),
				    GET_IPADDR_STRING(rlp->link_data));
				break;

			case RLA_TYPE_ROUTER:
				ND_PRINT("\n\t      Neighbor Router-ID: %s, Interface Address: %s",
				    GET_IPADDR_STRING(rlp->link_id),
				    GET_IPADDR_STRING(rlp->link_data));
				break;

			case RLA_TYPE_TRANSIT:
				ND_PRINT("\n\t      Neighbor Network-ID: %s, Interface Address: %s",
				    GET_IPADDR_STRING(rlp->link_id),
				    GET_IPADDR_STRING(rlp->link_data));
				break;

			case RLA_TYPE_STUB:
				ND_PRINT("\n\t      Stub Network: %s, Mask: %s",
				    GET_IPADDR_STRING(rlp->link_id),
				    GET_IPADDR_STRING(rlp->link_data));
				break;

			default:
				ND_PRINT("\n\t      Unknown Router Link Type (%u)",
				    GET_U_1(rlp->un_tos.link.link_type));
				return (ls_end);
			}

			ospf_print_tos_metrics(ndo, &rlp->un_tos);

			rlp = (const struct rlalink *)((const u_char *)(rlp + 1) +
			    (GET_U_1(rlp->un_tos.link.link_tos_count) * sizeof(union un_tos)));
		}
		break;

	case LS_TYPE_NETWORK:
		ND_PRINT("\n\t    Mask %s\n\t    Connected Routers:",
		    GET_IPADDR_STRING(lsap->lsa_un.un_nla.nla_mask));
		ap = lsap->lsa_un.un_nla.nla_router;
		while ((const u_char *)ap < ls_end) {
			ND_PRINT("\n\t      %s", GET_IPADDR_STRING(ap));
			++ap;
		}
		break;

	case LS_TYPE_SUM_IP:
		ND_TCHECK_4(lsap->lsa_un.un_nla.nla_mask);
		ND_PRINT("\n\t    Mask %s",
		    GET_IPADDR_STRING(lsap->lsa_un.un_sla.sla_mask));
		ND_TCHECK_SIZE(lsap->lsa_un.un_sla.sla_tosmetric);
		lp = (const uint8_t *)lsap->lsa_un.un_sla.sla_tosmetric;
		while (lp < ls_end) {
			uint32_t ul;

			ul = GET_BE_U_4(lp);
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

			ul = GET_BE_U_4(lp);
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
		    GET_IPADDR_STRING(lsap->lsa_un.un_asla.asla_mask));

		ND_TCHECK_SIZE(lsap->lsa_un.un_sla.sla_tosmetric);
		almp = lsap->lsa_un.un_asla.asla_metric;
		while ((const u_char *)almp < ls_end) {
			uint32_t ul;

			ul = GET_BE_U_4(almp->asla_tosmetric);
                        topology = ((ul & ASLA_MASK_TOS) >> ASLA_SHIFT_TOS);
			ND_PRINT("\n\t\ttopology %s (%u), type %u, metric",
                               tok2str(ospf_topology_values, "Unknown", topology),
                               topology,
                               (ul & ASLA_FLAG_EXTERNAL) ? 2 : 1);
			if ((ul & ASLA_MASK_METRIC) == 0xffffff)
				ND_PRINT(" infinite");
			else
				ND_PRINT(" %u", (ul & ASLA_MASK_METRIC));

			if (GET_IPV4_TO_NETWORK_ORDER(almp->asla_forward) != 0) {
				ND_PRINT(", forward %s", GET_IPADDR_STRING(almp->asla_forward));
			}
			if (GET_IPV4_TO_NETWORK_ORDER(almp->asla_tag) != 0) {
				ND_PRINT(", tag %s", GET_IPADDR_STRING(almp->asla_tag));
			}
			++almp;
		}
		break;

	case LS_TYPE_GROUP:
		/* Multicast extensions as of 23 July 1991 */
		mcp = lsap->lsa_un.un_mcla;
		while ((const u_char *)mcp < ls_end) {
			switch (GET_BE_U_4(mcp->mcla_vtype)) {

			case MCLA_VERTEX_ROUTER:
				ND_PRINT("\n\t    Router Router-ID %s",
				    GET_IPADDR_STRING(mcp->mcla_vid));
				break;

			case MCLA_VERTEX_NETWORK:
				ND_PRINT("\n\t    Network Designated Router %s",
				    GET_IPADDR_STRING(mcp->mcla_vid));
				break;

			default:
				ND_PRINT("\n\t    unknown VertexType (%u)",
				    GET_BE_U_4(mcp->mcla_vtype));
				break;
			}
		++mcp;
		}
		break;

	case LS_TYPE_OPAQUE_LL: /* fall through */
	case LS_TYPE_OPAQUE_AL:
	case LS_TYPE_OPAQUE_DW:

	    switch (GET_U_1(lsap->ls_hdr.un_lsa_id.opaque_field.opaque_type)) {
            case LS_OPAQUE_TYPE_RI:
		tptr = (const uint8_t *)(lsap->lsa_un.un_ri_tlv);

		u_int ls_length_remaining = ls_length;
		while (ls_length_remaining != 0) {
                    ND_TCHECK_4(tptr);
		    if (ls_length_remaining < 4) {
                        ND_PRINT("\n\t    Remaining LS length %u < 4", ls_length_remaining);
                        return(ls_end);
                    }
                    tlv_type = GET_BE_U_2(tptr);
                    tlv_length = GET_BE_U_2(tptr + 2);
                    tptr += 4;
                    ls_length_remaining -= 4;

                    ND_PRINT("\n\t    %s TLV (%u), length: %u, value: ",
                           tok2str(lsa_opaque_ri_tlv_values,"unknown",tlv_type),
                           tlv_type,
                           tlv_length);

                    if (tlv_length > ls_length_remaining) {
                        ND_PRINT("\n\t    Bogus length %u > remaining LS length %u", tlv_length,
                            ls_length_remaining);
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
                               bittok2str(lsa_opaque_ri_tlv_cap_values, "Unknown", GET_BE_U_4(tptr)));
                        break;

                    case LS_OPAQUE_RI_TLV_HOSTNAME:
                        ND_PRINT("\n\t      Hostname: ");
                        nd_printjnp(ndo, tptr, tlv_length);
                        break;

                    case LS_OPAQUE_RI_TLV_SR_ALGO:
                        num_tlv = tlv_length;
                        while (num_tlv >= 1) {
                            ND_PRINT("\n\t      %s (%u)",
                                     tok2str(lsa_opaque_ri_tlv_sr_algos,
                                     "Unknown", GET_U_1(tptr + tlv_length - num_tlv)),
                                     GET_U_1(tptr + tlv_length - num_tlv));
                            num_tlv--;
                        }
                        break;

                    case LS_OPAQUE_RI_TLV_SID_LABEL_RANGE:
                    case LS_OPAQUE_RI_TLV_SR_LOCAL_BLOCK:
                        ND_TCHECK_4(tptr);
                        ND_PRINT("\n\t      Range size: %u", GET_BE_U_3(tptr));
                        if (ospf_print_ri_lsa_sid_label_range_tlv(ndo, tptr + 4, tlv_length - 4) == -1) {
                            return(ls_end);
                        }
                        break;

                    case LS_OPAQUE_RI_TLV_SRMS_PREFERENCE:
                        if (tlv_length != 4) {
                            ND_PRINT("\n\t    Bogus SRMS Preference TLV length %u != 4", tlv_length);
                            return(ls_end);
                        }
                        ND_PRINT("\n\t      SRMS Preference: %u", GET_U_1(tptr));
                        break;

                    default:
                        if (ndo->ndo_vflag <= 1) {
                            if (!print_unknown_data(ndo, tptr, "\n\t      ", tlv_length))
                                return(ls_end);
                        }
                        break;

                    }

                    /* in OSPF everything has to be 32-bit aligned, including TLVs */
                    if (tlv_length % 4) {
                        tlv_length += (4 - (tlv_length % 4));
                        if (tlv_length > ls_length_remaining) {
                            ND_PRINT("\n\t    Bogus padded length %u > %u", tlv_length,
                                   ls_length_remaining);
                            return(NULL);
                        }
                    }
                    tptr += tlv_length;
                    ls_length_remaining -= tlv_length;
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

            case LS_OPAQUE_TYPE_EP:
                if (ospf_ep_lsa_print(ndo, (const u_char *)(lsap->lsa_un.un_ep_tlv),
                                      ls_length) == -1) {
                    return(ls_end);
                }
                break;

            case LS_OPAQUE_TYPE_EL:
                if (ospf_el_lsa_print(ndo, (const u_char *)(lsap->lsa_un.un_el_tlv),
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
	nd_print_trunc(ndo);
	return (NULL);
}

static void
ospf_decode_lls(netdissect_options *ndo,
                const struct ospfhdr *op, u_int length)
{
    const u_char *dptr;
    const u_char *dataend;
    u_int length2;
    uint16_t lls_type, lls_len;
    uint32_t lls_flags;

    switch (GET_U_1(op->ospf_type)) {

    case OSPF_TYPE_HELLO:
        if (!(GET_U_1(op->ospf_hello.hello_options) & OSPF_OPTION_L))
            return;
        break;

    case OSPF_TYPE_DD:
        if (!(GET_U_1(op->ospf_db.db_options) & OSPF_OPTION_L))
            return;
        break;

    default:
        return;
    }

    /* dig deeper if LLS data is available; see RFC4813 */
    length2 = GET_BE_U_2(op->ospf_len);
    dptr = (const u_char *)op + length2;
    dataend = (const u_char *)op + length;

    if (GET_BE_U_2(op->ospf_authtype) == OSPF_AUTH_MD5) {
        dptr = dptr + GET_U_1(op->ospf_authdata + 3);
        length2 += GET_U_1(op->ospf_authdata + 3);
    }
    if (length2 >= length) {
        ND_PRINT("\n\t[LLS truncated]");
        return;
    }
    ND_PRINT("\n\t  LLS: checksum: 0x%04x", (u_int) GET_BE_U_2(dptr));

    dptr += 2;
    length2 = GET_BE_U_2(dptr);
    ND_PRINT(", length: %u", length2);

    dptr += 2;
    while (dptr < dataend) {
        lls_type = GET_BE_U_2(dptr);
        ND_PRINT("\n\t    %s (%u)",
               tok2str(ospf_lls_tlv_values,"Unknown TLV",lls_type),
               lls_type);
        dptr += 2;
        lls_len = GET_BE_U_2(dptr);
        ND_PRINT(", length: %u", lls_len);
        dptr += 2;
        switch (lls_type) {

        case OSPF_LLS_EO:
            if (lls_len != 4) {
                ND_PRINT(" [should be 4]");
                lls_len = 4;
            }
            lls_flags = GET_BE_U_4(dptr);
            ND_PRINT("\n\t      Options: 0x%08x [%s]", lls_flags,
                   bittok2str(ospf_lls_eo_options, "?", lls_flags));

            break;

        case OSPF_LLS_MD5:
            if (lls_len != 20) {
                ND_PRINT(" [should be 20]");
                lls_len = 20;
            }
            ND_PRINT("\n\t      Sequence number: 0x%08x", GET_BE_U_4(dptr));
            break;
        }

        dptr += lls_len;
    }
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

	switch (GET_U_1(op->ospf_type)) {

	case OSPF_TYPE_HELLO:
		ND_PRINT("\n\tOptions [%s]",
		          bittok2str(ospf_option_values,"none",GET_U_1(op->ospf_hello.hello_options)));

		ND_PRINT("\n\t  Hello Timer %us, Dead Timer %us, Mask %s, Priority %u",
		          GET_BE_U_2(op->ospf_hello.hello_helloint),
		          GET_BE_U_4(op->ospf_hello.hello_deadint),
		          GET_IPADDR_STRING(op->ospf_hello.hello_mask),
		          GET_U_1(op->ospf_hello.hello_priority));

		if (GET_IPV4_TO_NETWORK_ORDER(op->ospf_hello.hello_dr) != 0)
			ND_PRINT("\n\t  Designated Router %s",
			    GET_IPADDR_STRING(op->ospf_hello.hello_dr));

		if (GET_IPV4_TO_NETWORK_ORDER(op->ospf_hello.hello_bdr) != 0)
			ND_PRINT(", Backup Designated Router %s",
			          GET_IPADDR_STRING(op->ospf_hello.hello_bdr));

		ap = op->ospf_hello.hello_neighbor;
		if ((const u_char *)ap < dataend)
			ND_PRINT("\n\t  Neighbor List:");
		while ((const u_char *)ap < dataend) {
			ND_PRINT("\n\t    %s", GET_IPADDR_STRING(ap));
			++ap;
		}
		break;	/* HELLO */

	case OSPF_TYPE_DD:
		ND_PRINT("\n\tOptions [%s]",
		          bittok2str(ospf_option_values, "none", GET_U_1(op->ospf_db.db_options)));
		ND_PRINT(", DD Flags [%s]",
		          bittok2str(ospf_dd_flag_values, "none", GET_U_1(op->ospf_db.db_flags)));
		if (GET_BE_U_2(op->ospf_db.db_ifmtu)) {
			ND_PRINT(", MTU: %u",
				 GET_BE_U_2(op->ospf_db.db_ifmtu));
		}
		ND_PRINT(", Sequence: 0x%08x", GET_BE_U_4(op->ospf_db.db_seq));

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
                           GET_IPADDR_STRING(lsrp->ls_router),
                           tok2str(lsa_values,"unknown",GET_BE_U_4(lsrp->ls_type)),
                           GET_BE_U_4(lsrp->ls_type));

                    switch (GET_BE_U_4(lsrp->ls_type)) {
                        /* the LSA header for opaque LSAs was slightly changed */
                    case LS_TYPE_OPAQUE_LL:
                    case LS_TYPE_OPAQUE_AL:
                    case LS_TYPE_OPAQUE_DW:
                        ND_PRINT(", Opaque-Type: %s LSA (%u), Opaque-ID: %u",
                               tok2str(lsa_opaque_values, "unknown",GET_U_1(lsrp->un_ls_stateid.opaque_field.opaque_type)),
                               GET_U_1(lsrp->un_ls_stateid.opaque_field.opaque_type),
                               GET_BE_U_3(lsrp->un_ls_stateid.opaque_field.opaque_id));
                        break;
                    default:
                        ND_PRINT(", LSA-ID: %s",
                               GET_IPADDR_STRING(lsrp->un_ls_stateid.ls_stateid));
                        break;
                    }

                    ++lsrp;
                }
		break;

	case OSPF_TYPE_LS_UPDATE:
                lsap = op->ospf_lsu.lsu_lsa;
                lsa_count_max = GET_BE_U_4(op->ospf_lsu.lsu_count);
                ND_PRINT(", %u LSA%s", lsa_count_max, PLURAL_SUFFIX(lsa_count_max));
                for (lsa_count = 1; lsa_count <= lsa_count_max; lsa_count++) {
                    ND_PRINT("\n\t  LSA #%u", lsa_count);
                        lsap = (const struct lsa *)ospf_print_lsa(ndo, lsap);
                        if (lsap == NULL)
                                goto trunc;
                }
		break;

	case OSPF_TYPE_LS_ACK:
                lshp = op->ospf_lsa.lsa_lshdr;
                while ((const u_char *)lshp < dataend) {
                    ospf_print_lshdr(ndo, lshp);
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
	if (GET_BE_U_2(op->ospf_authtype) == OSPF_AUTH_MD5) {
		length -= OSPF_AUTH_MD5_LEN;
		ndo->ndo_snapend -= OSPF_AUTH_MD5_LEN;
	}

	/* If the type is valid translate it, or just print the type */
	/* value.  If it's not valid, say so and return */
	cp = tok2str(type2str, "unknown LS-type %u", GET_U_1(op->ospf_type));
	ND_PRINT("OSPFv%u, %s, length %u", GET_U_1(op->ospf_version), cp,
		 length);
	if (*cp == 'u')
		return;

	if (!ndo->ndo_vflag) { /* non verbose - so lets bail out here */
		return;
	}

	if (length != GET_BE_U_2(op->ospf_len)) {
		ND_PRINT(" [len %u]", GET_BE_U_2(op->ospf_len));
	}

	if (length > GET_BE_U_2(op->ospf_len)) {
		dataend = bp + GET_BE_U_2(op->ospf_len);
	} else {
		dataend = bp + length;
	}

	ND_PRINT("\n\tRouter-ID %s", GET_IPADDR_STRING(op->ospf_routerid));

	if (GET_IPV4_TO_NETWORK_ORDER(op->ospf_areaid) != 0)
		ND_PRINT(", Area %s", GET_IPADDR_STRING(op->ospf_areaid));
	else
		ND_PRINT(", Backbone Area");

	if (ndo->ndo_vflag) {
		/* Print authentication data (should we really do this?) */
		ND_TCHECK_LEN(op->ospf_authdata, sizeof(op->ospf_authdata));

		ND_PRINT(", Authentication Type: %s (%u)",
		          tok2str(ospf_authtype_values, "unknown", GET_BE_U_2(op->ospf_authtype)),
		          GET_BE_U_2(op->ospf_authtype));

		switch (GET_BE_U_2(op->ospf_authtype)) {

		case OSPF_AUTH_NONE:
			break;

		case OSPF_AUTH_SIMPLE:
			ND_PRINT("\n\tSimple text password: ");
			nd_printjnp(ndo, op->ospf_authdata, OSPF_AUTH_SIMPLE_LEN);
			break;

		case OSPF_AUTH_MD5:
			ND_PRINT("\n\tKey-ID: %u, Auth-Length: %u, Crypto Sequence Number: 0x%08x",
			          GET_U_1(op->ospf_authdata + 2),
			          GET_U_1(op->ospf_authdata + 3),
			          GET_BE_U_4((op->ospf_authdata) + 4));
			break;

		default:
			return;
		}
	}
	/* Do rest according to version.	 */
	switch (GET_U_1(op->ospf_version)) {

	case 2:
		/* ospf version 2 */
		if (ospf_decode_v2(ndo, op, dataend))
			goto trunc;
		if (length > GET_BE_U_2(op->ospf_len))
			ospf_decode_lls(ndo, op, length);
		break;

	default:
		ND_PRINT(" ospf [version %u]", GET_U_1(op->ospf_version));
		break;
	}			/* end switch on version */

	return;
trunc:
	nd_trunc_longjmp(ndo);
}
