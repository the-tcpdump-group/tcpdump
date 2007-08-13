/*
 * Copyright (c) 1998-2007 The TCPDUMP project
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code
 * distributions retain the above copyright notice and this paragraph
 * in its entirety, and (2) distributions including binary code include
 * the above copyright notice and this paragraph in its entirety in
 * the documentation or other materials provided with the distribution.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND
 * WITHOUT ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, WITHOUT
 * LIMITATION, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE.
 *
 * support for the IEEE Link Discovery Protocol as per 802.1ab
 *
 * Original code by Hannes Gredler (hannes@juniper.net)
 */

#ifndef lint
static const char rcsid[] _U_ =
"@(#) $Header: /tcpdump/master/tcpdump/print-lldp.c,v 1.4 2007-08-13 12:55:17 hannes Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <tcpdump-stdinc.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "interface.h"
#include "extract.h"
#include "addrtoname.h"
#include "af.h"
#include "oui.h"

#define	LLDP_EXTRACT_TYPE(x) (((x)&0xfe00)>>9) 
#define	LLDP_EXTRACT_LEN(x) ((x)&0x01ff) 

/*
 * TLV type codes
 */
#define LLDP_END_TLV             0
#define LLDP_CHASSIS_ID_TLV      1
#define LLDP_PORT_ID_TLV         2
#define LLDP_TTL_TLV             3
#define LLDP_PORT_DESCR_TLV      4
#define LLDP_SYSTEM_NAME_TLV     5
#define LLDP_SYSTEM_DESCR_TLV    6
#define LLDP_SYSTEM_CAP_TLV      7
#define LLDP_MGMT_ADDR_TLV       8
#define LLDP_PRIVATE_TLV       127

static const struct tok lldp_tlv_values[] = {
    { LLDP_END_TLV, "End" },
    { LLDP_CHASSIS_ID_TLV, "Chassis ID" },
    { LLDP_PORT_ID_TLV, "Port ID" },
    { LLDP_TTL_TLV, "Time to Live" },
    { LLDP_PORT_DESCR_TLV, "Port Description" },
    { LLDP_SYSTEM_NAME_TLV, "System Name" },
    { LLDP_SYSTEM_DESCR_TLV, "System Description" },
    { LLDP_SYSTEM_CAP_TLV, "System Capabilities" },
    { LLDP_MGMT_ADDR_TLV, "Management Address" },
    { LLDP_PRIVATE_TLV, "Organization specific" },
    { 0, NULL}
};

/*
 * Chassis ID subtypes
 */
#define LLDP_CHASSIS_CHASSIS_COMP_SUBTYPE  1
#define LLDP_CHASSIS_INTF_ALIAS_SUBTYPE    2
#define LLDP_CHASSIS_PORT_COMP_SUBTYPE     3
#define LLDP_CHASSIS_MAC_ADDR_SUBTYPE      4
#define LLDP_CHASSIS_NETWORK_ADDR_SUBTYPE  5
#define LLDP_CHASSIS_INTF_NAME_SUBTYPE     6
#define LLDP_CHASSIS_LOCAL_SUBTYPE         7

static const struct tok lldp_chassis_subtype_values[] = {
    { LLDP_CHASSIS_CHASSIS_COMP_SUBTYPE, "Chassis component"},
    { LLDP_CHASSIS_INTF_ALIAS_SUBTYPE, "Interface alias"},
    { LLDP_CHASSIS_PORT_COMP_SUBTYPE, "Port component"},
    { LLDP_CHASSIS_MAC_ADDR_SUBTYPE, "MAC address"},
    { LLDP_CHASSIS_NETWORK_ADDR_SUBTYPE, "Network address"},
    { LLDP_CHASSIS_INTF_NAME_SUBTYPE, "Interface name"},
    { LLDP_CHASSIS_LOCAL_SUBTYPE, "Local"},
    { 0, NULL}
};

/*
 * Port ID subtypes
 */
#define LLDP_PORT_INTF_ALIAS_SUBTYPE       1
#define LLDP_PORT_PORT_COMP_SUBTYPE        2
#define LLDP_PORT_MAC_ADDR_SUBTYPE         3
#define LLDP_PORT_NETWORK_ADDR_SUBTYPE     4
#define LLDP_PORT_INTF_NAME_SUBTYPE        5
#define LLDP_PORT_AGENT_CIRC_ID_SUBTYPE    6
#define LLDP_PORT_LOCAL_SUBTYPE            7

static const struct tok lldp_port_subtype_values[] = {
    { LLDP_PORT_INTF_ALIAS_SUBTYPE, "Interface alias"},
    { LLDP_PORT_PORT_COMP_SUBTYPE, "Port component"},
    { LLDP_PORT_MAC_ADDR_SUBTYPE, "MAC address"},
    { LLDP_PORT_NETWORK_ADDR_SUBTYPE, "Network Address"},
    { LLDP_PORT_INTF_NAME_SUBTYPE, "Interface Name"},
    { LLDP_PORT_AGENT_CIRC_ID_SUBTYPE, "Agent circuit ID"},
    { LLDP_PORT_LOCAL_SUBTYPE, "Local"},
    { 0, NULL}
};

/*
 * System Capabilities
 */
#define LLDP_CAP_OTHER              (1 <<  0)
#define LLDP_CAP_REPEATER           (1 <<  1)
#define LLDP_CAP_BRIDGE             (1 <<  2)
#define LLDP_CAP_WLAN_AP            (1 <<  3)
#define LLDP_CAP_ROUTER             (1 <<  4)
#define LLDP_CAP_PHONE              (1 <<  5)
#define LLDP_CAP_DOCSIS             (1 <<  6)
#define LLDP_CAP_STATION_ONLY       (1 <<  7)

static const struct tok lldp_cap_values[] = {
    { LLDP_CAP_OTHER, "Other"},
    { LLDP_CAP_REPEATER, "Repeater"},
    { LLDP_CAP_BRIDGE, "Bridge"},
    { LLDP_CAP_WLAN_AP, "WLAN AP"},
    { LLDP_CAP_ROUTER, "Router"},
    { LLDP_CAP_PHONE, "Telephone"},
    { LLDP_CAP_DOCSIS, "Docsis"},
    { LLDP_CAP_STATION_ONLY, "Station Only"},
    { 0, NULL}
};

#define		LLDP_8023_SUTBYPE_1		1
#define		LLDP_8023_SUTBYPE_2		2
#define		LLDP_8023_SUTBYPE_3		3
#define		LLDP_8023_SUTBYPE_4		4

static const struct tok lldp_8023_subtype_values[] = {
    { LLDP_8023_SUTBYPE_1,	"MAC/PHY configuration/status"},
    { LLDP_8023_SUTBYPE_2,	"Power via MDI"},
    { LLDP_8023_SUTBYPE_3,  	"Link aggregation"},
    { LLDP_8023_SUTBYPE_4,	"Max frame size"},
    { 0, NULL}
};

/*
 * From RFC 3636 - dot3MauType
 */
#define		LLDP_MAU_TYPE_UNKNOWN		0
#define		LLDP_MAU_TYPE_AUI		1
#define		LLDP_MAU_TYPE_10BASE_5		2
#define		LLDP_MAU_TYPE_FOIRL		3
#define		LLDP_MAU_TYPE_10BASE_2		4
#define		LLDP_MAU_TYPE_10BASE_T		5
#define		LLDP_MAU_TYPE_10BASE_FP		6
#define		LLDP_MAU_TYPE_10BASE_FB		7
#define		LLDP_MAU_TYPE_10BASE_FL		8
#define		LLDP_MAU_TYPE_10BROAD36		9
#define		LLDP_MAU_TYPE_10BASE_T_HD	10
#define		LLDP_MAU_TYPE_10BASE_T_FD	11
#define		LLDP_MAU_TYPE_10BASE_FL_HD	12
#define		LLDP_MAU_TYPE_10BASE_FL_FD	13
#define		LLDP_MAU_TYPE_100BASE_T4	14
#define		LLDP_MAU_TYPE_100BASE_TX_HD	15
#define		LLDP_MAU_TYPE_100BASE_TX_FD	16
#define		LLDP_MAU_TYPE_100BASE_FX_HD	17
#define		LLDP_MAU_TYPE_100BASE_FX_FD	18
#define		LLDP_MAU_TYPE_100BASE_T2_HD	19
#define		LLDP_MAU_TYPE_100BASE_T2_FD	20
#define		LLDP_MAU_TYPE_1000BASE_X_HD	21
#define		LLDP_MAU_TYPE_1000BASE_X_FD	22
#define		LLDP_MAU_TYPE_1000BASE_LX_HD	23
#define		LLDP_MAU_TYPE_1000BASE_LX_FD	24
#define		LLDP_MAU_TYPE_1000BASE_SX_HD	25
#define		LLDP_MAU_TYPE_1000BASE_SX_FD	26
#define		LLDP_MAU_TYPE_1000BASE_CX_HD	27
#define		LLDP_MAU_TYPE_1000BASE_CX_FD	28
#define		LLDP_MAU_TYPE_1000BASE_T_HD	29
#define		LLDP_MAU_TYPE_1000BASE_T_FD	30
#define		LLDP_MAU_TYPE_10GBASE_X		31
#define		LLDP_MAU_TYPE_10GBASE_LX4	32
#define		LLDP_MAU_TYPE_10GBASE_R		33
#define		LLDP_MAU_TYPE_10GBASE_ER	34
#define		LLDP_MAU_TYPE_10GBASE_LR	35
#define		LLDP_MAU_TYPE_10GBASE_SR	36
#define		LLDP_MAU_TYPE_10GBASE_W		37
#define		LLDP_MAU_TYPE_10GBASE_EW	38
#define		LLDP_MAU_TYPE_10GBASE_LW	39
#define		LLDP_MAU_TYPE_10GBASE_SW	40

static const struct tok lldp_mau_types_values[] = {
    { LLDP_MAU_TYPE_UNKNOWN,            "Unknown"},
    { LLDP_MAU_TYPE_AUI,                "AUI"},
    { LLDP_MAU_TYPE_10BASE_5,           "10BASE_5"},
    { LLDP_MAU_TYPE_FOIRL,              "FOIRL"},
    { LLDP_MAU_TYPE_10BASE_2,           "10BASE2"},
    { LLDP_MAU_TYPE_10BASE_T,           "10BASET duplex mode unknown"},
    { LLDP_MAU_TYPE_10BASE_FP,          "10BASEFP"},
    { LLDP_MAU_TYPE_10BASE_FB,          "10BASEFB"},
    { LLDP_MAU_TYPE_10BASE_FL,          "10BASEFL duplex mode unknown"},
    { LLDP_MAU_TYPE_10BROAD36,          "10BROAD36"},
    { LLDP_MAU_TYPE_10BASE_T_HD,        "10BASET hdx"},
    { LLDP_MAU_TYPE_10BASE_T_FD,        "10BASET fdx"},
    { LLDP_MAU_TYPE_10BASE_FL_HD,       "10BASEFL hdx"},
    { LLDP_MAU_TYPE_10BASE_FL_FD,       "10BASEFL fdx"},
    { LLDP_MAU_TYPE_100BASE_T4,         "100BASET4"},
    { LLDP_MAU_TYPE_100BASE_TX_HD,      "100BASETX hdx"},
    { LLDP_MAU_TYPE_100BASE_TX_FD,      "100BASETX fdx"},
    { LLDP_MAU_TYPE_100BASE_FX_HD,      "100BASEFX hdx"},
    { LLDP_MAU_TYPE_100BASE_FX_FD,      "100BASEFX fdx"},
    { LLDP_MAU_TYPE_100BASE_T2_HD,      "100BASET2 hdx"},
    { LLDP_MAU_TYPE_100BASE_T2_FD,      "100BASET2 fdx"},
    { LLDP_MAU_TYPE_1000BASE_X_HD,      "1000BASEX hdx"},
    { LLDP_MAU_TYPE_1000BASE_X_FD,      "1000BASEX fdx"},
    { LLDP_MAU_TYPE_1000BASE_LX_HD,     "1000BASELX hdx"},
    { LLDP_MAU_TYPE_1000BASE_LX_FD,     "1000BASELX fdx"},
    { LLDP_MAU_TYPE_1000BASE_SX_HD,     "1000BASESX hdx"},
    { LLDP_MAU_TYPE_1000BASE_SX_FD,     "1000BASESX fdx"},
    { LLDP_MAU_TYPE_1000BASE_CX_HD,     "1000BASECX hdx"},
    { LLDP_MAU_TYPE_1000BASE_CX_FD,     "1000BASECX fdx"},
    { LLDP_MAU_TYPE_1000BASE_T_HD,      "1000BASET hdx"},
    { LLDP_MAU_TYPE_1000BASE_T_FD,      "1000BASET fdx"},
    { LLDP_MAU_TYPE_10GBASE_X,          "10GBASEX"},
    { LLDP_MAU_TYPE_10GBASE_LX4,        "10GBASELX4"},
    { LLDP_MAU_TYPE_10GBASE_R,          "10GBASER"},
    { LLDP_MAU_TYPE_10GBASE_ER,         "10GBASEER"},
    { LLDP_MAU_TYPE_10GBASE_LR,         "10GBASELR"},
    { LLDP_MAU_TYPE_10GBASE_SR,         "10GBASESR"},
    { LLDP_MAU_TYPE_10GBASE_W,          "10GBASEW"},
    { LLDP_MAU_TYPE_10GBASE_EW,         "10GBASEEW"},
    { LLDP_MAU_TYPE_10GBASE_LW,         "10GBASELW"},
    { LLDP_MAU_TYPE_10GBASE_SW,         "10GBASESW"},
    { 0, NULL}
};

#define LLDP_8023_AUTONEGOTIATION_SUPPORT       (1 <<  0)
#define LLDP_8023_AUTONEGOTIATION_STATUS        (1 <<  1)

static const struct tok lldp_8023_autonegotiation_values[] = {
    { LLDP_8023_AUTONEGOTIATION_SUPPORT, "supported"},
    { LLDP_8023_AUTONEGOTIATION_STATUS, "enabled"},
    { 0, NULL}
};

/*
 * From RFC 3636 - ifMauAutoNegCapAdvertisedBits
 */ 
#define	 LLDP_MAU_PMD_OTHER			(1 <<  0)
#define	 LLDP_MAU_PMD_10BASE_T			(1 <<  1)
#define	 LLDP_MAU_PMD_10BASE_T_FD		(1 <<  2)
#define	 LLDP_MAU_PMD_100BASE_T4		(1 <<  3)
#define	 LLDP_MAU_PMD_100BASE_TX		(1 <<  4)
#define	 LLDP_MAU_PMD_100BASE_TX_FD		(1 <<  5)
#define	 LLDP_MAU_PMD_100BASE_T2		(1 <<  6)
#define	 LLDP_MAU_PMD_100BASE_T2_FD		(1 <<  7)
#define	 LLDP_MAU_PMD_FDXPAUSE			(1 <<  8)
#define	 LLDP_MAU_PMD_FDXAPAUSE			(1 <<  9)
#define	 LLDP_MAU_PMD_FDXSPAUSE			(1 <<  10)
#define	 LLDP_MAU_PMD_FDXBPAUSE			(1 <<  11)
#define	 LLDP_MAU_PMD_1000BASE_X		(1 <<  12)
#define	 LLDP_MAU_PMD_1000BASE_X_FD		(1 <<  13)
#define	 LLDP_MAU_PMD_1000BASE_T		(1 <<  14)
#define	 LLDP_MAU_PMD_1000BASE_T_FD		(1 <<  15)

static const struct tok lldp_pmd_capability_values[] = {
    { LLDP_MAU_PMD_10BASE_T,		"10BASE-T hdx"},
    { LLDP_MAU_PMD_10BASE_T_FD,	        "10BASE-T fdx"},
    { LLDP_MAU_PMD_100BASE_T4,		"100BASE-T4"},
    { LLDP_MAU_PMD_100BASE_TX,		"100BASE-TX hdx"},
    { LLDP_MAU_PMD_100BASE_TX_FD,	"100BASE-TX fdx"},
    { LLDP_MAU_PMD_100BASE_T2,		"100BASE-T2 hdx"},
    { LLDP_MAU_PMD_100BASE_T2_FD,	"100BASE-T2 fdx"},
    { LLDP_MAU_PMD_FDXPAUSE,		"Pause for fdx links"},
    { LLDP_MAU_PMD_FDXAPAUSE,		"Asym PAUSE for fdx"},
    { LLDP_MAU_PMD_FDXSPAUSE,		"Sym PAUSE for fdx"},
    { LLDP_MAU_PMD_FDXBPAUSE,		"Asym and Sym PAUSE for fdx"},
    { LLDP_MAU_PMD_1000BASE_X,		"1000BASE-{X LX SX CX} hdx"},
    { LLDP_MAU_PMD_1000BASE_X_FD,	"1000BASE-{X LX SX CX} fdx"},
    { LLDP_MAU_PMD_1000BASE_T,		"1000BASE-T hdx"},
    { LLDP_MAU_PMD_1000BASE_T_FD,	"1000BASE-T fdx"},
    { 0, NULL}
};

#define	LLDP_MDI_PORT_CLASS			(1 <<  0)
#define	LLDP_MDI_POWER_SUPPORT			(1 <<  1)
#define LLDP_MDI_POWER_STATE			(1 <<  2)
#define LLDP_MDI_PAIR_CONTROL_ABILITY		(1 <<  3)

static const struct tok lldp_mdi_values[] = {
    { LLDP_MDI_PORT_CLASS, 		"PSE"},
    { LLDP_MDI_POWER_SUPPORT, 		"supported"},
    { LLDP_MDI_POWER_STATE, 		"enabled"},
    { LLDP_MDI_PAIR_CONTROL_ABILITY, 	"can be controlled"},
    { 0, NULL}
};

#define LLDP_MDI_PSE_PORT_POWER_PAIRS_SIGNAL	1
#define LLDP_MDI_PSE_PORT_POWER_PAIRS_SPARE	2

static const struct tok lldp_mdi_power_pairs_values[] = {
    { LLDP_MDI_PSE_PORT_POWER_PAIRS_SIGNAL,	"signal"},
    { LLDP_MDI_PSE_PORT_POWER_PAIRS_SPARE,	"spare"},
    { 0, NULL}
};

#define LLDP_MDI_POWER_CLASS0		1
#define LLDP_MDI_POWER_CLASS1		2
#define LLDP_MDI_POWER_CLASS2		3
#define LLDP_MDI_POWER_CLASS3		4
#define LLDP_MDI_POWER_CLASS4		5

static const struct tok lldp_mdi_power_class_values[] = {
    { LLDP_MDI_POWER_CLASS0,     "class0"},
    { LLDP_MDI_POWER_CLASS1,     "class1"},
    { LLDP_MDI_POWER_CLASS2,     "class2"},
    { LLDP_MDI_POWER_CLASS3,     "class3"},
    { LLDP_MDI_POWER_CLASS4,     "class4"},
    { 0, NULL}
};

#define LLDP_AGGREGATION_CAPABILTIY     (1 <<  0)
#define LLDP_AGGREGATION_STATUS         (1 <<  1)

static const struct tok lldp_aggregation_values[] = {
    { LLDP_AGGREGATION_CAPABILTIY,   	"supported"},
    { LLDP_AGGREGATION_STATUS,    	"enabled"},
    { 0, NULL}
};

/*
 * Interface numbering subtypes.
 */
#define LLDP_INTF_NUMB_IFX_SUBTYPE         2
#define LLDP_INTF_NUMB_SYSPORT_SUBTYPE     3

static const struct tok lldp_intf_numb_subtype_values[] = {
    { LLDP_INTF_NUMB_IFX_SUBTYPE, "Interface Index" },
    { LLDP_INTF_NUMB_SYSPORT_SUBTYPE, "System Port Number" },
    { 0, NULL}
};

#define LLDP_INTF_NUM_LEN                  5


static char *
lldp_network_addr_print(const u_char *tptr) {

    u_int8_t af;
    static char buf[BUFSIZE];
    const char * (*pfunc)(const u_char *);

    af = *tptr;
    switch (af) {
    case AFNUM_INET:
        pfunc = getname; 
        break;
#ifdef INET6
    case AFNUM_INET6:
        pfunc = getname6;
        break;
#endif
    case AFNUM_802:
        pfunc = etheraddr_string;
        break;
    default:
        pfunc = NULL;
        break;
    }

    if (!pfunc) {
        snprintf(buf, sizeof(buf), "AFI %s (%u) XXX",
                 tok2str(af_values, "Unknown", af), af);
    } else {
        snprintf(buf, sizeof(buf), "AFI %s (%u): %s",
                 tok2str(af_values, "Unknown", af), af, (*pfunc)(tptr+1));
    }

    return buf;
}

static int
lldp_mgmt_addr_tlv_print(const u_char *pptr, u_int len) {

    u_int8_t mgmt_addr_len, intf_num_subtype, oid_len;
    const u_char *tptr;
    u_int tlen;
    
    tlen = len;
    tptr = pptr;

    mgmt_addr_len = *tptr++;
    tlen--;

    if (tlen < mgmt_addr_len) {
        return 0;
    }

    printf("\n\t  Management Address length %u, %s",
           mgmt_addr_len,
           lldp_network_addr_print(tptr));
    tptr += mgmt_addr_len;
    tlen -= mgmt_addr_len;

    if (tlen < LLDP_INTF_NUM_LEN) {
        return 0;
    }

    intf_num_subtype = *tptr;
    printf("\n\t  %s Interface Numbering (%u): %u",
           tok2str(lldp_intf_numb_subtype_values, "Unknown", intf_num_subtype),
           intf_num_subtype,
           EXTRACT_32BITS(tptr+1));

    tptr += LLDP_INTF_NUM_LEN;
    tlen -= LLDP_INTF_NUM_LEN;

    /*
     * The OID is optional.
     */
    if (tlen) {
        oid_len = *tptr;

        if (oid_len) {
            printf("\n\t  OID length %u", oid_len);
            safeputs((const char *)tptr+1, oid_len);
        }
    }

    return 1;
} 

void
lldp_print(register const u_char *pptr, register u_int len) {

    u_int8_t subtype;
    u_int16_t tlv, cap, ena_cap;
    u_int oui, tlen, hexdump, tlv_type, tlv_len;
    const u_char *tptr;
    
    tptr = pptr;
    tlen = len;

    if (vflag) {
        printf("LLDP, length %u", len);
    }

    while (tlen >= sizeof(tlv)) {

        TCHECK2(*tptr, sizeof(tlv));

        tlv = EXTRACT_16BITS(tptr);

        tlv_type = LLDP_EXTRACT_TYPE(tlv);
        tlv_len = LLDP_EXTRACT_LEN(tlv);
        hexdump = FALSE;

        tlen -= sizeof(tlv);
        tptr += sizeof(tlv);

        if (vflag) {
            printf("\n\t%s TLV (%u), length %u",
                   tok2str(lldp_tlv_values, "Unknown", tlv_type),
                   tlv_type, tlv_len);
        }

        /* infinite loop check */
        if (!tlv_type || !tlv_len) {
            break;
        }

        TCHECK2(*tptr, tlv_len);

        switch (tlv_type) {
        case LLDP_TTL_TLV:
            if (vflag) {
                printf(": TTL %us", EXTRACT_16BITS(tptr));
            }
            break;

        case LLDP_SYSTEM_NAME_TLV:

            /*
             * The system name is also print in non-verbose mode
             * similar to the CDP printer.
             */
            if (vflag) {
                printf(": ");
                safeputs((const char *)tptr, tlv_len);
            } else {
                printf("LLDP, name ");
                safeputs((const char *)tptr, tlv_len);
                printf(", length %u", len);
            }
            break;

        case LLDP_PORT_DESCR_TLV:
            if (vflag) {
                printf(": ");
                safeputs((const char *)tptr, tlv_len);
            }
            break;

        case LLDP_SYSTEM_DESCR_TLV:
            if (vflag) {
                printf("\n\t  ");
                safeputs((const char *)tptr, tlv_len);
            }
            break;


        case LLDP_CHASSIS_ID_TLV:
            if (vflag) {
                subtype = *tptr;
                printf("\n\t  Subtype %s (%u): ",
                       tok2str(lldp_chassis_subtype_values, "Unknown", subtype),
                       subtype);

                switch (subtype) {
                case LLDP_CHASSIS_MAC_ADDR_SUBTYPE:
                    printf("%s", etheraddr_string(tptr+1));
                    break;

                case LLDP_CHASSIS_INTF_NAME_SUBTYPE: /* fall through */
                case LLDP_CHASSIS_LOCAL_SUBTYPE:
                case LLDP_CHASSIS_CHASSIS_COMP_SUBTYPE:
                case LLDP_CHASSIS_INTF_ALIAS_SUBTYPE:
                case LLDP_CHASSIS_PORT_COMP_SUBTYPE:
                    safeputs((const char *)tptr+1, tlv_len-1);
                    break;

                case LLDP_CHASSIS_NETWORK_ADDR_SUBTYPE:
                    printf("%s", lldp_network_addr_print(tptr+1));
                    break;

                default:
                    hexdump = TRUE;
                    break;
                }
            }
            break;

        case LLDP_PORT_ID_TLV:
            if (vflag) {
                subtype = *tptr;
                printf("\n\t  Subtype %s (%u): ",
                       tok2str(lldp_port_subtype_values, "Unknown", subtype),
                       subtype);

                switch (subtype) {
                case LLDP_PORT_MAC_ADDR_SUBTYPE:
                    printf("%s", etheraddr_string(tptr+1));
                    break;

                case LLDP_PORT_INTF_NAME_SUBTYPE: /* fall through */
                case LLDP_PORT_LOCAL_SUBTYPE:
                case LLDP_PORT_AGENT_CIRC_ID_SUBTYPE:
                case LLDP_PORT_INTF_ALIAS_SUBTYPE:
                case LLDP_PORT_PORT_COMP_SUBTYPE:
                    safeputs((const char *)tptr+1, tlv_len-1);
                    break;

                case LLDP_PORT_NETWORK_ADDR_SUBTYPE:
                    printf("%s", lldp_network_addr_print(tptr+1));
                    break;

                default:
                    hexdump = TRUE;
                    break;
                }
            }
            break;

        case LLDP_PRIVATE_TLV:
            if (vflag) {
		int subtype;
                oui = EXTRACT_24BITS(tptr);
                printf(": OUI %s (0x%06x)", tok2str(oui_values, "Unknown", oui), oui);
                hexdump = TRUE;
                
		if (oui == OUI_IEEE_PRIVATE) {

                    hexdump = FALSE;
		    subtype = *(tptr+3);

	  	    printf("\n\t  %s Subtype (%u)",
                           tok2str(lldp_8023_subtype_values, "unknown", subtype),
                           subtype);

		    switch (subtype) {
                    case LLDP_8023_SUTBYPE_1:
                        printf("\n\t    autonegotiation [%s] (0x%02x)",
                               bittok2str(lldp_8023_autonegotiation_values,"none",*(tptr+4)),
                               *(tptr+4));
                        printf("\n\t    PMD autoneg capability [%s] (0x%04x)",
                               bittok2str(lldp_pmd_capability_values,"unknown",EXTRACT_16BITS(tptr+5)),
                               EXTRACT_16BITS(tptr+5));
                        printf("\n\t    MAU type %s (0x%04x)",
                               tok2str(lldp_mau_types_values, "unknown", EXTRACT_16BITS(tptr+7)),
                               EXTRACT_16BITS(tptr+7));
                        break;

                    case LLDP_8023_SUTBYPE_2:
                        printf("\n\t    MDI power support [%s], power pair %s, power class %s",
                               bittok2str(lldp_mdi_values, "none", *(tptr+4)),
                               tok2str(lldp_mdi_power_pairs_values, "unknown", *(tptr+5)),
                               tok2str(lldp_mdi_power_class_values, "unknown", *(tptr+6)));
                        break;

                    case LLDP_8023_SUTBYPE_3:
                        printf("\n\t    aggregation status [%s], aggregation port ID %u",
                               bittok2str(lldp_aggregation_values, "none", (*tptr+4)),
                               EXTRACT_32BITS(tptr+5));
                        break;

                    case LLDP_8023_SUTBYPE_4:
                        printf("\n\t    MTU size %u",
                               EXTRACT_16BITS(tptr+4));
                        break;

                    default:
                        hexdump = TRUE;
                        break;
                    }
                }
            }
            break;

        case LLDP_SYSTEM_CAP_TLV:
            if (vflag) {
                cap = EXTRACT_16BITS(tptr);
                ena_cap = EXTRACT_16BITS(tptr+2);
                printf("\n\t  System  Capabilities [%s] (0x%04x)",
                       bittok2str(lldp_cap_values, "none", cap), cap);
                printf("\n\t  Enabled Capabilities [%s] (0x%04x)",
                       bittok2str(lldp_cap_values, "none", ena_cap), ena_cap);
            }
            break;

        case LLDP_MGMT_ADDR_TLV:
            if (vflag) {
                if (!lldp_mgmt_addr_tlv_print(tptr, tlen)) {
                    goto trunc;
                }
            }
            break;

        default:
            hexdump = TRUE;
            break;
        }

        /* do we also want to see a hex dump ? */
        if (vflag > 1 || (vflag && hexdump)) {
            print_unknown_data(tptr,"\n\t  ", tlv_len);
        }

        tlen -= tlv_len;
        tptr += tlv_len;
    }
    return;
 trunc:
    printf("\n\t[|LLDP]");
}

/*
 * Local Variables:
 * c-style: whitesmith
 * c-basic-offset: 4
 * End:
 */
