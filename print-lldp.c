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
"@(#) $Header: /tcpdump/master/tcpdump/print-lldp.c,v 1.2 2007-08-08 14:39:52 hannes Exp $";
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
#define LLDP_CAP_OTHER               1 <<  0
#define LLDP_CAP_REPEATER            1 <<  1
#define LLDP_CAP_BRIDGE              1 <<  2
#define LLDP_CAP_WLAN_AP             1 <<  3
#define LLDP_CAP_ROUTER              1 <<  4
#define LLDP_CAP_PHONE               1 <<  5
#define LLDP_CAP_DOCSIS              1 <<  6
#define LLDP_CAP_STATION_ONLY        1 <<  7

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


static char *
lldp_network_addr_print(const u_char *tptr) {

    u_int8_t af;
    static char buf[BUFSIZE];
    const char * (*pfunc)(const u_char *);

    af = *(tptr);
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
lldp_mgmt_addr_tlv_print(const u_char *pptr, u_int len)  {

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

    if (tlen < 5) {
        return 0;
    }

    intf_num_subtype = *tptr;
    printf("\n\t  %s Interface Numbering (%u): %u",
           tok2str(lldp_intf_numb_subtype_values, "Unknown", intf_num_subtype),
           intf_num_subtype,
           EXTRACT_32BITS(tptr+1));
    tptr += 5;
    tlen -= 5;

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

                oui = EXTRACT_24BITS(tptr);
                printf(": OUI %s (0x%06x)", tok2str(oui_values, "Unknown", oui), oui);
                hexdump = TRUE;
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
