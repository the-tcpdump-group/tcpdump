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
    "@(#) $Header: /tcpdump/master/tcpdump/print-lldp.c,v 1.1 2007-08-03 11:03:19 hannes Exp $";
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

#define	LLDP_EXTRACT_TYPE(x) (((x)&0xfe00)>>9) 
#define	LLDP_EXTRACT_LEN(x) ((x)&0x01ff) 

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

void lldp_print(register const u_char *pptr, register u_int len) {

    u_int16_t tlv;
    u_int tlen, hexdump, tlv_type, tlv_len;
    const u_char *tptr;
    
    tptr = pptr;
    tlen = len;

    printf("LLDP, length %u", len);

    if (!vflag) {
        return;
    }

    while (tlen >= sizeof(tlv)) {

        TCHECK2(*tptr, sizeof(tlv));

        tlv = EXTRACT_16BITS(tptr);

        tlv_type = LLDP_EXTRACT_TYPE(tlv);
        tlv_len = LLDP_EXTRACT_LEN(tlv);
        hexdump = FALSE;

        tlen -= sizeof(tlv);
        tptr += sizeof(tlv);

        printf("\n\t%s TLV (%u), length %u",
               tok2str(lldp_tlv_values, "Unknown", tlv_type),
               tlv_type, tlv_len);

        /* infinite loop check */
        if (!tlv_type || !tlv_len) {
            break;
        }

        TCHECK2(*tptr, tlv_len);

        switch (tlv_type) {
        case LLDP_TTL_TLV:
            printf(", TTL %us", EXTRACT_16BITS(tptr));
            break;

        case LLDP_SYSTEM_NAME_TLV:
        case LLDP_PORT_DESCR_TLV:
            printf(", ");
            safeputs((const char *)tptr, tlv_len);
            break;

        case LLDP_SYSTEM_DESCR_TLV:
            printf("\n\t  ");
            safeputs((const char *)tptr, tlv_len);
            break;

        default:
            hexdump = TRUE;
        }

        /* do we also want to see a hex dump ? */
        if (vflag > 1 || hexdump) {
            print_unknown_data(tptr,"\n\t  ", tlv_len);
        }

        tlen -= tlv_len;
        tptr += tlv_len;
    }
    return;
 trunc:
    printf("\n\t[|LLDP]");
}
