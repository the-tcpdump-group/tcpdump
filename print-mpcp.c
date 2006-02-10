/*
 * Copyright (c) 1998-2006 The TCPDUMP project
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
 * support for the IEEE MPCP protocol as per 802.3ah
 *
 * Original code by Hannes Gredler (hannes@juniper.net)
 */

#ifndef lint
static const char rcsid[] _U_ =
    "@(#) $Header: /tcpdump/master/tcpdump/print-mpcp.c,v 1.1 2006-02-10 04:52:25 hannes Exp $";
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
#include "ether.h"

struct mpcp_common_header_t {
    u_int8_t opcode[2];
    u_int8_t timestamp[4];
};

#define	MPCP_OPCODE_PAUSE        0x0001
#define	MPCP_OPCODE_GATE         0x0002
#define	MPCP_OPCODE_REPORT       0x0003
#define	MPCP_OPCODE_REGISTER_REQ 0x0004
#define	MPCP_OPCODE_REGISTER     0x0005
#define	MPCP_OPCODE_REGISTER_ACK 0x0006

static const struct tok mpcp_opcode_values[] = {
    { MPCP_OPCODE_PAUSE, "Pause" },
    { MPCP_OPCODE_GATE, "Gate" },
    { MPCP_OPCODE_REPORT, "Report" },
    { MPCP_OPCODE_REGISTER_REQ, "Register Request" },
    { MPCP_OPCODE_REGISTER, "Register" },
    { MPCP_OPCODE_REGISTER_ACK, "Register ACK" },
    { 0, NULL}
};

#define	MPCP_GRANT_NUMBER_MASK 0x7 
static const struct tok mpcp_grant_flag_values[] = {
    { 0x08, "Discovery" },
    { 0x10, "Force Grant #1" },
    { 0x20, "Force Grant #2" },
    { 0x40, "Force Grant #3" },
    { 0x80, "Force Grant #4" },
    { 0, NULL}
};

struct mpcp_grant_t {
    u_int8_t starttime[4];
    u_int8_t length[2];
};

static const struct tok mpcp_register_req_flag_values[] = {
    { 1, "Register" },
    { 3, "De-Register" },
    { 0, NULL}
};

static const struct tok mpcp_register_flag_values[] = {
    { 1, "Re-Register" },
    { 2, "De-Register" },
    { 3, "ACK" },
    { 4, "NACK" },
    { 0, NULL}
};

static const struct tok mpcp_register_ack_flag_values[] = {
    { 0, "NACK" },
    { 1, "ACK" },
    { 0, NULL}
};

void
mpcp_print(register const u_char *pptr, register u_int length) {

    union {
        const struct mpcp_common_header_t *common_header;
        const struct mpcp_grant_t *grant;
    } mpcp;


    const u_char *tptr;
    u_int16_t opcode;
    u_int8_t grant_numbers, grant;

    tptr=pptr;
    mpcp.common_header = (const struct mpcp_common_header_t *)pptr;
    TCHECK(*mpcp.common_header);

    opcode = EXTRACT_16BITS(mpcp.common_header->opcode);

    printf("MPCP, Opcode %s", tok2str(mpcp_opcode_values, "Unknown (%u)", opcode));
    if (opcode != MPCP_OPCODE_PAUSE) {
        printf(", Timestamp %u", EXTRACT_32BITS(mpcp.common_header->timestamp));
    }
    printf(", length %u", length);

    if (!vflag)
        return;

    tptr += sizeof(const struct mpcp_common_header_t);

    switch (opcode) {
    case MPCP_OPCODE_PAUSE:
        break;

    case MPCP_OPCODE_GATE:
        grant_numbers = *tptr & MPCP_GRANT_NUMBER_MASK;
        printf("\n\tGrant Numbers %u, Flags [ %s ]",
               grant_numbers,
               bittok2str(mpcp_grant_flag_values,
                          "?",
                          *tptr &~ MPCP_GRANT_NUMBER_MASK));
        tptr++;

        for (grant = 1; grant <= grant_numbers; grant++) {
            mpcp.grant = (const struct mpcp_grant_t *)tptr;        
            printf("\n\tGrant #%u, Start-Time %u, length %u",
                   grant,
                   EXTRACT_32BITS(mpcp.grant->starttime),
                   EXTRACT_16BITS(mpcp.grant->length));
            tptr += sizeof(const struct mpcp_grant_t);
        }

        printf("\n\tSync-Time %u", EXTRACT_16BITS(tptr));
        break;

        /* FIXME */
    case MPCP_OPCODE_REPORT:
    case MPCP_OPCODE_REGISTER_REQ:
    case MPCP_OPCODE_REGISTER:
    case MPCP_OPCODE_REGISTER_ACK:
    default:
        break;
    }

    return;
trunc:
    printf("\n\t[|MPCP]");
}
