/*
 * Copyright (c) 1998-2004  Hannes Gredler <hannes@tcpdump.org>
 *      The TCPDUMP project
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
 */

#ifndef lint
static const char rcsid[] _U_ =
    "@(#) $Header: /tcpdump/master/tcpdump/print-eigrp.c,v 1.1 2004-04-30 22:22:04 hannes Exp $";
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

/*
 * packet format documented at
 * http://www.rhyshaden.com/eigrp.htm
 */

struct eigrp_common_header {
    u_int8_t version;
    u_int8_t opcode;
    u_int8_t checksum[2];
    u_int8_t flags[4];
    u_int8_t seq[4];
    u_int8_t ack[4];
    u_int8_t asn[4];
};

#define	EIGRP_VERSION                        2

#define	EIGRP_OPCODE_UPDATE                  1
#define	EIGRP_OPCODE_QUERY                   3
#define	EIGRP_OPCODE_REPLY                   4
#define	EIGRP_OPCODE_HELLO                   5
#define	EIGRP_OPCODE_IPXSAP                  6
#define	EIGRP_OPCODE_PROBE                   7

static const struct tok eigrp_opcode_values[] = {
    { EIGRP_OPCODE_UPDATE, "Update" },
    { EIGRP_OPCODE_QUERY, "Query" },
    { EIGRP_OPCODE_REPLY, "Reply" },
    { EIGRP_OPCODE_HELLO, "Hello" },
    { EIGRP_OPCODE_IPXSAP, "IPX SAP" },
    { EIGRP_OPCODE_PROBE, "Probe" },
    { 0, NULL}
};

struct eigrp_tlv_header {
    u_int8_t type[2];
    u_int8_t length[2];
};

#define EIGRP_TLV_GENERAL_PARM   0x0001
#define EIGRP_TLV_SEQ            0x0003
#define EIGRP_TLV_SW_VERSION     0x0004
#define EIGRP_TLV_MCAST_SEQ      0x0005
#define EIGRP_TLV_IP_INT         0x0102
#define EIGRP_TLV_IP_EXT         0x0103
#define EIGRP_TLV_AT_INT         0x0202
#define EIGRP_TLV_AT_EXT         0x0203
#define EIGRP_TLV_AT_CABLE_SETUP 0x0204
#define EIGRP_TLV_IPX_INT        0x0302
#define EIGRP_TLV_IPX_EXT        0x0303

static const struct tok eigrp_tlv_values[] = {
    { EIGRP_TLV_GENERAL_PARM, "General Parameters"},
    { EIGRP_TLV_SEQ, "Sequence"},
    { EIGRP_TLV_SW_VERSION, "Software Version"},
    { EIGRP_TLV_MCAST_SEQ, "Next Multicast Sequence"},
    { EIGRP_TLV_IP_INT, "IP Internal routes"},
    { EIGRP_TLV_IP_EXT, "IP External routes"},
    { EIGRP_TLV_AT_INT, "AppleTalk Internal routes"},
    { EIGRP_TLV_AT_EXT, "AppleTalk External routes"},
    { EIGRP_TLV_AT_CABLE_SETUP, "AppleTalk Cable setup"},
    { EIGRP_TLV_IPX_INT, "IPX Internal routes"},
    { EIGRP_TLV_IPX_EXT, "IPX External routes"},
    { 0, NULL}
};

void
eigrp_print(register const u_char *pptr, register u_int len) {

    const struct eigrp_common_header *eigrp_com_header;
    const struct eigrp_tlv_header *eigrp_tlv_header;
    const u_char *tptr,*obj_tptr;
    int tlen,eigrp_tlv_len,eigrp_tlv_type,obj_tlen;

    tptr=pptr;
    eigrp_com_header = (const struct eigrp_common_header *)pptr;
    TCHECK(*eigrp_com_header);

    /*
     * Sanity checking of the header.
     */
    if (eigrp_com_header->version != EIGRP_VERSION) {
	printf("EIGRP version %u packet not supported",eigrp_com_header->version);
	return;
    }

    /* in non-verbose mode just lets print the basic Message Type*/
    if (vflag < 1) {
        printf("EIGRP %s, length: %u",
               tok2str(eigrp_opcode_values, "unknown (%u)",eigrp_com_header->opcode),
               len);
        return;
    }

    /* ok they seem to want to know everything - lets fully decode it */

    tlen=len-sizeof(struct eigrp_common_header);

    /* FIXME print other header info */
    printf("\n\tEIGRP v%u, opcode: %s (%u), chksum: 0x%04x, Flags: [0x%08x]\n\tseq: 0x%08x, ack: 0x%08x, AS: %u, length: %u",
           eigrp_com_header->version,
           tok2str(eigrp_opcode_values, "unknown, type: %u",eigrp_com_header->opcode),
           eigrp_com_header->opcode,
           EXTRACT_16BITS(&eigrp_com_header->checksum),
           EXTRACT_32BITS(&eigrp_com_header->flags),
           EXTRACT_32BITS(&eigrp_com_header->seq),
           EXTRACT_32BITS(&eigrp_com_header->ack),
           EXTRACT_32BITS(&eigrp_com_header->asn),
           tlen);

    tptr+=sizeof(const struct eigrp_common_header);

    while(tlen>0) {
        /* did we capture enough for fully decoding the object header ? */
        if (!TTEST2(*tptr, sizeof(struct eigrp_tlv_header)))
            goto trunc;

        eigrp_tlv_header = (const struct eigrp_tlv_header *)tptr;
        eigrp_tlv_len=EXTRACT_16BITS(&eigrp_tlv_header->length);
        eigrp_tlv_type=EXTRACT_16BITS(&eigrp_tlv_header->type);


        if (eigrp_tlv_len == 0 || eigrp_tlv_len > tlen) {
            print_unknown_data(tptr+sizeof(sizeof(struct eigrp_tlv_header)),"\n\t    ",tlen);
            return;
        }

        printf("\n\t  %s TLV (0x%04x), length: %u",
               tok2str(eigrp_tlv_values,
                       "Unknown",
                       eigrp_tlv_type),
               eigrp_tlv_type,
               eigrp_tlv_len);

        obj_tptr=tptr+sizeof(struct eigrp_tlv_header);
        obj_tlen=eigrp_tlv_len-sizeof(struct eigrp_tlv_header);

        /* did we capture enough for fully decoding the object ? */
        if (!TTEST2(*tptr, eigrp_tlv_len))
            goto trunc;

        switch(eigrp_tlv_type) {

            /*
             * FIXME those are the defined TLVs that lack a decoder
             * you are welcome to contribute code ;-)
             */

        case EIGRP_TLV_GENERAL_PARM:
        case EIGRP_TLV_SEQ:
        case EIGRP_TLV_SW_VERSION:
        case EIGRP_TLV_MCAST_SEQ:
        case EIGRP_TLV_IP_INT:
        case EIGRP_TLV_IP_EXT:
        case EIGRP_TLV_AT_INT:
        case EIGRP_TLV_AT_EXT:
        case EIGRP_TLV_AT_CABLE_SETUP:
        case EIGRP_TLV_IPX_INT:
        case EIGRP_TLV_IPX_EXT:

        default:
            if (vflag <= 1)
                print_unknown_data(obj_tptr,"\n\t    ",obj_tlen);
            break;
        }
        /* do we want to see an additionally hexdump ? */
        if (vflag > 1)
            print_unknown_data(tptr+sizeof(sizeof(struct eigrp_tlv_header)),"\n\t    ",
                               eigrp_tlv_len-sizeof(struct eigrp_tlv_header));

        tptr+=eigrp_tlv_len;
        tlen-=eigrp_tlv_len;
    }
    return;
trunc:
    printf("\n\t\t packet exceeded snapshot");
}
