/*
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
 * Original code by Hannes Gredler (hannes@juniper.net)
 */

#ifndef lint
static const char rcsid[] =
    "@(#) $Header: /tcpdump/master/tcpdump/print-ldp.c,v 1.1 2002-12-13 00:40:35 hannes Exp $";
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
#include "ethertype.h"

/*
 * ldp common header
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  Version                      |         PDU Length            |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                         LDP Identifier                        |
 * +                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

struct ldp_common_header {
    u_int8_t version[2];
    u_int8_t pdu_length[2];
    u_int8_t lsr_id[4];
    u_int8_t label_space[2];
};

#define LDP_VERSION 1

/* 
 * ldp tlv header
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |U|F|        Type               |            Length             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                                                               |
 * |                             Value                             |
 * ~                                                               ~
 * |                                                               |
 * |                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

struct ldp_tlv_header {
    u_int8_t type[2];
    u_int8_t length[2];
};

#define	LDP_MASK_TLV_TYPE(x)  ((x)&0x3fff) 
#define	LDP_MASK_TLV_U_BIT(x) ((x)&0x8000) 
#define	LDP_MASK_TLV_F_BIT(x) ((x)&0x4000) 

#define	LDP_TLV_FEC            0x0100
#define	LDP_TLV_ADDRESS_LIST   0x0101
#define	LDP_TLV_HOP_COUNT      0x0103
#define	LDP_TLV_PATH_VECTOR    0x0104
#define	LDP_TLV_GENERIC_LABEL  0x0200
#define	LDP_TLV_ATM_LABEL      0x0201
#define	LDP_TLV_FR_LABEL       0x0202
#define	LDP_TLV_STATUS         0x0300

static const struct tok ldp_tlv_values[] = {
    { LDP_TLV_FEC,	       "FEC" },
    { LDP_TLV_ADDRESS_LIST,    "Address List" },
    { LDP_TLV_HOP_COUNT,       "Hop Count" },
    { LDP_TLV_HOP_COUNT,       "Path Vector" },
    { LDP_TLV_GENERIC_LABEL,   "Generic Label" },
    { LDP_TLV_ATM_LABEL,       "ATM Label" },
    { LDP_TLV_FR_LABEL,        "Frame-Relay Label" },
    { LDP_TLV_STATUS,          "Status" },
    { 0, NULL}
};

#define FALSE 0
#define TRUE  1

void
ldp_print(register const u_char *pptr, register u_int len) {

    const struct ldp_common_header *ldp_com_header;
    const struct ldp_tlv_header *ldp_tlv_header;
    const u_char *tptr,*tlv_tptr;
    u_short tlen,tlv_len,tlv_type,tlv_tlen;
    int hexdump;

    tptr=pptr;
    ldp_com_header = (const struct ldp_common_header *)pptr;
    TCHECK(*ldp_com_header);

    /*
     * Sanity checking of the header.
     */
    if (EXTRACT_16BITS(&ldp_com_header->version) != LDP_VERSION) {
	printf("LDP version %u packet not supported",
               EXTRACT_16BITS(&ldp_com_header->version));
	return;
    }

    /* print the LSR-ID, label-space & length */
    printf("%sLDP, Label-Space-ID: %s:%u, length: %u",
           (vflag < 1) ? "" : "\n\t",
           ipaddr_string(&ldp_com_header->lsr_id),
           EXTRACT_16BITS(&ldp_com_header->label_space),
           len);

    /* bail out if non-verbose */ 
    if (vflag < 1)
        return;

    /* ok they seem to want to know everything - lets fully decode it */
    tlen=EXTRACT_16BITS(ldp_com_header->pdu_length);

    tptr+=sizeof(const struct ldp_common_header);
    tlen-=sizeof(const struct ldp_common_header);

    while(tlen>0) {
        /* did we capture enough for fully decoding the tlv header ? */
        if (!TTEST2(*tptr, sizeof(struct ldp_tlv_header)))
            goto trunc;

        ldp_tlv_header = (const struct ldp_tlv_header *)tptr;
        tlv_len=EXTRACT_16BITS(ldp_tlv_header->length);
        tlv_type=LDP_MASK_TLV_TYPE(EXTRACT_16BITS(ldp_tlv_header->type));

        printf("\n\t  %s TLV (0x%04x), length: %u, Flags: [%s and %s forward if unknown]",
               tok2str(ldp_tlv_values,
                       "Unknown",
                       tlv_type),
               tlv_type,
               tlv_len,
               LDP_MASK_TLV_U_BIT(EXTRACT_16BITS(&ldp_tlv_header->type)) ? "continue processing" : "ignore all, notify",
               LDP_MASK_TLV_F_BIT(EXTRACT_16BITS(&ldp_tlv_header->type)) ? "do" : "don't");

        tlv_tptr=tptr+sizeof(struct ldp_tlv_header);
        tlv_tlen=tlv_len-sizeof(struct ldp_tlv_header);

        /* did we capture enough for fully decoding the object ? */
        if (!TTEST2(*tptr, tlv_len))
            goto trunc;
        hexdump=FALSE;

        switch(tlv_type) {
 
        /*
         *  FIXME those are the defined objects that lack a decoder
         *  you are welcome to contribute code ;-)
         */

        case LDP_TLV_FEC:
        case LDP_TLV_ADDRESS_LIST:
        case LDP_TLV_HOP_COUNT:
        case LDP_TLV_PATH_VECTOR:
        case LDP_TLV_GENERIC_LABEL:
        case LDP_TLV_ATM_LABEL:
        case LDP_TLV_FR_LABEL:
        case LDP_TLV_STATUS:
        default:
            if (vflag <= 1)
                print_unknown_data(tlv_tptr,"\n\t    ",tlv_tlen);
            break;
        }
        /* do we want to see an additionally hexdump ? */
        if (vflag > 1 || hexdump==TRUE)
            print_unknown_data(tptr+sizeof(sizeof(struct ldp_tlv_header)),"\n\t    ",
                               tlv_len-sizeof(struct ldp_tlv_header));

        tptr+=tlv_len;
        tlen-=tlv_len;
    }
    return;
trunc:
    printf("\n\t\t packet exceeded snapshot");
}

