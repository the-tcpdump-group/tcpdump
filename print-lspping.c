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
static const char rcsid[] _U_ =
    "@(#) $Header: /tcpdump/master/tcpdump/print-lspping.c,v 1.1 2004-06-06 19:20:03 hannes Exp $";
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
 * LSPPING common header
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |         Version Number        |         Must Be Zero          |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  Message Type |   Reply mode  |  Return Code  | Return Subcode|
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                        Sender's Handle                        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                        Sequence Number                        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    TimeStamp Sent (seconds)                   |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                  TimeStamp Sent (microseconds)                |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                  TimeStamp Received (seconds)                 |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                TimeStamp Received (microseconds)              |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                            TLVs ...                           |
 * .                                                               .
 * .                                                               .
 * .                                                               .
 */

struct lspping_common_header {
    u_int8_t version[2];
    u_int8_t reserved[2];
    u_int8_t msg_type;
    u_int8_t reply_mode;   
    u_int8_t return_code;   
    u_int8_t return_subcode;   
    u_int8_t sender_handle[4];
    u_int8_t seq_number[4];
    u_int8_t ts_sent_sec[4];
    u_int8_t ts_sent_usec[4];
    u_int8_t ts_rcvd_sec[4];
    u_int8_t ts_rcvd_usec[4];
};

#define LSPPING_VERSION            1
#define FALSE 0
#define TRUE  1

static const struct tok lspping_msg_type_values[] = {
    { 1, "MPLS Echo Request"},
    { 2, "MPLS Echo Reply"},
    { 0, NULL}
};

static const struct tok lspping_reply_mode_values[] = {
    { 1, "Do not reply"},
    { 2, "Reply via an IPv4/IPv6 UDP packet"},
    { 3, "Reply via an IPv4/IPv6 UDP packet with Router Alert"},
    { 4, "Reply via application level control channel"},
    { 0, NULL}
};

/* 
 * LSPPING TLV header
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |             Type              |            Length             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                             Value                             |
 * .                                                               .
 * .                                                               .
 * .                                                               .
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

struct lspping_tlv_header {
    u_int8_t type[2];
    u_int8_t length[2];
};

#define	LSPPING_TLV_TARGET_FEC_STACK      1
#define	LSPPING_TLV_DOWNSTREAM_MAPPING    2
#define	LSPPING_TLV_PAD                   3
#define	LSPPING_TLV_ERROR_CODE            4
#define	LSPPING_TLV_VENDOR_PRIVATE        5 

static const struct tok lspping_tlv_values[] = {
    { LSPPING_TLV_TARGET_FEC_STACK, "Target FEC Stack" },
    { LSPPING_TLV_DOWNSTREAM_MAPPING, "Downstream Mapping" },
    { LSPPING_TLV_PAD, "Pad" },
    { LSPPING_TLV_ERROR_CODE, "Error Code" },
    { LSPPING_TLV_VENDOR_PRIVATE, "Vendor Enterprise Code" },
    { 0, NULL}
};

void
lspping_print(register const u_char *pptr, register u_int len) {

    const struct lspping_common_header *lspping_com_header;
    const struct lspping_tlv_header *lspping_tlv_header;
    const u_char *tptr,*tlv_tptr;
    int tlen,lspping_tlv_len,lspping_tlv_type,tlv_tlen;
    int hexdump;

    tptr=pptr;
    lspping_com_header = (const struct lspping_common_header *)pptr;
    TCHECK(*lspping_com_header);

    /*
     * Sanity checking of the header.
     */
    if (EXTRACT_16BITS(&lspping_com_header->version[0]) != LSPPING_VERSION) {
	printf("LSP-PING version %u packet not supported",
               EXTRACT_16BITS(&lspping_com_header->version[0]));
	return;
    }

    /* in non-verbose mode just lets print the basic Message Type*/
    if (vflag < 1) {
        printf("LSP-PINGv%u, %s, seq %u, length: %u",
               EXTRACT_16BITS(&lspping_com_header->version[0]),
               tok2str(lspping_msg_type_values, "unknown (%u)",lspping_com_header->msg_type),
               EXTRACT_32BITS(lspping_com_header->seq_number),
               len);
        return;
    }

    /* ok they seem to want to know everything - lets fully decode it */

    tlen=len;

    printf("\n\tLSP-PINGv%u, msg-type: %s (%u), reply-mode: %s (%u)" \
           "\n\t  Return Code: (%u), Return Subcode: (%u)" \
           "\n\t  Sender Handle: 0x%08x, Sequence: %u" \
           "\n\t  Sender Timestamp %u.%us, Receiver Timestamp %u.%us",
           EXTRACT_16BITS(&lspping_com_header->version[0]),
           tok2str(lspping_msg_type_values, "unknown",lspping_com_header->msg_type),
           lspping_com_header->msg_type,
           tok2str(lspping_reply_mode_values, "unknown",lspping_com_header->reply_mode),
           lspping_com_header->reply_mode,
           lspping_com_header->return_code,
           lspping_com_header->return_subcode,
           EXTRACT_32BITS(lspping_com_header->sender_handle),
           EXTRACT_32BITS(lspping_com_header->seq_number),
           EXTRACT_32BITS(lspping_com_header->ts_sent_sec),
           EXTRACT_32BITS(lspping_com_header->ts_sent_usec),
           EXTRACT_32BITS(lspping_com_header->ts_rcvd_sec),
           EXTRACT_32BITS(lspping_com_header->ts_rcvd_usec));

    tptr+=sizeof(const struct lspping_common_header);
    tlen-=sizeof(const struct lspping_common_header);

    while(tlen>0) {
        /* did we capture enough for fully decoding the tlv header ? */
        if (!TTEST2(*tptr, sizeof(struct lspping_tlv_header)))
            goto trunc;

        lspping_tlv_header = (const struct lspping_tlv_header *)tptr;
        lspping_tlv_type=EXTRACT_16BITS(lspping_tlv_header->type);
        lspping_tlv_len=EXTRACT_16BITS(lspping_tlv_header->length);

        if(lspping_tlv_len % 4 || lspping_tlv_len < 4)
            return;

        printf("\n\t  %s TLV (%u), length: %u",
               tok2str(lspping_tlv_values,
                       "Unknown",
                       lspping_tlv_type),
               lspping_tlv_type,
               lspping_tlv_len);

        tlv_tptr=tptr+sizeof(struct lspping_tlv_header);
        tlv_tlen=lspping_tlv_len-sizeof(struct lspping_tlv_header);

        /* did we capture enough for fully decoding the tlv ? */
        if (!TTEST2(*tptr, lspping_tlv_len))
            goto trunc;
        hexdump=FALSE;

        switch(lspping_tlv_type) {

        /*
         *  FIXME those are the defined messages that lack a decoder
         *  you are welcome to contribute code ;-)
         */

        case LSPPING_TLV_TARGET_FEC_STACK:
        case LSPPING_TLV_DOWNSTREAM_MAPPING:
        case LSPPING_TLV_PAD:
        case LSPPING_TLV_ERROR_CODE:
        case LSPPING_TLV_VENDOR_PRIVATE:
    
        default:
            if (vflag <= 1)
                print_unknown_data(tlv_tptr,"\n\t    ",tlv_tlen);
            break;
        }
        /* do we want to see an additionally hexdump ? */
        if (vflag > 1 || hexdump==TRUE)
            print_unknown_data(tptr+sizeof(sizeof(struct lspping_tlv_header)),"\n\t    ",
                               lspping_tlv_len-sizeof(struct lspping_tlv_header));

        tptr+=lspping_tlv_len;
        tlen-=lspping_tlv_len;
    }
    return;
trunc:
    printf("\n\t\t packet exceeded snapshot");
}
