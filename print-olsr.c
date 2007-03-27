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
 * Optimized Link State Protocl (OLSR) as per rfc3626
 *
 * Original code by Hannes Gredler <hannes@juniper.net>
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <tcpdump-stdinc.h>

#include <stdio.h>
#include <string.h>

#include "interface.h"
#include "addrtoname.h"
#include "extract.h"		
#include "nlpid.h"

/*
 * RFC 3626 common header
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |         Packet Length         |    Packet Sequence Number     |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  Message Type |     Vtime     |         Message Size          |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                      Originator Address                       |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  Time To Live |   Hop Count   |    Message Sequence Number    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                                                               |
 * :                            MESSAGE                            :
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  Message Type |     Vtime     |         Message Size          |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                      Originator Address                       |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  Time To Live |   Hop Count   |    Message Sequence Number    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                                                               |
 * :                            MESSAGE                            :
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * :                                                               :
 */

struct olsr_common {
    u_int8_t packet_len[2];
    u_int8_t packet_seq[2];
};

#define OLSR_HELLO_MSG         1 /* rfc3626 */
#define OLSR_TC_MSG            2 /* rfc3626 */
#define OLSR_MID_MSG           3 /* rfc3626 */
#define OLSR_HNA_MSG           4 /* rfc3626 */
#define OLSR_POWERINFO_MSG   128
#define OLSR_NAMESERVICE_MSG 130
#define OLSR_HELLO_LQ_MSG    201 /* LQ extensions olsr.org */
#define OLSR_TC_LQ_MSG       202 /* LQ extensions olsr.org */

static struct tok olsr_msg_values[] = {
    { OLSR_HELLO_MSG, "Hello" },
    { OLSR_TC_MSG, "TC" },
    { OLSR_MID_MSG, "MID" },
    { OLSR_HNA_MSG, "HNA" },
    { OLSR_POWERINFO_MSG, "Powerinfo" },
    { OLSR_NAMESERVICE_MSG, "Nameservice" },
    { OLSR_HELLO_LQ_MSG, "Hello-LQ" },
    { OLSR_TC_LQ_MSG, "TC-LQ" },
    { 0, NULL}
};

struct olsr_msg {
    u_int8_t msg_type;
    u_int8_t vtime;
    u_int8_t msg_len[2];
    u_int8_t originator[4];
    u_int8_t ttl;
    u_int8_t hopcount;
    u_int8_t msg_seq[2];
};

struct olsr_hello_lq {
    u_int8_t res[2];
    u_int8_t htime;
    u_int8_t will;
};

struct olsr_hello_lq_link {
    u_int8_t link_code;
    u_int8_t res;
    u_int8_t len[2];
};

#define OLSR_EXTRACT_LINK_TYPE(link_code) (link_code & 0x3)
#define OLSR_EXTRACT_NEIGHBOR_TYPE(link_code) (link_code >> 2)

static struct tok olsr_link_type_values[] = {
    { 0, "Unspecified" },
    { 1, "Asymmetric" },
    { 2, "Symmetric" },
    { 3, "Lost" },
    { 0, NULL}
};

static struct tok olsr_neighbor_type_values[] = {
    { 0, "Not-Neighbor" },
    { 1, "Symmetric" },
    { 2, "Symmetric-MPR" },
    { 0, NULL}
};

struct olsr_hello_lq_neighbor {
    u_int8_t neighbor[4];
    u_int8_t link_quality;
    u_int8_t neighbor_link_quality;
    u_int8_t res[2];
};

/*
 * macro to convert the 8-bit mantissa/exponent to a double float
 * taken from olsr.org code.
 */
#define VTIME_SCALE_FACTOR    0.0625
#define ME_TO_DOUBLE(me) \
  (double)(VTIME_SCALE_FACTOR*(1+(double)(me>>4)/16)*(double)(1<<(me&0x0F)))

void
olsr_print (const u_char *pptr, u_int length)
{
    union {
        const struct olsr_common *common;
        const struct olsr_msg *msg;
        const struct olsr_hello_lq *hello_lq;
        const struct olsr_hello_lq_link *hello_lq_link;
        const struct olsr_hello_lq_neighbor *hello_lq_neighbor;
    } ptr;

    u_int msg_type, msg_len, msg_tlen, hello_len;
    u_int8_t link_type, neighbor_type;
    const u_char *tptr, *msg_data;

    tptr = pptr; 

    if (length < sizeof(struct olsr_common)) {
        goto trunc;
    }

    if (!TTEST2(*tptr, sizeof(struct olsr_common))) {
	goto trunc;
    }

    ptr.common = (struct olsr_common *)tptr;
    length = MIN(length, EXTRACT_16BITS(ptr.common->packet_len));

    printf("OLSR, seq 0x%04x, length %u",
           EXTRACT_16BITS(ptr.common->packet_seq),
           length);

    tptr += sizeof(struct olsr_common);

    /*
     * In non-verbose mode, just print version.
     */
    if (vflag < 1) {
	return;
    }

    while (tptr < (pptr+length)) {

        if (!TTEST2(*tptr, sizeof(struct olsr_msg)))	
            goto trunc;

        ptr.msg = (struct olsr_msg *)tptr;

        msg_type = ptr.msg->msg_type;
        msg_len = EXTRACT_16BITS(ptr.msg->msg_len);

        /* infinite loop check */
        if (msg_type == 0 || msg_len == 0) {
            return;
        }

        printf("\n\t%s Message (%u), originator %s, ttl %u, hop %u"
               "\n\t  vtime %.3lfs, msg-seq 0x%04x, length %u",
               tok2str(olsr_msg_values, "Unknown", msg_type),
               msg_type, ipaddr_string(ptr.msg->originator),
               ptr.msg->ttl,
               ptr.msg->hopcount,
               ME_TO_DOUBLE(ptr.msg->vtime),
               EXTRACT_16BITS(ptr.msg->msg_seq),
               msg_len);

        msg_tlen = msg_len - sizeof(struct olsr_msg);
        msg_data = tptr + sizeof(struct olsr_msg);

        switch (msg_type) {
        case OLSR_HELLO_LQ_MSG:
            ptr.hello_lq = (struct olsr_hello_lq *)msg_data;
            printf("\n\t  hello-time %.3lfs, MPR willingness %u",
                   ME_TO_DOUBLE(ptr.hello_lq->htime),
                   ptr.hello_lq->will);
            msg_data += sizeof(struct olsr_hello_lq);
            msg_tlen -= sizeof(struct olsr_hello_lq);

            while (msg_tlen >= sizeof(struct olsr_hello_lq_link)) {

                /*
                 * link-type.
                 */
                ptr.hello_lq_link = (struct olsr_hello_lq_link *)msg_data;

                hello_len = EXTRACT_16BITS(ptr.hello_lq_link->len);
                link_type = OLSR_EXTRACT_LINK_TYPE(ptr.hello_lq_link->link_code);
                neighbor_type = OLSR_EXTRACT_NEIGHBOR_TYPE(ptr.hello_lq_link->link_code);

                printf("\n\t    link-type %s, neighbor-type %s, len %u",
                       tok2str(olsr_link_type_values, "Unknown", link_type),
                       tok2str(olsr_neighbor_type_values, "Unknown", neighbor_type),
                       hello_len);

                msg_data += sizeof(struct olsr_hello_lq_link);
                msg_tlen -= sizeof(struct olsr_hello_lq_link);

                hello_len -= sizeof(struct olsr_hello_lq_link);
                while (hello_len >= sizeof(struct olsr_hello_lq_neighbor)) {

                    /*
                     * neighbor.
                     */
                    ptr.hello_lq_neighbor =
                        (struct olsr_hello_lq_neighbor *)msg_data;

                    printf("\n\t      neighbor %s, link-quality %.2lf%%"
                           ", neighbor-link-quality %.2lf%%",
                           ipaddr_string(ptr.hello_lq_neighbor->neighbor),
                           ((double)ptr.hello_lq_neighbor->link_quality/2.55),
                           ((double)ptr.hello_lq_neighbor->neighbor_link_quality/2.55));

                    msg_data += sizeof(struct olsr_hello_lq_neighbor);
                    msg_tlen -= sizeof(struct olsr_hello_lq_neighbor);                
                    hello_len -= sizeof(struct olsr_hello_lq_neighbor);
                }
            }
            break;

            /*
             * FIXME those are the defined messages that lack a decoder
             * you are welcome to contribute code ;-)
             */

        case OLSR_HELLO_MSG:
        case OLSR_TC_MSG:
        case OLSR_MID_MSG:
        case OLSR_HNA_MSG:
        case OLSR_POWERINFO_MSG:
        case OLSR_NAMESERVICE_MSG:
        case OLSR_TC_LQ_MSG:
        default:
	    print_unknown_data(msg_data, "\n\t    ", msg_tlen);
            break;
        }	
        tptr += msg_len;
    }

    return;

 trunc:
    printf("[|olsr]");
}

/*
 * Local Variables:
 * c-style: whitesmith
 * c-basic-offset: 4
 * End:
 */
