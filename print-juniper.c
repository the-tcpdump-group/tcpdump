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
    "@(#) $Header: /tcpdump/master/tcpdump/print-juniper.c,v 1.8.2.4 2005-05-03 20:39:26 hannes Exp $ (LBL)";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <tcpdump-stdinc.h>

#include <pcap.h>
#include <stdio.h>

#include "interface.h"
#include "extract.h"
#include "ppp.h"
#include "llc.h"
#include "nlpid.h"

#define JUNIPER_BPF_OUT           0       /* Outgoing packet */
#define JUNIPER_BPF_IN            1       /* Incoming packet */
#define JUNIPER_BPF_PKT_IN        0x1     /* Incoming packet */
#define JUNIPER_BPF_NO_L2         0x2     /* L2 header stripped */
#define JUNIPER_MGC_NUMBER        0x4d4743 /* = "MGC" */

static struct tok juniper_direction_values[] = {
    { JUNIPER_BPF_IN,  "In"},
    { JUNIPER_BPF_OUT, "Out"},
    { 0, NULL}
};

/* FIXME change enums to real DLT_s */
enum {
    JUNIPER_ATM1,
    JUNIPER_ATM2,
    JUNIPER_MLPPP,
    JUNIPER_MLFR,
    JUNIPER_MFR,
    JUNIPER_PPPOE
};

enum {
    DEFAULT,
    LS_COOKIE
};

struct juniper_cookie_table_t {
    u_int32_t pictype;		/* pic type */
    u_int8_t  cookie_len;       /* cookie len */
    const char *s;		/* pic name */
};

static struct juniper_cookie_table_t juniper_cookie_table[] = {
    { JUNIPER_ATM1,  4, "ATM1"},
    { JUNIPER_ATM2,  8, "ATM2"},
    { JUNIPER_MLPPP, 2, "MLPPP"},
    { JUNIPER_MLFR,  2, "MLFR"},
    { JUNIPER_MFR,   4, "MFR"},
    { JUNIPER_PPPOE, 0, "PPPoE"},
};

struct juniper_l2info_t {
    u_int32_t length;
    u_int32_t caplen;
    u_int32_t pictype;
    u_int8_t direction;
    u_int8_t header_len;
    u_int8_t cookie_len;
    u_int8_t cookie_type;
    u_int8_t cookie[8];
    u_int8_t bundle;
    u_int16_t proto;
};

#define LS_COOKIE_ID            0x54
#define LS_MLFR_COOKIE_LEN	4
#define ML_MLFR_COOKIE_LEN	2
#define LS_MFR_COOKIE_LEN	6
#define ATM1_COOKIE_LEN         4
#define ATM2_COOKIE_LEN         8

#define ATM2_PKT_TYPE_MASK  0x70
#define ATM2_GAP_COUNT_MASK 0x3F

int ip_heuristic_guess(register const u_char *, u_int);
int juniper_ppp_heuristic_guess(register const u_char *, u_int);
static int juniper_parse_header (const u_char *, const struct pcap_pkthdr *, struct juniper_l2info_t *);

u_int
juniper_pppoe_print(const struct pcap_pkthdr *h, register const u_char *p)
{
        struct juniper_l2info_t l2info;

        l2info.pictype = JUNIPER_PPPOE;
        if(juniper_parse_header(p, h, &l2info) == 0)
            return l2info.header_len;

        p+=l2info.header_len;
        /* this DLT contains nothing but raw ethernet frames */
        ether_print(p, l2info.length, l2info.caplen);
        return l2info.header_len;
}


u_int
juniper_mlppp_print(const struct pcap_pkthdr *h, register const u_char *p)
{
        struct juniper_l2info_t l2info;

        l2info.pictype = JUNIPER_MLPPP;
        if(juniper_parse_header(p, h, &l2info) == 0)
            return l2info.header_len;

        /* suppress Bundle-ID if frame was captured on a child-link
         * best indicator if the cookie looks like a proto */
        if (eflag &&
            EXTRACT_16BITS(&l2info.cookie) != PPP_OSI &&
            EXTRACT_16BITS(&l2info.cookie) !=  (PPP_ADDRESS << 8 | PPP_CONTROL))
            printf(", Bundle-ID %u: ",l2info.bundle);

        p+=l2info.header_len;

        switch (EXTRACT_16BITS(&l2info.cookie)) {
        case PPP_OSI:
            ppp_print(p-2,l2info.length+2);
            break;
        case (PPP_ADDRESS << 8 | PPP_CONTROL): /* fall through */
        default:
            ppp_print(p,l2info.length);
            break;
        }

        return l2info.header_len;
}


u_int
juniper_mfr_print(const struct pcap_pkthdr *h, register const u_char *p)
{
        struct juniper_l2info_t l2info;

        l2info.pictype = JUNIPER_MFR;
        if(juniper_parse_header(p, h, &l2info) == 0)
            return l2info.header_len;
        
        p+=l2info.header_len;
        /* suppress Bundle-ID if frame was captured on a child-link */
        if (eflag && EXTRACT_32BITS(l2info.cookie) != 1) printf("Bundle-ID %u, ",l2info.bundle);
        switch (l2info.proto) {
        case (LLCSAP_ISONS<<8 | LLCSAP_ISONS):
            isoclns_print(p+1, l2info.length-1, l2info.caplen-1);
            break;
        case (LLC_UI<<8 | NLPID_Q933):
        case (LLC_UI<<8 | NLPID_IP):
        case (LLC_UI<<8 | NLPID_IP6):
            /* pass IP{4,6} to the OSI layer for proper link-layer printing */
            isoclns_print(p-1, l2info.length+1, l2info.caplen+1); 
            break;
        default:
            printf("unknown protocol 0x%04x, length %u",l2info.proto, l2info.length);
        }

        return l2info.header_len;
}

u_int
juniper_mlfr_print(const struct pcap_pkthdr *h, register const u_char *p)
{
        struct juniper_l2info_t l2info;

        l2info.pictype = JUNIPER_MLFR;
        if(juniper_parse_header(p, h, &l2info) == 0)
            return l2info.header_len;

        p+=l2info.header_len;

        /* suppress Bundle-ID if frame was captured on a child-link */
        if (eflag && EXTRACT_32BITS(l2info.cookie) != 1) printf("Bundle-ID %u, ",l2info.bundle);
        switch (l2info.proto) {
        case (LLC_UI):
        case (LLC_UI<<8):
            isoclns_print(p, l2info.length, l2info.caplen);
            break;
        case (LLC_UI<<8 | NLPID_Q933):
        case (LLC_UI<<8 | NLPID_IP):
        case (LLC_UI<<8 | NLPID_IP6):
            /* pass IP{4,6} to the OSI layer for proper link-layer printing */
            isoclns_print(p-1, l2info.length+1, l2info.caplen+1);
            break;
        default:
            printf("unknown protocol 0x%04x, length %u",l2info.proto, l2info.length);
        }

        return l2info.header_len;
}

/*
 *     ATM1 PIC cookie format
 *
 *     +-----+-------------------------+-------------------------------+
 *     |fmtid|     vc index            |  channel  ID                  |
 *     +-----+-------------------------+-------------------------------+
 */

u_int
juniper_atm1_print(const struct pcap_pkthdr *h, register const u_char *p)
{
        u_int16_t extracted_ethertype;

        struct juniper_l2info_t l2info;

        l2info.pictype = JUNIPER_ATM1;
        if(juniper_parse_header(p, h, &l2info) == 0)
            return l2info.header_len;

        p+=l2info.header_len;

        if (l2info.cookie[0] == 0x80) { /* OAM cell ? */
            oam_print(p,l2info.length);
            return l2info.header_len;
        }

        if (EXTRACT_24BITS(p) == 0xfefe03 || /* NLPID encaps ? */
            EXTRACT_24BITS(p) == 0xaaaa03) { /* SNAP encaps ? */

            if (llc_print(p, l2info.length, l2info.caplen, NULL, NULL,
                          &extracted_ethertype) != 0)
                return l2info.header_len;
        }

        if (p[0] == 0x03) { /* Cisco style NLPID encaps ? */
            isoclns_print(p + 1, l2info.length - 1, l2info.caplen - 1);
            /* FIXME check if frame was recognized */
            return l2info.header_len;
        }

        if(ip_heuristic_guess(p, l2info.length) != 0) /* last try - vcmux encaps ? */
            return l2info.header_len;

	return l2info.header_len;
}

/*
 *     ATM2 PIC cookie format
 *
 *     +-------------------------------+---------+---+-----+-----------+
 *     |     channel ID                |  reserv |AAL| CCRQ| gap cnt   |
 *     +-------------------------------+---------+---+-----+-----------+
 */

u_int
juniper_atm2_print(const struct pcap_pkthdr *h, register const u_char *p)
{
        u_int16_t extracted_ethertype;

        struct juniper_l2info_t l2info;

        l2info.pictype = JUNIPER_ATM2;
        if(juniper_parse_header(p, h, &l2info) == 0)
            return l2info.header_len;

        p+=l2info.header_len;

        if (l2info.cookie[7] & ATM2_PKT_TYPE_MASK) { /* OAM cell ? */
            oam_print(p,l2info.length);
            return l2info.header_len;
        }

        if (EXTRACT_24BITS(p) == 0xfefe03 || /* NLPID encaps ? */
            EXTRACT_24BITS(p) == 0xaaaa03) { /* SNAP encaps ? */

            if (llc_print(p, l2info.length, l2info.caplen, NULL, NULL,
                          &extracted_ethertype) != 0)
                return l2info.header_len;
        }

        if (l2info.direction != JUNIPER_BPF_PKT_IN && /* ether-over-1483 encaps ? */
            (EXTRACT_32BITS(l2info.cookie) & ATM2_GAP_COUNT_MASK)) {
            ether_print(p, l2info.length, l2info.caplen);
            return l2info.header_len;
        }

        if (p[0] == 0x03) { /* Cisco style NLPID encaps ? */
            isoclns_print(p + 1, l2info.length - 1, l2info.caplen - 1);
            /* FIXME check if frame was recognized */
            return l2info.header_len;
        }

        if(juniper_ppp_heuristic_guess(p, l2info.length) != 0) /* PPPoA vcmux encaps ? */
            return l2info.header_len;

        if(ip_heuristic_guess(p, l2info.length) != 0) /* last try - vcmux encaps ? */
            return l2info.header_len;

	return l2info.header_len;
}


/* try to guess, based on all PPP protos that are supported in
 * a juniper router if the payload data is encapsulated using PPP */
int
juniper_ppp_heuristic_guess(register const u_char *p, u_int length) {

    switch(EXTRACT_16BITS(p)) {
    case PPP_IP :
    case PPP_OSI :
    case PPP_MPLS_UCAST :
    case PPP_MPLS_MCAST :
    case PPP_IPCP :
    case PPP_OSICP :
    case PPP_MPLSCP :
    case PPP_LCP :
    case PPP_PAP :
    case PPP_CHAP :
    case PPP_ML :
#ifdef INET6
    case PPP_IPV6 :
    case PPP_IPV6CP :
#endif
        ppp_print(p, length);
        break;

    default:
        return 0; /* did not find a ppp header */
        break;
    }
    return 1; /* we printed a ppp packet */
}

int
ip_heuristic_guess(register const u_char *p, u_int length) {

    switch(p[0]) {
    case 0x45:
    case 0x46:
    case 0x47:
    case 0x48:
    case 0x49:
    case 0x4a:
    case 0x4b:
    case 0x4c:
    case 0x4d:
    case 0x4e:
    case 0x4f:
	    ip_print(gndo, p, length);
	    break;
#ifdef INET6
    case 0x60:
    case 0x61:
    case 0x62:
    case 0x63:
    case 0x64:
    case 0x65:
    case 0x66:
    case 0x67:
    case 0x68:
    case 0x69:
    case 0x6a:
    case 0x6b:
    case 0x6c:
    case 0x6d:
    case 0x6e:
    case 0x6f:
        ip6_print(p, length);
        break;
#endif
    default:
        return 0; /* did not find a ip header */
        break;
    }
    return 1; /* we printed an v4/v6 packet */
}

static int
juniper_parse_header (const u_char *p, const struct pcap_pkthdr *h, struct juniper_l2info_t *l2info) {

    struct juniper_cookie_table_t *lp = juniper_cookie_table;
    u_int idx;

    l2info->header_len = 0;
    l2info->cookie_len = 0;
    l2info->proto = 0;


    l2info->length = h->len;
    l2info->caplen = h->caplen;
    l2info->direction = p[3]&JUNIPER_BPF_PKT_IN;
    
    if (EXTRACT_24BITS(p) != JUNIPER_MGC_NUMBER) /* magic number found ? */
        return 0;
    else
        l2info->header_len = 4;

    if (eflag) /* print direction */
        printf("%3s ",tok2str(juniper_direction_values,"---",l2info->direction));

    if ((p[3] & JUNIPER_BPF_NO_L2 ) == JUNIPER_BPF_NO_L2 ) {            
        if (eflag)
            printf("no-L2-hdr, ");

        /* there is no link-layer present -
         * perform the v4/v6 heuristics
         * to figure out what it is
         */
        if(ip_heuristic_guess(p+8,l2info->length-8) == 0)
            printf("no IP-hdr found!");

        l2info->header_len+=4;
        return 0; /* stop parsing the output further */
        
    }

    p+=l2info->header_len;
    l2info->length -= l2info->header_len;
    l2info->caplen -= l2info->header_len;

    /* search through the cookie table and copy values matching for our PIC type */
    while (lp->s != NULL) {
        if (lp->pictype == l2info->pictype) {

            l2info->cookie_len = lp->cookie_len;
            l2info->header_len += lp->cookie_len;

            if(p[0] == LS_COOKIE_ID) {
                l2info->cookie_type = LS_COOKIE;
                l2info->cookie_len += 2;
                l2info->header_len += 2;
                l2info->bundle = l2info->cookie[1];
            } else l2info->bundle = l2info->cookie[0];

            if (eflag)
                printf("%s-PIC, cookie-len %u",
                       lp->s,
                       l2info->cookie_len);

            if (eflag && l2info->cookie_len > 0) {
                printf(", cookie 0x");
                for (idx = 0; idx < l2info->cookie_len; idx++) {
                    l2info->cookie[idx] = p[idx]; /* copy cookie data */
                    if (eflag) printf("%02x",p[idx]);
                }
            }

            if (eflag) printf(": "); /* print demarc b/w L2/L3*/
            

            l2info->proto = EXTRACT_16BITS(p+l2info->cookie_len); 
            break;
        }
        ++lp;
    }
    p+=l2info->cookie_len;

    /* DLT_ specific parsing */
    switch(l2info->pictype) {
    case JUNIPER_MLPPP:
        if (l2info->cookie_type == LS_COOKIE) {
            l2info->bundle = l2info->cookie[1];
        } else {
            l2info->bundle = l2info->cookie[0];
        }
        break;
    case JUNIPER_MLFR: /* fall through */
    case JUNIPER_MFR:
        if (l2info->cookie_type == LS_COOKIE) {
            l2info->bundle = l2info->cookie[1];
        } else {
            l2info->bundle = l2info->cookie[0];
        }
        l2info->proto = EXTRACT_16BITS(p);        
        l2info->header_len += 2;
        l2info->length -= 2;
        l2info->caplen -= 2;
        break;
    case JUNIPER_ATM2:
    case JUNIPER_ATM1:
    default:

        break;
    }
    
    if (eflag > 1)
        printf("hlen %u, proto 0x%04x, ",l2info->header_len,l2info->proto);

    return 1; /* everything went ok so far. continue parsing */
}


/*
 * Local Variables:
 * c-style: whitesmith
 * c-basic-offset: 4
 * End:
 */
