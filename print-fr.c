/*
 * Copyright (c) 1990, 1991, 1993, 1994, 1995, 1996
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
 */

#ifndef lint
static const char rcsid[] =
	"@(#)$Header: /tcpdump/master/tcpdump/print-fr.c,v 1.7 2002-11-09 17:19:25 itojun Exp $ (LBL)";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <tcpdump-stdinc.h>

struct mbuf;
struct rtentry;

#include <stdio.h>
#include <string.h>
#include <pcap.h>

#include "interface.h"
#include "addrtoname.h"
#include "ethertype.h"
#include "extract.h"

static void q933_print(const u_char *, int);

#define FR_CR_BIT	0x02
#define FR_EA_BIT(p)	((p)&0x01)
#define FR_FECN		0x08
#define FR_BECN		0x04
#define FR_DE		0x02
#define FR_DLCI(b0, b1)	((((b0)&0xFC)<<2)+(((b1)&0xF0)>>4))

/* find out how many bytes are there in a frame */
static u_int
fr_addr_len(const u_char *p)
{
	u_int i=0;
	
	while (!FR_EA_BIT(p[i]) && i++ && !FR_EA_BIT(p[i+1])) i++;
	return (i+1);
}

/* the following is for framerelay */
#define NLPID_LEN	1	/* NLPID is one byte long */
#define NLPID_Q933      0x08
#define NLPID_LMI       0x09
#define NLPID_SNAP      0x80
#define NLPID_CLNP      0x81
#define NLPID_ESIS      0x82
#define NLPID_ISIS      0x83
#define NLPID_CONS      0x84
#define NLPID_IDRP      0x85
#define NLPID_X25_ESIS  0x8a
#define NLPID_IP        0xcc


static const char *fr_nlpids[256];

static void
init_fr_nlpids(void)
{
	int i;
	static int fr_nlpid_flag = 0;

	if (!fr_nlpid_flag) {
		for (i=0; i < 256; i++)
			fr_nlpids[i] = NULL;
		fr_nlpids[NLPID_Q933] = "Q.933";
		fr_nlpids[NLPID_LMI] = "LMI";
		fr_nlpids[NLPID_SNAP] = "SNAP";
		fr_nlpids[NLPID_CLNP] = "CLNP";
		fr_nlpids[NLPID_ESIS] = "ESIS";
		fr_nlpids[NLPID_ISIS] = "ISIS";
		fr_nlpids[NLPID_CONS] = "CONS";
		fr_nlpids[NLPID_IDRP] = "IDRP";
		fr_nlpids[NLPID_X25_ESIS] = "X25_ESIS";
		fr_nlpids[NLPID_IP] = "IP";
	}
	fr_nlpid_flag = 1;
}

/* Framerelay packet structure */

/*
                  +---------------------------+
                  |    flag (7E hexadecimal)  |
                  +---------------------------+
                  |       Q.922 Address*      |
                  +--                       --+
                  |                           |
                  +---------------------------+
                  | Control (UI = 0x03)       |
                  +---------------------------+
                  | Optional Pad      (0x00)  |
                  +---------------------------+
                  | NLPID                     |
                  +---------------------------+
                  |             .             |
                  |             .             |
                  |             .             |
                  |           Data            |
                  |             .             |
                  |             .             |
                  +---------------------------+
                  |   Frame Check Sequence    |
                  +--           .           --+
                  |       (two octets)        |
                  +---------------------------+
                  |   flag (7E hexadecimal)   |
                  +---------------------------+

           * Q.922 addresses, as presently defined, are two octets and
             contain a 10-bit DLCI.  In some networks Q.922 addresses
             may optionally be increased to three or four octets.

*/

#define FR_PROTOCOL(p) fr_protocol((p))

static u_int
fr_hdrlen(const u_char *p)
{
	u_int hlen;
	hlen = fr_addr_len(p)+1;  /* addr_len + 0x03 + padding */
	if (p[hlen])
		return hlen;
	else
		return hlen+1;
}

#define LAYER2_LEN(p) (fr_hdrlen((p))+NLPID_LEN)

static int
fr_protocol(const u_char *p)
{
	int hlen;
	
	hlen = fr_addr_len(p) + 1;
	if (p[hlen])  /* check for padding */
		return p[hlen];
	else 
		return p[hlen+1];
}

static char *
fr_flags(const u_char *p)
{
	static char flags[1+1+4+1+4+1+2+1];

	if (p[0] & FR_CR_BIT)
		strcpy(flags, "C");
	else
		strcpy(flags, "R");
	if (p[1] & FR_FECN)
		strcat(flags, ",FECN");
	if (p[1] & FR_BECN)
		strcat(flags, ",BECN");
	if (p[1] & FR_DE)
		strcat(flags, ",DE");
	return flags;
}

static const char *
fr_protostring(u_int8_t proto)
{
	static char buf[5+1+2+1];

	if (nflag || fr_nlpids[proto] == NULL) {
		sprintf(buf, "proto-%02x", proto);
		return buf;
	}
	return fr_nlpids[proto];
}

static void
fr_hdr_print(const u_char *p, int length)
{
	u_int8_t proto;

	proto = FR_PROTOCOL(p);

	init_fr_nlpids();
	/* this is kinda kludge since it assumed that DLCI is two bytes. */
	if (qflag)
		(void)printf("DLCI-%u-%s %d: ",
			     FR_DLCI(p[0], p[1]), fr_flags(p), length);
	else
		(void)printf("DLCI-%u-%s %s %d: ",
			     FR_DLCI(p[0], p[1]), fr_flags(p),
			     fr_protostring(proto), length);
}

void
fr_if_print(u_char *user _U_, const struct pcap_pkthdr *h,
	     register const u_char *p)
{
	register u_int length = h->len;
	register u_int caplen = h->caplen;
	u_char protocol;
	int layer2_len;
	u_short extracted_ethertype;
	u_int32_t orgcode;
	register u_short et;

	ts_print(&h->ts);

	if (caplen < fr_hdrlen(p)) {
		printf("[|fr]");
		goto out;
	}

	/*
	 * Some printers want to get back at the link level addresses,
	 * and/or check that they're not walking off the end of the packet.
	 * Rather than pass them all the way down, we set these globals.
	 */
	packetp = p;
	snapend = p + caplen;

	if (eflag)
		fr_hdr_print(p, length);

	protocol = FR_PROTOCOL(p);
	layer2_len = LAYER2_LEN(p);
	p += layer2_len;
	length -= layer2_len;
	caplen -= layer2_len;

	switch (protocol) {

	case NLPID_IP:
		ip_print(p, length);
		break;

	case NLPID_CLNP:
	case NLPID_ESIS:
	case NLPID_ISIS:
		isoclns_print(p, length, caplen, NULL, NULL);
		break;

	case NLPID_SNAP:
		orgcode = EXTRACT_24BITS(p);
		et = EXTRACT_16BITS(p + 3);
		if (snap_print((const u_char *)(p + 5), length - 5,
			   caplen - 5, &extracted_ethertype, orgcode, et,
			   0) == 0) {
			/* ether_type not known, print raw packet */
			if (!eflag)
				fr_hdr_print(p - layer2_len, length + layer2_len);
			if (extracted_ethertype) {
				printf("(SNAP %s) ",
			       etherproto_string(htons(extracted_ethertype)));
			}
			if (!xflag && !qflag)
				default_print(p - layer2_len, caplen + layer2_len);
		}
		break;

	case NLPID_Q933:
		q933_print(p, length);
		break;

	default:
		if (!eflag)
			fr_hdr_print(p - layer2_len, length + layer2_len);
		if (!xflag)
			default_print(p, caplen);
	}

	if (xflag)
		default_print(p, caplen);
out:
	putchar('\n');
}

/*
 * Q.933 decoding portion for framerelay specific.
 */

/* Q.933 packet format
                      Format of Other Protocols   
                          using Q.933 NLPID
                  +-------------------------------+            
                  |        Q.922 Address          | 
                  +---------------+---------------+
                  |Control  0x03  | NLPID   0x08  |        
                  +---------------+---------------+        
                  |          L2 Protocol ID       |
                  | octet 1       |  octet 2      |
                  +-------------------------------+
                  |          L3 Protocol ID       |
                  | octet 2       |  octet 2      |
                  +-------------------------------+
                  |         Protocol Data         |
                  +-------------------------------+
                  | FCS                           |
                  +-------------------------------+
 */

/* L2 (Octet 1)- Call Reference Usually is 0x0 */

/*
 * L2 (Octet 2)- Message Types definition 1 byte long.
 */
/* Call Establish */
#define MSG_TYPE_ESC_TO_NATIONAL  0x00
#define MSG_TYPE_ALERT            0x01
#define MSG_TYPE_CALL_PROCEEDING  0x02
#define MSG_TYPE_CONNECT          0x07
#define MSG_TYPE_CONNECT_ACK      0x0F
#define MSG_TYPE_PROGRESS         0x03
#define MSG_TYPE_SETUP            0x05
/* Call Clear */
#define MSG_TYPE_DISCONNECT       0x45
#define MSG_TYPE_RELEASE          0x4D
#define MSG_TYPE_RELEASE_COMPLETE 0x5A
#define MSG_TYPE_RESTART          0x46
#define MSG_TYPE_RESTART_ACK      0x4E
/* Status */
#define MSG_TYPE_STATUS           0x7D
#define MSG_TYPE_STATUS_ENQ       0x75

#define ONE_BYTE_IE_MASK 0xF0

/* See L2 protocol ID picture above */
struct q933_header {
    u_int8_t call_ref;  /* usually is 0 for framerelay PVC */
    u_int8_t msg_type;  
} __attribute__((packed));

#define REPORT_TYPE_IE    0x01
#define LINK_VERIFY_IE_91 0x19
#define LINK_VERIFY_IE_94 0x03
#define PVC_STATUS_IE     0x07

#define MAX_IE_SIZE

struct common_ie_header {
    u_int8_t ie_id;
    u_int8_t ie_len;
} __attribute__((packed));

#define FULL_STATUS 0
#define LINK_VERIFY 1
#define ASYNC_PVC   2

static void
q933_print(const u_char *p, int length)
{
	struct q933_header *header = (struct q933_header *)(p+1);
	const u_char *ptemp = p;
	int ie_len;
	const char *decode_str;
	char temp_str[255];
	struct common_ie_header *ie_p;
    
	/* printing out header part */
	printf("Call Ref: %02x, MSG Type: %02x", 
	       header->call_ref, header->msg_type);
	switch(header->msg_type) {
	case MSG_TYPE_STATUS:
	    decode_str = "STATUS REPLY";
	    break;
	case MSG_TYPE_STATUS_ENQ:
	    decode_str = "STATUS ENQUIRY";
	    break;
	default:
	    decode_str = "UNKNOWN MSG Type";
	}
	printf(" %s\n", decode_str);

	length = length - 3;
	ptemp = ptemp + 3;
	
	/* Loop through the rest of IE */
	while( length > 0 ) {
	    if (ptemp[0] & ONE_BYTE_IE_MASK) {
		ie_len = 1;
		printf("\t\tOne byte IE: %02x, Content %02x\n", 
		       (*ptemp & 0x70)>>4, (*ptemp & 0x0F));
		length--;
		ptemp++;
	    }
	    else {  /* Multi-byte IE */
		ie_p = (struct common_ie_header *)ptemp;
		switch (ie_p->ie_id) {
		case REPORT_TYPE_IE:
		    switch(ptemp[2]) {
		    case FULL_STATUS:
			decode_str = "FULL STATUS";
			break;
		    case LINK_VERIFY:
			decode_str = "LINK VERIFY";
			break;
		    case ASYNC_PVC:
			decode_str = "Async PVC Status";
			break;
		    default:
			decode_str = "Reserved Value";
		    }
		    break;
		case LINK_VERIFY_IE_91:
		case LINK_VERIFY_IE_94:
		    snprintf(temp_str, sizeof (temp_str), "TX Seq: %3d, RX Seq: %3d",
			    ptemp[2], ptemp[3]);
		    decode_str = temp_str;
		    break;
		case PVC_STATUS_IE:
		    snprintf(temp_str, sizeof (temp_str), "DLCI %d: status %s %s",
			    ((ptemp[2]&0x3f)<<4)+ ((ptemp[3]&0x78)>>3), 
			    ptemp[4] & 0x8 ?"new,":" ",
			    ptemp[4] & 0x2 ?"Active":"Inactive");
		    break;
		default:
		    decode_str = "Non-decoded Value";		    
		}
		printf("\t\tIE: %02X Len: %d, %s\n",
		       ie_p->ie_id, ie_p->ie_len, decode_str);
		length = length - ie_p->ie_len - 2;
		ptemp = ptemp + ie_p->ie_len + 2;
	    }
	}
}
