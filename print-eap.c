/*
 * Copyright (c) 2004 - Michael Richardson <mcr@xelerance.com>
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
 *
 * Format and print EAP packets.
 *
 */

#ifndef lint
static const char rcsid[] _U_ =
    "@(#) $Header: /tcpdump/master/tcpdump/print-eap.c,v 1.4 2007-10-04 08:34:28 hannes Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <tcpdump-stdinc.h>

#include <stdio.h>
#include <string.h>

#include "netdissect.h"
#include "interface.h"
#include "addrtoname.h"
#include "extract.h"
#include "ether.h"

#define	EAP_FRAME_TYPE_PACKET		0
#define	EAP_FRAME_TYPE_START		1
#define	EAP_FRAME_TYPE_LOGOFF		2
#define	EAP_FRAME_TYPE_KEY		3
#define	EAP_FRAME_TYPE_ENCAP_ASF_ALERT	4

struct eap_frame_t {
    unsigned char   version;
    unsigned char   type;
    unsigned char   length[2];
};

static const struct tok eap_frame_type_values[] = {
    { EAP_FRAME_TYPE_PACKET,      	"EAP packet" },
    { EAP_FRAME_TYPE_START,    		"EAPOL start" },
    { EAP_FRAME_TYPE_LOGOFF,      	"EAPOL logoff" },
    { EAP_FRAME_TYPE_KEY,      		"EAPOL key" },
    { EAP_FRAME_TYPE_ENCAP_ASF_ALERT, 	"Encapsulated ASF alert" },
    { 0, NULL}
};

/* RFC 3748 */
struct eap_packet_t {
    unsigned char	code;
    unsigned char	id;
    unsigned char	length[2];
};

#define		EAP_REQUEST	1
#define		EAP_RESPONSE	2
#define		EAP_SUCCESS	3
#define		EAP_FAILURE	4

static const struct tok eap_code_values[] = {
    { EAP_REQUEST,	"Request" },
    { EAP_RESPONSE,	"Response" },
    { EAP_SUCCESS,	"Success" },
    { EAP_FAILURE,	"Failure" },
    { 0, NULL}
};

#define		EAP_TYPE_NO_PROPOSED	0
#define		EAP_TYPE_IDENTITY	1
#define		EAP_TYPE_NOTIFICATION	2
#define		EAP_TYPE_NAK		3
#define		EAP_TYPE_MD5_CHALLENGE	4
#define		EAP_TYPE_OTP		5
#define		EAP_TYPE_GTC		6
#define		EAP_TYPE_EXPANDED_TYPES	254
#define		EAP_TYPE_EXPERIMENTAL	255

static const struct tok eap_type_values[] = {
    { EAP_TYPE_NO_PROPOSED,	"No proposed" },
    { EAP_TYPE_IDENTITY,	"Identity" },
    { EAP_TYPE_NOTIFICATION,    "Notification" },
    { EAP_TYPE_NAK,      	"Nak" },
    { EAP_TYPE_MD5_CHALLENGE,   "MD5-challenge" },
    { EAP_TYPE_OTP,      	"OTP" },
    { EAP_TYPE_GTC,      	"GTC" },
    { EAP_TYPE_EXPANDED_TYPES,  "Expanded types" },
    { EAP_TYPE_EXPERIMENTAL,    "Experimental" },
    { 0, NULL}
};  

/*
 * Print EAP requests / responses
 */
void
eap_print(netdissect_options *ndo _U_,
          register const u_char *cp,
          u_int length _U_)
{
    const struct eap_frame_t *eap;
    const u_char *tptr;
    u_int tlen, type, subtype;
    int count=0, len;
    
    tptr = cp;
    tlen = length;
    eap = (const struct eap_frame_t *)cp;
    TCHECK(*eap);

    /* in non-verbose mode just lets print the basic info */
    if (vflag < 1) {
	printf("%s (%u) v%u, len %u",
               tok2str(eap_frame_type_values, "unknown", eap->type),
               eap->type,
               eap->version,
               EXTRACT_16BITS(eap->length));
	return;
    }
  
    printf("%s (%u) v%u, len %u", 
           tok2str(eap_frame_type_values, "unknown", eap->type),
           eap->type,
           eap->version,
           EXTRACT_16BITS(eap->length));

    tptr += sizeof(const struct eap_frame_t);
    tlen -= sizeof(const struct eap_frame_t);

    switch (eap->type) {
    case EAP_FRAME_TYPE_PACKET:
        type = *(tptr);
        len = EXTRACT_16BITS(tptr+2);
        printf(", %s (%u), id %u, len %u",
               tok2str(eap_code_values, "unknown", type),
               type,
               *(tptr+1),
               len);

        if (!TTEST2(*tptr, len)) 
            goto trunc;

        if (type <= 2) { /* For EAP_REQUEST and EAP_RESPONSE only */
            subtype = *(tptr+4);
            printf("\n\t\t Type %s (%u)",
                   tok2str(eap_type_values, "unknown", *(tptr+4)),
                   *(tptr+4));

            switch (subtype) {	
            case EAP_TYPE_IDENTITY:
                if (len - 5 > 0) {
                    printf(", Identity: ");
                    safeputs((const char *)tptr+5, len-5);
                }
                break;

            case EAP_TYPE_NOTIFICATION:
                if (len - 5 > 0) {
                    printf(", Notification: ");
                    safeputs((const char *)tptr+5, len-5);
                }
                break;

            case EAP_TYPE_NAK:
                count = 5;

                /*
                 * one or more octets indicating
                 * the desired authentication
                 * type one octet per type
                 */
                while (count < len) {	
                    printf(" %s (%u),", 
                           tok2str(eap_type_values, "unknown", *(tptr+count)),
                           *(tptr+count));
                    count++;
                }
                break;

            case EAP_TYPE_MD5_CHALLENGE:	
            case EAP_TYPE_OTP:
            case EAP_TYPE_GTC:
            case EAP_TYPE_EXPANDED_TYPES:
            case EAP_TYPE_EXPERIMENTAL:
            default:
                break;
            }
        }
        break;	

    case EAP_FRAME_TYPE_LOGOFF:
    case EAP_FRAME_TYPE_ENCAP_ASF_ALERT:
    default:
        break;
    }
    return;

 trunc:
    printf("\n\t[|EAP]");
}

/*
 * Local Variables:
 * c-basic-offset: 4
 * End:
 */
