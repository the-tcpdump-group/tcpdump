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
 */

/* \summary: Extensible Authentication Protocol (EAP) printer */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "netdissect-stdinc.h"

#include "netdissect.h"
#include "extract.h"

#define	EAP_FRAME_TYPE_PACKET		0
#define	EAP_FRAME_TYPE_START		1
#define	EAP_FRAME_TYPE_LOGOFF		2
#define	EAP_FRAME_TYPE_KEY		3
#define	EAP_FRAME_TYPE_ENCAP_ASF_ALERT	4
#define	EAP_FRAME_TYPE_MKA		5

struct eap_frame_t {
    nd_uint8_t  version;
    nd_uint8_t  type;
    nd_uint16_t length;
};

static const struct tok eap_frame_type_values[] = {
    { EAP_FRAME_TYPE_PACKET,      	"EAP packet" },
    { EAP_FRAME_TYPE_START,    		"EAPOL start" },
    { EAP_FRAME_TYPE_LOGOFF,      	"EAPOL logoff" },
    { EAP_FRAME_TYPE_KEY,      		"EAPOL key" },
    { EAP_FRAME_TYPE_ENCAP_ASF_ALERT, 	"Encapsulated ASF alert" },
    { EAP_FRAME_TYPE_MKA,              "EAPOL-MKA" },
    { 0, NULL}
};

#define MACSEC_CAP_NONE                 0
#define MACSEC_CAP_INTEGRITY_ONLY       1
#define MACSEC_CAP_INT_CONF             2
#define MACSEC_CAP_INT_CONF_WITH_OFFSET 3

static const struct tok eapol_mka_macsec_cap_values[] = {
	{ MACSEC_CAP_NONE,
		"MACsec is not implemented" },
	{ MACSEC_CAP_INTEGRITY_ONLY,
		"Integrity without confidentiality" },
	{ MACSEC_CAP_INT_CONF,
		"Integrity with confidentiality / no confidentiality offset" },
	{ MACSEC_CAP_INT_CONF_WITH_OFFSET,
		"Integrity with confidentiality / confidentiality offset" },
	{ 0, NULL }
};

/* RFC 3748 */
struct eap_packet_t {
    nd_uint8_t  code;
    nd_uint8_t  id;
    nd_uint16_t length;
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
#define		EAP_TYPE_TLS		13		/* RFC 2716 */
#define		EAP_TYPE_SIM		18		/* RFC 4186 */
#define		EAP_TYPE_TTLS		21		/* draft-funk-eap-ttls-v0-01.txt */
#define		EAP_TYPE_AKA		23		/* RFC 4187 */
#define		EAP_TYPE_FAST		43		/* RFC 4851 */
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
    { EAP_TYPE_TLS,      	"TLS" },
    { EAP_TYPE_SIM,      	"SIM" },
    { EAP_TYPE_TTLS,      	"TTLS" },
    { EAP_TYPE_AKA,      	"AKA" },
    { EAP_TYPE_FAST,      	"FAST" },
    { EAP_TYPE_EXPANDED_TYPES,  "Expanded types" },
    { EAP_TYPE_EXPERIMENTAL,    "Experimental" },
    { 0, NULL}
};

#define EAP_TLS_EXTRACT_BIT_L(x) 	(((x)&0x80)>>7)

/* RFC 2716 - EAP TLS bits */
#define EAP_TLS_FLAGS_LEN_INCLUDED		(1 << 7)
#define EAP_TLS_FLAGS_MORE_FRAGMENTS		(1 << 6)
#define EAP_TLS_FLAGS_START			(1 << 5)

static const struct tok eap_tls_flags_values[] = {
	{ EAP_TLS_FLAGS_LEN_INCLUDED, "L bit" },
	{ EAP_TLS_FLAGS_MORE_FRAGMENTS, "More fragments bit"},
	{ EAP_TLS_FLAGS_START, "Start bit"},
	{ 0, NULL}
};

#define EAP_TTLS_VERSION(x)		((x)&0x07)

/* EAP-AKA and EAP-SIM - RFC 4187 */
#define EAP_AKA_CHALLENGE		1
#define EAP_AKA_AUTH_REJECT		2
#define EAP_AKA_SYNC_FAILURE		4
#define EAP_AKA_IDENTITY		5
#define EAP_SIM_START			10
#define EAP_SIM_CHALLENGE		11
#define EAP_AKA_NOTIFICATION		12
#define EAP_AKA_REAUTH			13
#define EAP_AKA_CLIENT_ERROR		14

static const struct tok eap_aka_subtype_values[] = {
    { EAP_AKA_CHALLENGE,	"Challenge" },
    { EAP_AKA_AUTH_REJECT,	"Auth reject" },
    { EAP_AKA_SYNC_FAILURE,	"Sync failure" },
    { EAP_AKA_IDENTITY,		"Identity" },
    { EAP_SIM_START,		"Start" },
    { EAP_SIM_CHALLENGE,	"Challenge" },
    { EAP_AKA_NOTIFICATION,	"Notification" },
    { EAP_AKA_REAUTH,		"Reauth" },
    { EAP_AKA_CLIENT_ERROR,	"Client error" },
    { 0, NULL}
};

static uint16_t
get_parameter_set_body_length(netdissect_options *ndo, const u_char *p)
{
       uint16_t x = GET_BE_U_2(p);
       return (uint16_t) ((x & 0xFFF));
}

static void
decode_mka_parameter_set(
               netdissect_options *ndo,
               const u_char *p,
               const uint32_t index,
               const uint16_t parameter_set_body_len)
{
    uint32_t i = 0;
    while (i < parameter_set_body_len) {
        if (i % 20 == 0) {
            ND_PRINT("\n\t\t %02x",  GET_U_1(p + index + 4 + i));
        }
        else {
            ND_PRINT("%02x", GET_U_1(p + index + 4 + i));
        }
        i++;
    }
}

static void
decode_mka_peer_list_parameter_sets(
               netdissect_options *ndo,
               const u_char *p,
               uint32_t index,
               const uint16_t parameter_set_body_len)
{
    uint32_t i, n;

    ND_PRINT("\n\t\t Parameter set body length: %d",
                parameter_set_body_len);
    n = parameter_set_body_len / 16;
    index += 4;
    for (i = 0; i < n; i++) {
        ND_PRINT("\n\t\t Actor's Member Id: 0x%08x%08x%08x",
                    GET_BE_U_4(p + index),
                    GET_BE_U_4(p + index + 4),
                    GET_BE_U_4(p + index + 8));
        ND_PRINT("\n\t\t Actor's Message Number: 0x%08x",
                    GET_BE_U_4(p + index + 12));
        index += 16;
    }
}

static void decode_mka_sak_use_parameter_set(
               netdissect_options *ndo,
               const u_char *p,
               uint32_t index,
               const uint16_t parameter_set_body_len)
{
    uint16_t two_bytes = GET_BE_U_2(p + index + 1);
    uint8_t latest_key_an = (uint8_t) ((two_bytes & 0xC000) >> 14);
    uint8_t latest_key_tx = (uint8_t) ((two_bytes & 0x2000) >> 13);
    uint8_t latest_key_rx = (uint8_t) ((two_bytes & 0x1000) >> 12);
    uint8_t old_key_an = (uint8_t) ((two_bytes & 0xC00) >> 10);
    uint8_t old_key_tx = (uint8_t) ((two_bytes & 0x200) >> 9);
    uint8_t old_key_rx = (uint8_t) ((two_bytes & 0x100) >> 8);
    uint8_t plain_tx = (uint8_t) ((two_bytes & 0x80) >> 7);
    uint8_t plain_rx = (uint8_t) ((two_bytes & 0x40) >> 6);
    uint8_t delay_protect = (uint8_t) ((two_bytes & 0x10) >> 4);

    ND_PRINT("\n\t MACsec SAK Use:");
    ND_PRINT("\n\t\t Latest Key AN: %u\
                \n\t\t Latest Key tx: %u\
                \n\t\t Latest Key rx: %u\
                \n\t\t Old Key AN: %u\
                \n\t\t Old Key tx: %u\
                \n\t\t Old Key rx: %u\
                \n\t\t Plain tx: %u\
                \n\t\t Plain rx: %u\
                \n\t\t Delay protect: %u",
                latest_key_an,
                latest_key_tx,
                latest_key_rx,
                old_key_an,
                old_key_tx,
                old_key_rx,
                plain_tx,
                plain_rx,
                delay_protect);
    ND_PRINT("\n\t\t Parameter set body length: %d",
                parameter_set_body_len);
    ND_PRINT("\n\t\t Latest Key - Key Server Member Id: 0x%08x%08x%08x",
                GET_BE_U_4(p + index + 4),
                GET_BE_U_4(p + index + 8),
                GET_BE_U_4(p + index + 12));
    ND_PRINT("\n\t\t Latest Key - Key Number: 0x%08x",
                GET_BE_U_4(p + index + 16));
    ND_PRINT("\n\t\t Latest Key - Lowest Acceptable PN: 0x%08x",
                GET_BE_U_4(p + index + 20));
    ND_PRINT("\n\t\t Old Key - Key Server Member Id: 0x%08x%08x%08x",
                GET_BE_U_4(p + index + 24),
                GET_BE_U_4(p + index + 28),
                GET_BE_U_4(p + index + 32));
    ND_PRINT("\n\t\t Old Key - Key Number: 0x%08x",
                GET_BE_U_4(p + index + 36));
    ND_PRINT("\n\t\t Old Key - Lowest Acceptable PN: 0x%08x",
                GET_BE_U_4(p + index + 40));
}

static void decode_mka_distributed_sak_parameter_set(
               netdissect_options *ndo,
               const u_char *p,
               uint32_t index,
               const uint16_t parameter_set_body_len)
{
    if (parameter_set_body_len > 0) {
        uint16_t two_bytes = GET_BE_U_2(p + index + 1);
        uint8_t dist_an = (uint8_t) ((two_bytes & 0xC000) >> 14);
        uint8_t offset = (uint8_t) ((two_bytes & 0x3000) >> 12);

        ND_PRINT("\n\t Distributed SAK:");
        ND_PRINT("\n\t\t Distributed AN: %u\
                    \n\t\t Confidentiality offset: %u\
                    \n\t\t Parameter set body length: %d\
                    \n\t\t Key Number: 0x%08x",
                        dist_an,
                        offset,
                        parameter_set_body_len,
                        GET_BE_U_4(p + index + 4));
        if (parameter_set_body_len == 28) {
            /*
             * The default cipher suite, GCM-AES-128, is being used.
             * */
            ND_PRINT("\n\t\t AES Key Wrap of SAK: 0x%08x%08x%08x%08x%08x%08x",
                        GET_BE_U_4(p + index + 8),
                        GET_BE_U_4(p + index + 12),
                        GET_BE_U_4(p + index + 16),
                        GET_BE_U_4(p + index + 20),
                        GET_BE_U_4(p + index + 24),
                        GET_BE_U_4(p + index + 28));
        }
        else if (parameter_set_body_len == 36) {
            /*
             * The cipher suite being used is not GCM-AES-128.
             * */
            ND_PRINT("\n\t\t MACsec Cipher Suite: 0x%08x%08x",
                        GET_BE_U_4(p + index + 8),
                        GET_BE_U_4(p + index + 12));
            ND_PRINT("\n\t\t AES Key Wrap of SAK: 0x%08x%08x%08x%08x%08x%08x",
                        GET_BE_U_4(p + index + 16),
                        GET_BE_U_4(p + index + 20),
                        GET_BE_U_4(p + index + 24),
                        GET_BE_U_4(p + index + 28),
                        GET_BE_U_4(p + index + 32),
                        GET_BE_U_4(p + index + 36));
        }
        else {
            /* Unexpected value */
            uint32_t i = 0;
            while (i < parameter_set_body_len) {
                if (i % 20 == 0) {
                    ND_PRINT("\n\t\t %02x", GET_U_1(p + index + 8 + i));
                }
                else {
                    ND_PRINT("%02x", GET_U_1(p + index + 8 + i));
                }
                i++;
            }
        }
    }
    else {
            ND_PRINT("\n\t\t Parameter set body length: %d",
                        parameter_set_body_len);
    }
}

static void decode_mka_distributed_cak_parameter_set(
               netdissect_options *ndo,
               const u_char *p,
               uint32_t index,
               const uint16_t parameter_set_body_len)
{
    ND_PRINT("\n\t Distributed CAK Use:");
    ND_PRINT("\n\t\t Parameter set body length: %d",
                parameter_set_body_len);
    ND_PRINT("\n\t\t AES Key Wrap of CAK: 0x%08x%08x%08x%08x%08x%08x",
                GET_BE_U_4(p + index + 4),
                GET_BE_U_4(p + index + 8),
                GET_BE_U_4(p + index + 12),
                GET_BE_U_4(p + index + 16),
                GET_BE_U_4(p + index + 20),
                GET_BE_U_4(p + index + 24));
    uint32_t cak_name_len = parameter_set_body_len - 24;
    uint32_t i = 0;
    ND_PRINT("\n\t\t CAK Key Name:");
    while (i < cak_name_len) {
        if (i % 20 == 0) {
            ND_PRINT("\n\t\t %02x", GET_U_1(p + index + 28 + i));
        }
        else {
            ND_PRINT("%02x", GET_U_1(p + index + 28 + i));
        }
    }
}

static uint32_t
decode_mka_parameter_sets(netdissect_options *ndo,
                       const u_char *p,
                       uint32_t index)
{
    uint8_t         param_set_type;
    uint16_t        param_set_body_len;
    uint8_t         b = 1;

    param_set_type = GET_U_1(p + index);
    while (b) {
        param_set_body_len = get_parameter_set_body_length(ndo, p + index + 2);
        ND_TCHECK_LEN(p + index, 4 + param_set_body_len);
        switch (param_set_type) {
        case 1:
            /* Live Peer List                       */
            ND_PRINT("\n\t Live Peer List:");
            decode_mka_peer_list_parameter_sets(
                    ndo,
                    p,
                    index,
                    param_set_body_len);
            break;
        case 2:
            /* Potential Peer List                  */
            ND_PRINT("\n\t Potential Peer List:");
            decode_mka_peer_list_parameter_sets(
                    ndo,
                    p,
                    index,
                    param_set_body_len);
            break;
        case 3:
            /* MACsec SAK Use parameter set         */
            decode_mka_sak_use_parameter_set(
                    ndo,
                    p,
                    index,
                    param_set_body_len);
            break;
        case 4:
            /* Distributed SAK parameter set        */
            decode_mka_distributed_sak_parameter_set(
                    ndo,
                    p,
                    index,
                    param_set_body_len);
            break;
        case 5:
            /* Distributed CAK parameter set        */
            decode_mka_distributed_cak_parameter_set(
                    ndo,
                    p,
                    index,
                    param_set_body_len);
            break;

        default:
            ND_PRINT("\n\t Unknown parameter set (%d):",
                        param_set_type);
            ND_PRINT("\n\t\t Parameter set body length: %d",
                        param_set_body_len);
            decode_mka_parameter_set(
                ndo,
                p,
                index,
                param_set_body_len);
            break;
        }

        /* Update the index (always 4 + the length of the body) */
        index += 4 + param_set_body_len;

        /* Get next parameter set type  */
        param_set_type = GET_U_1(p + index);
        if (param_set_type == 255) {
            b = 0;
        }
    }
    return index;

trunc:
       ND_PRINT("\n\t[|MKPDU]");

       /* Return last index if ND_TEST2() fails.       */
       return index;
}

/*
 * Print EAP requests / responses
 */
void
eap_print(netdissect_options *ndo,
          const u_char *cp,
          u_int length)
{
    u_int type, subtype, len;
    int count;

    type = GET_U_1(cp);
    len = GET_BE_U_2(cp + 2);
    if(len != length) {
       goto trunc;
    }
    ND_PRINT("%s (%u), id %u, len %u",
            tok2str(eap_code_values, "unknown", type),
            type,
            GET_U_1((cp + 1)),
            len);

    ND_TCHECK_LEN(cp, len);

    if (type == EAP_REQUEST || type == EAP_RESPONSE) {
        /* RFC 3748 Section 4.1 */
        subtype = GET_U_1(cp + 4);
        ND_PRINT("\n\t\t Type %s (%u)",
                tok2str(eap_type_values, "unknown", subtype),
                subtype);

        switch (subtype) {
            case EAP_TYPE_IDENTITY:
                if (len - 5 > 0) {
                    ND_PRINT(", Identity: ");
                    nd_printjnp(ndo, cp + 5, len - 5);
                }
                break;

            case EAP_TYPE_NOTIFICATION:
                if (len - 5 > 0) {
                    ND_PRINT(", Notification: ");
                    nd_printjnp(ndo, cp + 5, len - 5);
                }
                break;

            case EAP_TYPE_NAK:
                count = 5;

                /*
                 * one or more octets indicating
                 * the desired authentication
                 * type one octet per type
                 */
                while (count < (int)len) {
                    ND_PRINT(" %s (%u),",
                           tok2str(eap_type_values, "unknown", GET_U_1((cp + count))),
                           GET_U_1(cp + count));
                    count++;
                }
                break;

            case EAP_TYPE_TTLS:
            case EAP_TYPE_TLS:
                if (subtype == EAP_TYPE_TTLS)
                    ND_PRINT(" TTLSv%u",
                           EAP_TTLS_VERSION(GET_U_1((cp + 5))));
                ND_PRINT(" flags [%s] 0x%02x,",
                       bittok2str(eap_tls_flags_values, "none", GET_U_1((cp + 5))),
                       GET_U_1(cp + 5));

                if (EAP_TLS_EXTRACT_BIT_L(GET_U_1(cp + 5))) {
                    ND_PRINT(" len %u", GET_BE_U_4(cp + 6));
                }
                break;

            case EAP_TYPE_FAST:
                ND_PRINT(" FASTv%u",
                       EAP_TTLS_VERSION(GET_U_1((cp + 5))));
                ND_PRINT(" flags [%s] 0x%02x,",
                       bittok2str(eap_tls_flags_values, "none", GET_U_1((cp + 5))),
                       GET_U_1(cp + 5));

                if (EAP_TLS_EXTRACT_BIT_L(GET_U_1(cp + 5))) {
                    ND_PRINT(" len %u", GET_BE_U_4(cp + 6));
                }

                /* FIXME - TLV attributes follow */
                break;

            case EAP_TYPE_AKA:
            case EAP_TYPE_SIM:
                ND_PRINT(" subtype [%s] 0x%02x,",
                       tok2str(eap_aka_subtype_values, "unknown", GET_U_1((cp + 5))),
                       GET_U_1(cp + 5));

                /* FIXME - TLV attributes follow */
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
    return;
trunc:
    nd_print_trunc(ndo);
}

void
eapol_print(netdissect_options *ndo,
            const u_char *cp)
{
    const struct eap_frame_t *eap;
    u_int eap_type, eap_len;

    ndo->ndo_protocol = "eap";
    eap = (const struct eap_frame_t *)cp;
    ND_TCHECK_SIZE(eap);
    eap_type = GET_U_1(eap->type);

    ND_PRINT("%s (%u) v%u, len %u",
           tok2str(eap_frame_type_values, "unknown", eap_type),
           eap_type,
           GET_U_1(eap->version),
           GET_BE_U_2(eap->length));
    if (ndo->ndo_vflag < 1)
        return;

    cp += sizeof(struct eap_frame_t);
    eap_len = GET_BE_U_2(eap->length);

    switch (eap_type) {
    case EAP_FRAME_TYPE_PACKET:
        if (eap_len == 0)
            goto trunc;
        ND_PRINT(", ");
        eap_print(ndo, cp, eap_len);
        return;
    case EAP_FRAME_TYPE_LOGOFF:
    case EAP_FRAME_TYPE_ENCAP_ASF_ALERT:
       break;
    case EAP_FRAME_TYPE_MKA:
       /* The first parameter set is always the "Basic Parameter Set"  */
       ND_TCHECK_LEN(tptr, 32);

       uint8_t mka_version_id = GET_U_1(tptr);
       uint8_t ks_priority = GET_U_1(tptr + 1);
       uint16_t two_bytes = GET_BE_U_2(tptr + 2);
       uint8_t ks = ((two_bytes & 0x8000) >> 15);
       uint8_t macsec_desired = ((two_bytes & 0x4000) >> 14);
       uint8_t macsec_cap = (uint8_t) ((two_bytes & 0x3000) >> 12);
       uint16_t param_set_body_len = get_parameter_set_body_length(ndo, tptr + 2);

       ND_PRINT("\n\t Basic Parameter Set:");
       ND_PRINT("\n\t\t MKA Version Id: %d", mka_version_id);
       ND_PRINT("\n\t\t Key Server Priority: %d", ks_priority);
       ND_PRINT("\n\t\t Key Server: %d", ks);
       ND_PRINT("\n\t\t MACsec Desired: %d", macsec_desired);
       ND_PRINT("\n\t\t MACsec Capability: %d (%s)",
                   macsec_cap,
                   tok2str(eapol_mka_macsec_cap_values, "none", macsec_cap));
       ND_PRINT("\n\t\t Parameter set body length: %d",
                   param_set_body_len);
       ND_PRINT("\n\t\t SCI: 0x%08x%08x",
                   GET_BE_U_4(tptr + 4),
                   GET_BE_U_4(tptr + 8));
       ND_PRINT("\n\t\t Actor's Member Id: 0x%08x%08x%08x",
                   GET_BE_U_4(tptr + 12),
                   GET_BE_U_4(tptr + 16),
                   GET_BE_U_4(tptr + 20));
       ND_PRINT("\n\t\t Actor's Message Number: 0x%08x",
                   GET_BE_U_4(tptr + 24));
       ND_PRINT("\n\t\t Algorithm Agility: 0x%08x",
                   GET_BE_U_4(tptr + 28));
       uint32_t remaining = param_set_body_len - 28;
       uint32_t index = 32;
       ND_TCHECK_LEN(tptr + index, remaining);
       ND_PRINT("\n\t\t CAK Name: ");
       while (remaining) {
           ND_PRINT("%02x", GET_U_1(tptr + index));
           index++;
           remaining--;
       }

       /* Decode the next parameter sets               */
       if (GET_U_1(tptr + index) < 255) {
           index = decode_mka_parameter_sets(ndo, tptr, index);
       }

       /* ICV Indicator - The last parameter set       */
       ND_TCHECK_LEN(tptr + index, 4);
       ND_PRINT("\n\t ICV Indicator:");
       ND_PRINT("\n\t\t Parameter set type: %d", GET_U_1(tptr + index));
       index += 2;
       uint16_t icv_len = get_parameter_set_body_length(ndo, tptr + index);
       ND_PRINT("\n\t\t ICV length: %d", icv_len);

       /* The ICV itself is at the end of the data     */
       index += 2;
       ND_TCHECK_LEN(tptr + index, icv_len);
       ND_PRINT("\n\t ICV: ");
       while (icv_len) {
           ND_PRINT("%02x", GET_U_1(tptr + index));
           index++;
           icv_len--;
       }
       break;
    default:
        break;
    }
    return;

 trunc:
    nd_print_trunc(ndo);
}
