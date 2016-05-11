/* Copyright (c) 2015, The TCPDUMP project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <netdissect-stdinc.h>

#include <string.h>

#include "netdissect.h"
#include "extract.h"

static const char tstr[] = " [|coap]";

struct coap_header {
    uint8_t coap_vt;
#define COAP_VER(c) (((c)->coap_vt & 0xc0) >> 6)
#define COAP_TYPE(c) (((c)->coap_vt & 0x30) >> 4)
#define COAP_TKL(c) ((c)->coap_vt & 0x0f)
    uint8_t coap_code;
#define COAP_CODE_CL(c) (((c)->coap_code & 0xe0) >> 5)
#define COAP_CODE_DL(c) ((c)->coap_code & 0x1f)
    uint16_t msg_id;
} UNALIGNED;

static const struct tok MessageTypes[] = {
    { 0, "CON" },
    { 1, "NON" },
    { 2, "ACK" },
    { 3, "RST" },
    { 0, NULL }
};

#define REQUEST_MSG_CLASS 0
#define SUCCESS_MSG_CLASS 2
#define CLIENT_ERR_MSG_CLASS 4
#define SERVER_ERR_MSG_CLASS 5

static const struct tok RequestCodes[] = {
    { 1, "GET" },
    { 2, "POST" },
    { 3, "PUT" },
    { 4, "DELETE" },
    { 0, NULL }
};

static const struct tok SuccessCodes[] = {
    { 1, "Created" },
    { 2, "Deleted" },
    { 3, "Valid" },
    { 4, "Changed" },
    { 5, "Content" },
    { 0, NULL }
};

static const struct tok ClientErrorCodes[] = {
    { 0, "Bad request" },
    { 1, "Unauthorized" },
    { 2, "Bad option" },
    { 3, "Forbidden" },
    { 4, "Not found" },
    { 5, "Method not allowed" },
    { 0, NULL }
};

static const struct tok ServerErrorCodes[] = {
    { 0, "Internal server error" },
    { 1, "Not implemented" },
    { 2, "Bad gateway" },
    { 3, "Service unavaliable" },
    { 4, "Gateway timeout" },
    { 5, "Proxy not supported" },
    { 0, NULL }
};

#define OPT_IF_MATCH 1
#define OPT_URI_HOST 3
#define OPT_ETAG 4
#define OPT_IF_NONE_MATCH 5
#define OPT_OBSERVE 6
#define OPT_URI_PORT 7
#define OPT_LOCATION_PATH 8
#define OPT_URI_PATH 11
#define OPT_CONTENT_FORMAT 12
#define OPT_MAX_AGE 14
#define OPT_URI_QUERY 15
#define OPT_ACCEPT 17
#define OPT_LOCATION_QUERY 20
#define OPT_PROXY_URI 35
#define OPT_PROXY_SCHEME 39
#define OPT_SIZE1 60

#define OPT_PROXY_URI_STRING_MAXLEN 1034

#define OPT_OPAQUE_MAXLEN 8
#define OPT_EMPTY_MAXLEN 0
#define OPT_STRING_MAXLEN 255
#define OPT_UINT16_MAXLEN (sizeof(uint16_t))
#define OPT_UINT32_MAXLEN (sizeof(uint32_t))

/* https://tools.ietf.org/html/rfc7641#section-2 */
#define OPT_OBSERVE_MAXLEN 3

static const struct tok CoapOptions[] = {
    { OPT_IF_MATCH, "If-Match"},
    { OPT_URI_HOST, "Uri-Host"},
    { OPT_ETAG, "ETag"},
    { OPT_IF_NONE_MATCH, "If-None-Match"},
    { OPT_OBSERVE, "Observe"},
    { OPT_URI_PORT, "Uri-Port"},
    { OPT_LOCATION_PATH, "Location-Path"},
    { OPT_URI_PATH, "Uri-Path"},
    { OPT_CONTENT_FORMAT, "Content-Format"},
    { OPT_MAX_AGE, "Max-Age"},
    { OPT_URI_QUERY, "Uri-Query"},
    { OPT_ACCEPT, "Accept"},
    { OPT_LOCATION_QUERY, "Location-Query"},
    { OPT_PROXY_URI, "Proxy-Uri"},
    { OPT_PROXY_SCHEME, "Proxy-Scheme"},
    { OPT_SIZE1, "Size1"},
    { 0, NULL }
};

static const struct tok ContentTypes[] = {
    { 0,    "text/plain;charset=utf-8" },
    { 40,   "application/link-format" },
    { 41,   "application/xml" },
    { 42,   "application/octet-stream" },
    { 47,   "application/exi" },
    { 50,   "application/json" },
    { 1541, "application/vnd.oma.lwm2m+text" },
    { 1542, "application/vnd.oma.lwm2m+tlv" },
    { 1543, "application/vnd.oma.lwm2m+json" },
    { 1544, "application/vnd.oma.lwm2m+opaque" },
    { 0, NULL }
};

typedef void oprint_func_t(netdissect_options *, const u_char *, const u_int, uint16_t);

static void
oprint_opaque(netdissect_options *ndo, const u_char *buf, const u_int len, uint16_t opt) {
    const u_char *p = buf;
    size_t n;

    (void) opt;

    ND_PRINT((ndo, "{"));
    if (len > 0) {
        ND_PRINT((ndo, "0x"));
        for (n = 0; n < len; n++, p++) {
            ND_PRINT((ndo, "%02x", *(const uint8_t *) p));
        }
    }
    ND_PRINT((ndo, "}"));
}

static void
oprint_string(netdissect_options *ndo, const u_char *buf, const u_int len, uint16_t opt) {
    (void) opt;
    if (len > OPT_STRING_MAXLEN) {
        ND_PRINT((ndo, "%%string option is too long%%"));
        return;
    }
    fn_print(ndo, buf, buf+len);
}

static void
oprint_empty(netdissect_options *ndo, const u_char *buf, const u_int len, uint16_t opt) {
    (void) buf;
    (void) len;
    (void) opt;
    ND_PRINT((ndo, "[Empty]"));
}

static void
oprint_int(netdissect_options *ndo, const u_char *buf, const u_int len, uint16_t opt) {
    uint32_t b = 0;
    memcpy((u_char *) &b + (sizeof(b) - len), buf, len);
    switch (opt) {
        case OPT_CONTENT_FORMAT:
            ND_PRINT((ndo, "%s", tok2str(ContentTypes, NULL, EXTRACT_32BITS(&b))));
            break;
        default:
            ND_PRINT((ndo, "%i", EXTRACT_32BITS(&b)));
    }
}

static oprint_func_t *
get_oprint_func(uint16_t opt, size_t len) {
    /* If the length of an option value in a request is outside the defined
     * range, that option MUST be treated like an unrecognized option.
     */
    switch (opt) {
    case OPT_ETAG:
        if (len == 0) return NULL;
    case OPT_IF_MATCH:
        return (len <= OPT_OPAQUE_MAXLEN) ? oprint_opaque : NULL;
    case OPT_OBSERVE:
        return (len <= OPT_OBSERVE_MAXLEN) ? oprint_int : NULL;
    case OPT_PROXY_URI:
        return (len > 0 && len <= OPT_PROXY_URI_STRING_MAXLEN) ? oprint_string : NULL;
    case OPT_URI_HOST:
    case OPT_PROXY_SCHEME:
        return (len > 0 && len <= OPT_STRING_MAXLEN) ? oprint_string : NULL;
    case OPT_LOCATION_PATH:
    case OPT_URI_PATH:
    case OPT_URI_QUERY:
    case OPT_LOCATION_QUERY:
        return (len <= OPT_STRING_MAXLEN) ? oprint_string : NULL;
    case OPT_URI_PORT:
    case OPT_ACCEPT:
    case OPT_CONTENT_FORMAT:
        return (len <= OPT_UINT16_MAXLEN) ? oprint_int : NULL;
    case OPT_MAX_AGE:
    case OPT_SIZE1:
        return (len <= OPT_UINT32_MAXLEN) ? oprint_int : NULL;
    case OPT_IF_NONE_MATCH:
        return (len <= OPT_EMPTY_MAXLEN) ? oprint_empty : NULL;
    };
    return NULL;
}

#define COAP_PAYLOAD_MARKER 0xff

/*
 *    0   1   2   3   4   5   6   7
 *  +---------------+---------------+
 *  |               |               |
 *  |  Option Delta | Option Length |   1 byte
 *  |               |               |
 *  +---------------+---------------+
 *  \                               \
 *  /         Option Delta          /   0-2 bytes
 *  \          (extended)           \
 *  +-------------------------------+
 *  \                               \
 *  /         Option Length         /   0-2 bytes
 *  \          (extended)           \
 *  +-------------------------------+
 *  \                               \
 *  /                               /
 *  \                               \
 *  /         Option Value          /   0 or more bytes
 *  \                               \
 *  /                               /
 *  \                               \
 *  +-------------------------------+
 */
static void
coap_print_options(netdissect_options *ndo, const u_char *buf, const u_int size)
{
#define EXT_BYTE_CODE 13
#define EXT_WORD_CODE 14
#define EXT_BYTE_ADDEND 13
#define EXT_WORD_ADDEND 269

#define EXT_OPT(opt) {\
    switch (opt) {\
    case EXT_BYTE_CODE:\
        ND_TCHECK2(*p, sizeof(uint8_t));\
        opt = ((uint8_t) (*p++)) + EXT_BYTE_ADDEND;\
        break;\
    case EXT_WORD_CODE:\
        ND_TCHECK2(*p, sizeof(uint16_t));\
        opt = (uint16_t) (EXTRACT_16BITS((const uint16_t *) p)) + EXT_WORD_ADDEND;\
        p += sizeof(uint16_t);\
        break;\
    }\
}
    const u_char *p = buf;
    const char *optstr = NULL;

    uint16_t option = 0;
    uint16_t len, delta;

    while (buf + size > p) {
        oprint_func_t *opf;

        if (*p == COAP_PAYLOAD_MARKER) {
            ND_PRINT((ndo, " [Payload %u bytes]", size - (unsigned) (p - buf)));
            return;
        }

        delta = ((*p) & 0xf0) >> 4;
        len = (*p) & 0xf;

        if (delta == 0xf || len == 0xf) {
            goto corrupt;
        }

        p++;

        EXT_OPT(delta);
        EXT_OPT(len);

        option += delta;

        optstr = tok2str(CoapOptions, NULL, option);
        opf = get_oprint_func(option, len);

        if (opf) {
            ND_TCHECK2(*p, len);
            ND_PRINT((ndo, " %s=", optstr));
            opf(ndo, p, len, option);
        } else {
            ND_PRINT((ndo, " Unknown-Opt(%d)", option));
        }
        p += len;
    }
    return;

corrupt:
    ND_PRINT((ndo, "%s", istr));
    ND_TCHECK2(*buf, size);
    return;
trunc:
    ND_PRINT((ndo, "%s", tstr));
}

/*
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |Ver| T |  TKL  |      Code     |          Message ID           |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |   Token (if any, TKL bytes) ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |   Options (if any) ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |1 1 1 1 1 1 1 1|    Payload (if any) ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
void
coap_print(netdissect_options *ndo, const u_char *buf, const u_int size)
{
    const struct coap_header *hdr = (const struct coap_header *) buf;
    const struct tok *code_details;
    const u_char *p = buf + sizeof(struct coap_header);

    if (size < sizeof(struct coap_header))
        goto corrupt;

    ND_TCHECK(*hdr);
    if (COAP_VER(hdr) != 1)
        return;

    code_details =
        COAP_CODE_CL(hdr) == REQUEST_MSG_CLASS ? RequestCodes :
        COAP_CODE_CL(hdr) == SUCCESS_MSG_CLASS ? SuccessCodes :
        COAP_CODE_CL(hdr) == CLIENT_ERR_MSG_CLASS ? ClientErrorCodes :
        COAP_CODE_CL(hdr) == SERVER_ERR_MSG_CLASS ? ServerErrorCodes :
        NULL;

    ND_PRINT((ndo, "CoAP<0x%04x[%s]> ",
             EXTRACT_16BITS(&hdr->msg_id), tok2str(MessageTypes, "Unknown", COAP_TYPE(hdr))));

    if (COAP_TKL(hdr)) {
        int n, tkl;
        tkl = COAP_TKL(hdr);
        ND_TCHECK2(*p, tkl);
        ND_PRINT((ndo, "0x"));
        for (n = 0; n < tkl; n++, p++) {
            ND_PRINT((ndo, "%02x", *p));
        }
    } else {
        ND_PRINT((ndo, "-"));
    }

    ND_PRINT((ndo, " %i.%02i", COAP_CODE_CL(hdr), COAP_CODE_DL(hdr)));
    ND_PRINT((ndo, " %s:", code_details ? tok2str(code_details, "Unknown", COAP_CODE_DL(hdr)) : "Unknown"));

    coap_print_options(ndo, p, size - (p - buf));
    return;

corrupt:
    ND_PRINT((ndo, "%s", istr));
    ND_TCHECK2(*buf, size);
    return;
trunc:
    ND_PRINT((ndo, "%s", tstr));
}
