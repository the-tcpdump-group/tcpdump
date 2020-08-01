/* Copyright (c) 2015, bugyo
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
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

/* \summary: Network Service Header (NSH) printer */

/* specification: draft-ietf-sfc-nsh-01 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "netdissect-stdinc.h"

#include "netdissect.h"
#include "extract.h"

static const struct tok nsh_flags [] = {
    { 0x20, "O" },
    { 0x10, "C" },
    { 0, NULL }
};

#define NSH_BASE_HDR_LEN 4
#define NSH_SERVICE_PATH_HDR_LEN 4
#define NSH_HDR_WORD_SIZE 4U

void
nsh_print(netdissect_options *ndo, const u_char *bp, u_int len)
{
    u_int n, vn;
    uint8_t ver;
    uint8_t flags;
    u_int length;
    uint8_t md_type;
    uint8_t next_protocol;
    uint32_t service_path_id;
    uint8_t service_index;
    uint32_t ctx;
    uint16_t tlv_class;
    uint8_t tlv_type;
    uint8_t tlv_len;
    u_int next_len;

    ndo->ndo_protocol = "nsh";
    /* print Base Header and Service Path Header */
    if (len < NSH_BASE_HDR_LEN + NSH_SERVICE_PATH_HDR_LEN)
        goto trunc;

    ND_TCHECK_LEN(bp, NSH_BASE_HDR_LEN + NSH_SERVICE_PATH_HDR_LEN);

    ver = (uint8_t)(GET_U_1(bp) >> 6);
    flags = GET_U_1(bp);
    bp += 1;
    length = GET_U_1(bp);
    bp += 1;
    md_type = GET_U_1(bp);
    bp += 1;
    next_protocol = GET_U_1(bp);
    bp += 1;
    service_path_id = GET_BE_U_3(bp);
    bp += 3;
    service_index = GET_U_1(bp);
    bp += 1;

    ND_PRINT("NSH, ");
    if (ndo->ndo_vflag > 1) {
        ND_PRINT("ver %u, ", ver);
    }
    ND_PRINT("flags [%s], ", bittok2str_nosep(nsh_flags, "none", flags));
    if (ndo->ndo_vflag > 2) {
        ND_PRINT("length %u, ", length);
        ND_PRINT("md type 0x%x, ", md_type);
    }
    if (ndo->ndo_vflag > 1) {
        ND_PRINT("next-protocol 0x%x, ", next_protocol);
    }
    ND_PRINT("service-path-id 0x%06x, ", service_path_id);
    ND_PRINT("service-index 0x%x", service_index);

    /* Make sure we have all the headers */
    if (len < length * NSH_HDR_WORD_SIZE)
        goto trunc;

    ND_TCHECK_LEN(bp, length * NSH_HDR_WORD_SIZE);

    /*
     * length includes the lengths of the Base and Service Path headers.
     * That means it must be at least 2.
     */
    if (length < 2)
        goto trunc;

    /*
     * Print, or skip, the Context Headers.
     * (length - 2) is the length of those headers.
     */
    if (ndo->ndo_vflag > 2) {
        if (md_type == 0x01) {
            for (n = 0; n < length - 2; n++) {
                ctx = GET_BE_U_4(bp);
                bp += NSH_HDR_WORD_SIZE;
                ND_PRINT("\n        Context[%02u]: 0x%08x", n, ctx);
            }
        }
        else if (md_type == 0x02) {
            n = 0;
            while (n < length - 2) {
                tlv_class = GET_BE_U_2(bp);
                bp += 2;
                tlv_type  = GET_U_1(bp);
                bp += 1;
                tlv_len   = GET_U_1(bp);
                bp += 1;

                ND_PRINT("\n        TLV Class %u, Type %u, Len %u",
                          tlv_class, tlv_type, tlv_len);

                n += 1;

                if (length - 2 < n + tlv_len) {
                    ND_PRINT(" ERROR: invalid-tlv-length");
                    return;
                }

                for (vn = 0; vn < tlv_len; vn++) {
                    ctx = GET_BE_U_4(bp);
                    bp += NSH_HDR_WORD_SIZE;
                    ND_PRINT("\n            Value[%02u]: 0x%08x", vn, ctx);
                }
                n += tlv_len;
            }
        }
        else {
            ND_PRINT("ERROR: unknown-next-protocol");
            return;
        }
    }
    else {
        bp += (length - 2) * NSH_HDR_WORD_SIZE;
    }
    ND_PRINT(ndo->ndo_vflag ? "\n    " : ": ");

    /* print Next Protocol */
    next_len = len - length * NSH_HDR_WORD_SIZE;
    switch (next_protocol) {
    case 0x1:
        ip_print(ndo, bp, next_len);
        break;
    case 0x2:
        ip6_print(ndo, bp, next_len);
        break;
    case 0x3:
        ether_print(ndo, bp, next_len, ND_BYTES_AVAILABLE_AFTER(bp), NULL, NULL);
        break;
    default:
        ND_PRINT("ERROR: unknown-next-protocol");
        return;
    }

    return;

trunc:
    nd_print_trunc(ndo);
}

