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

/* \summary: Generic Protocol Extension for VXLAN (VXLAN GPE) printer */

/* specification: draft-ietf-nvo3-vxlan-gpe-12 */

#include <config.h>

#include "netdissect-stdinc.h"

#define ND_LONGJMP_FROM_TCHECK
#include "netdissect.h"
#include "extract.h"

#define VXLAN_GPE_VER   0x30 /* GPE */
#define VXLAN_GPE_SHIFT 4
#define VXLAN_GPE_VER_0 0x0
#define VXLAN_GPE_I     0x08 /* Instance Bit */
#define VXLAN_GPE_P     0x04 /* GPE Next Protocol */
#define VXLAN_GPE_B     0x02 /* GPE BUM Traffic */
#define VXLAN_GPE_O     0x01 /* GPE OAM Flag */

static const struct tok vxlan_gpe_flags [] = {
    { VXLAN_GPE_I, "I" },
    { VXLAN_GPE_P, "P" },
    { VXLAN_GPE_B, "B" },
    { VXLAN_GPE_O, "O" },
    { 0, NULL }
};

#define VXLAN_GPE_PROTO_RESERVED 0x00
#define VXLAN_GPE_PROTO_IPV4     0x01
#define VXLAN_GPE_PROTO_IPV6     0x02
#define VXLAN_GPE_PROTO_ETHERNET 0x03
#define VXLAN_GPE_PROTO_NSH      0x04

#define VXLAN_GPE_HDR_LEN 8

/*
 * VXLAN GPE header, draft-ietf-nvo3-vxlan-gpe-12
 *                   Generic Protocol Extension for VXLAN
 *
 *     0                   1                   2                   3
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |R|R|Ver|I|P|B|O|       Reserved                |Next Protocol  |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                VXLAN Network Identifier (VNI) |   Reserved    |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

void
vxlan_gpe_print(netdissect_options *ndo, const u_char *bp, u_int len)
{
    uint8_t flags, ver;
    uint8_t next_protocol;

    /*
     * XXX - OpenBSD has a single dissector for VXLAN and VXLAN-GPE,
     * using the flag bits to distinguish between them.
     *
     * draft-ietf-nvo3-vxlan-gpe-12, the final VXLAN-GPE draft, says
     * that VXLAN-GPE uses port 4790, rather than VXLAN's port 4789,
     * and that the P flag bit must be set for VXLAN-GPE packets,
     * indicating that the header includes a "next protocol" field,
     * and that if a packet with the P it not set is received on
     * port 4790, "the "Next Protocol" field must be set to zero and
     * the payload MUST be ETHERNET(L2) as defined by [RFC7348]."
     */
    ndo->ndo_protocol = "vxlan_gpe";
    ND_PRINT("VXLAN-GPE, ");
    if (len < VXLAN_GPE_HDR_LEN) {
        ND_PRINT(" (len %u < %u)", len, VXLAN_GPE_HDR_LEN);
        goto invalid;
    }

    flags = GET_U_1(bp);
    bp += 1;
    len -= 1;
    ver = (flags & VXLAN_GPE_VER) >> VXLAN_GPE_SHIFT;
    if (ver != VXLAN_GPE_VER_0) {
        ND_PRINT("unknown version %u", ver);
        goto invalid;
    }
    ND_PRINT("flags [%s], ",
              bittok2str_nosep(vxlan_gpe_flags, "none", flags));

    /* Reserved */
    bp += 2;
    len -= 2;

    /*
     * If the VXLAN_GPE_P flag bit isn't set, that means this is a VXLAN
     * packet, not a VXLAN-GPE packet, and thus has no "next protocol"
     * field; the payload is Ethernet.
     */
    if (flags & VXLAN_GPE_P)
        next_protocol = GET_U_1(bp);
    else
        next_protocol = VXLAN_GPE_PROTO_ETHERNET;
    bp += 1;
    len -= 1;

    /*
     * Both RFC 7348 and draft-ietf-nvo3-vxlan-gpe-12 say that the I flag
     * MUST be set.
     */
    if (flags & VXLAN_GPE_I)
        ND_PRINT("vni %u", GET_BE_U_3(bp));
    else
        ND_PRINT("ERROR: I flag not set");
    bp += 3;
    len -= 3;

    if (flags & VXLAN_GPE_B)
        ND_PRINT(", BUM");

    if (flags & VXLAN_GPE_O) {
        ND_PRINT(", OAM (proto 0x%x, len %u)", next_protocol, len);
        return;
    }

    /* Reserved */
    ND_TCHECK_1(bp);
    bp += 1;
    len -= 1;

    ND_PRINT(ndo->ndo_vflag ? "\n    " : ": ");

    switch (next_protocol) {
    case VXLAN_GPE_PROTO_IPV4:
        ip_print(ndo, bp, len);
        break;
    case VXLAN_GPE_PROTO_IPV6:
        ip6_print(ndo, bp, len);
        break;
    case VXLAN_GPE_PROTO_ETHERNET:
        ether_print(ndo, bp, len, ND_BYTES_AVAILABLE_AFTER(bp), NULL, NULL);
        break;
    case VXLAN_GPE_PROTO_NSH:
        nsh_print(ndo, bp, len);
        break;
    /*
     * OpenBSD supports 0x05 for MPLS, which was in earlier drafts
     * of VXLAN GPE, but not in the final -12 draft.
     */
    default:
        ND_PRINT("ERROR: unknown-next-protocol");
        goto invalid;
    }

    return;

invalid:
    nd_print_invalid(ndo);
}

