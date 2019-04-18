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
 * Original code by Francesco Fondelli (francesco dot fondelli, gmail dot com)
 */

/* \summary: Virtual eXtensible Local Area Network (VXLAN) printer */

/* specification: RFC 7348 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "netdissect-stdinc.h"

#include "netdissect.h"
#include "extract.h"


#define VXLAN_HDR_LEN 8

/*
 * VXLAN header, RFC7348
 *               Virtual eXtensible Local Area Network (VXLAN): A Framework
 *               for Overlaying Virtualized Layer 2 Networks over Layer 3 Networks
 *
 *     0                   1                   2                   3
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |R|R|R|R|I|R|R|R|            Reserved                           |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                VXLAN Network Identifier (VNI) |   Reserved    |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

void
vxlan_print(netdissect_options *ndo, const u_char *bp, u_int len)
{
    uint8_t flags;
    uint32_t vni;

    ndo->ndo_protocol = "vxlan";
    if (len < VXLAN_HDR_LEN)
        goto trunc;

    ND_TCHECK_LEN(bp, VXLAN_HDR_LEN);

    flags = GET_U_1(bp);
    bp += 4;

    vni = GET_BE_U_3(bp);
    bp += 4;

    ND_PRINT("VXLAN, ");
    ND_PRINT("flags [%s] (0x%02x), ", flags & 0x08 ? "I" : ".", flags);
    ND_PRINT("vni %u\n", vni);

    ether_print(ndo, bp, len - VXLAN_HDR_LEN, ND_BYTES_AVAILABLE_AFTER(bp), NULL, NULL);

    return;

trunc:
    nd_print_trunc(ndo);
}
