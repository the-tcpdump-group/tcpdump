/*
 * Copyright (c) 2020 George Hopkins <george-hopkins@null.net>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in
 *      the documentation and/or other materials provided with the
 *      distribution.
 *   3. The names of the authors may not be used to endorse or promote
 *      products derived from this software without specific prior
 *      written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

/* \summary: Linux netlink printer */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "netdissect-stdinc.h"

#include "netdissect.h"
#include "extract.h"

#define abs_diff(a, b) ((a) > (b) ? (a) - (b) : (b) - (a))

static const struct tok netlink_family[] = {
    { 0, "Route" },
    { 2, "User-mode socket protocols" },
    { 3, "IPv4 user space queueing" },
    { 4, "Socket monitoring" },
    { 5, "Netfilter ULOG" },
    { 6, "IPsec" },
    { 7, "SELinux" },
    { 8, "Open-iSCSI" },
    { 9, "Auditing" },
    { 10, "FIB lookup" },
    { 11, "Kernel connector" },
    { 12, "Netfilter" },
    { 13, "IPv6 user space queueing" },
    { 14, "DECnet routing" },
    { 15, "Kernel messages to userspace" },
    { 16, "Generic" },
    { 18, "SCSI Transport" },
    { 19, "ecryptfs" },
    { 20, "RDMA" },
    { 21, "Crypto" },
    { 22, "SMC" },
    { 0, NULL }
};

struct netlink_hdr {
    nd_uint8_t  reserved[14];
    nd_uint16_t family;
};

struct netlink_msg {
    nd_uint32_t length;
    nd_uint16_t type;
    nd_uint16_t flags;
    nd_uint32_t sequence;
    nd_uint32_t pid;
};

static u_int
netlink_msg_print(netdissect_options *ndo, const u_char *p, const u_int caplen)
{
    const struct netlink_msg *msg = (const struct netlink_msg *)p;
    uint8_t le;
    uint32_t length, length_le, length_be;

    if (caplen < sizeof(struct netlink_msg)) {
        return 0;
    }

    /**
     * We do not know the endianness of the capture host. We assume
     * that the reported length approximately matches the captured length.
     * Usually this assumption holds because packet lengths rarely need
     * more than 16 bits.
     */
    length_le = GET_LE_U_4(msg->length);
    length_be = GET_BE_U_4(msg->length);
    le = abs_diff(length_le, caplen) < abs_diff(length_be, caplen);
    length = le ? length_le : length_be;

    ND_PRINT("\n\ttype %u, length %u, flags 0x%04x, sequence %u, pid %u",
             le ? GET_LE_U_2(msg->type) : GET_BE_U_2(msg->type),
             length,
             le ? GET_LE_U_2(msg->flags) : GET_BE_U_2(msg->flags),
             le ? GET_LE_U_4(msg->sequence) : GET_BE_U_4(msg->sequence),
             le ? GET_LE_U_4(msg->pid) : GET_BE_U_4(msg->pid));

    if (caplen < length) {
        return 0;
    }

    return length;
}

static void
netlink_hdr_print(netdissect_options *ndo, const u_char *p, const u_int caplen)
{
    const struct netlink_hdr *hdr = (const struct netlink_hdr *)p;
    uint16_t family;
    u_int offset = sizeof(struct netlink_hdr);
    u_int ret = 0;

    family = GET_BE_U_2(hdr->family);
    ND_PRINT("%s: length %u", tok2str(netlink_family, "0x%04x", family),
             caplen);

    if (ndo->ndo_vflag) {
        while (offset < caplen) {
            ret = netlink_msg_print(ndo, p + offset, caplen);
            if (ret == 0) {
                nd_print_trunc(ndo);
                break;
            }
            offset += ret;
        }
    }
}

void
netlink_if_print(netdissect_options *ndo, const struct pcap_pkthdr *h,
           const u_char *cp)
{
    u_int caplen = h->caplen;

    ndo->ndo_protocol = "netlink";

    if (caplen < sizeof(struct netlink_hdr)) {
        nd_print_trunc(ndo);
        ndo->ndo_ll_hdr_len += caplen;
        return;
    }

    ndo->ndo_ll_hdr_len += sizeof(struct netlink_hdr);
    netlink_hdr_print(ndo, cp, caplen);
}
