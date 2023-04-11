/*
 * Copyright (c) 2014 VMware, Inc. All Rights Reserved.
 *
 * Jesse Gross <jesse@nicira.com>
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
 */

/* \summary: Generic Network Virtualization Encapsulation (Geneve) printer */
/* specification: RFC 8926 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "netdissect-stdinc.h"

#define ND_LONGJMP_FROM_TCHECK
#include "netdissect.h"
#include "extract.h"
#include "ethertype.h"

/*
 * Geneve header:
 *
 *    0                   1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |Ver|  Opt Len  |O|C|    Rsvd.  |          Protocol Type        |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |        Virtual Network Identifier (VNI)       |    Reserved   |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                                                               |
 *    ~                    Variable-Length Options                    ~
 *    |                                                               |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Options:
 *    0                   1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |          Option Class         |      Type     |R|R|R| Length  |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                                                               |
 *    ~                  Variable-Length Option Data                  ~
 *    |                                                               |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

#define VER_SHIFT 6
#define HDR_OPTS_LEN_MASK 0x3F

#define FLAG_OAM      (1 << 7)
#define FLAG_CRITICAL (1 << 6)
#define FLAG_R1       (1 << 5)
#define FLAG_R2       (1 << 4)
#define FLAG_R3       (1 << 3)
#define FLAG_R4       (1 << 2)
#define FLAG_R5       (1 << 1)
#define FLAG_R6       (1 << 0)

#define OPT_TYPE_CRITICAL (1 << 7)
#define OPT_LEN_MASK 0x1F

static const struct tok geneve_flag_values[] = {
        { FLAG_OAM, "O" },
        { FLAG_CRITICAL, "C" },
        { FLAG_R1, "R1" },
        { FLAG_R2, "R2" },
        { FLAG_R3, "R3" },
        { FLAG_R4, "R4" },
        { FLAG_R5, "R5" },
        { FLAG_R6, "R6" },
        { 0, NULL }
};

static const char *
format_opt_class(const uint16_t opt_class)
{
    switch (opt_class) {
    case 0x0100:
        return "Linux";
    case 0x0101:
        return "Open vSwitch";
    case 0x0102:
        return "Open Virtual Networking (OVN)";
    case 0x0103:
        return "In-band Network Telemetry (INT)";
    case 0x0104:
        return "VMware";
    case 0x0105:
    case 0x0108:
    case 0x0109:
    case 0x010A:
    case 0x010B:
    case 0x010C:
    case 0x010D:
    case 0x010E:
    case 0x010F:
    case 0x0110:
        return "Amazon";
    case 0x0106:
    case 0x0130:
    case 0x0131:
        return "Cisco";
    case 0x0107:
        return "Oracle";
    case 0x0111:
    case 0x0112:
    case 0x0113:
    case 0x0114:
    case 0x0115:
    case 0x0116:
    case 0x0117:
    case 0x0118:
        return "IBM";
    case 0x0119:
    case 0x011A:
    case 0x011B:
    case 0x011C:
    case 0x011D:
    case 0x011E:
    case 0x011F:
    case 0x0120:
    case 0x0121:
    case 0x0122:
    case 0x0123:
    case 0x0124:
    case 0x0125:
    case 0x0126:
    case 0x0127:
    case 0x0128:
        return "Ericsson";
    case 0x0129:
        return "Oxide";
    case 0x0132:
    case 0x0133:
    case 0x0134:
    case 0x0135:
        return "Google";
    case 0x0136:
        return "InfoQuick";
    default:
        if (opt_class <= 0x00ff)
            return "Standard";
        else if (opt_class >= 0xfff0)
            return "Experimental";
    }

    return "Unknown";
}

static unsigned
geneve_opts_print(netdissect_options *ndo, const u_char *bp, u_int len)
{
    const char *sep = "";

    while (len > 0) {
        uint16_t opt_class;
        uint8_t opt_type;
        uint8_t opt_len;

        ND_ICHECKMSG_U("remaining options length", len, <, 4);
        ND_PRINT("%s", sep);
        sep = ", ";

        opt_class = GET_BE_U_2(bp);
        opt_type = GET_U_1(bp + 2);
        opt_len = 4 + ((GET_U_1(bp + 3) & OPT_LEN_MASK) * 4);

        ND_PRINT("class %s (0x%x) type 0x%x%s len %u",
                  format_opt_class(opt_class), opt_class, opt_type,
                  opt_type & OPT_TYPE_CRITICAL ? "(C)" : "", opt_len);

        if (opt_len > len) {
            ND_PRINT(" [bad length]");
            goto invalid;
        }

        if (ndo->ndo_vflag > 1 && opt_len > 4) {
            const uint32_t *data = (const uint32_t *)(bp + 4);
            int i;

            ND_PRINT(" data");

            for (i = 4; i < opt_len; i += 4) {
                ND_PRINT(" %08x", GET_BE_U_4(data));
                data++;
            }
        } else
            ND_TCHECK_LEN(bp, opt_len);

        bp += opt_len;
        len -= opt_len;
    }
    return 1;
invalid:
    ND_TCHECK_LEN(bp, len);
    return 0;
}

void
geneve_print(netdissect_options *ndo, const u_char *bp, u_int len)
{
    uint8_t ver_opt;
    u_int version;
    uint8_t flags;
    uint16_t prot;
    uint32_t vni;
    uint8_t reserved;
    u_int opts_len;

    ndo->ndo_protocol = "geneve";
    ND_PRINT("Geneve");

    ND_ICHECK_U(len, <, 8);

    ver_opt = GET_U_1(bp);
    bp += 1;
    len -= 1;

    version = ver_opt >> VER_SHIFT;
    if (version != 0) {
        ND_PRINT(" ERROR: unknown-version %u", version);
        goto invalid;
    }

    flags = GET_U_1(bp);
    bp += 1;
    len -= 1;

    prot = GET_BE_U_2(bp);
    bp += 2;
    len -= 2;

    vni = GET_BE_U_3(bp);
    bp += 3;
    len -= 3;

    reserved = GET_U_1(bp);
    bp += 1;
    len -= 1;

    ND_PRINT(", Flags [%s]",
              bittok2str_nosep(geneve_flag_values, "none", flags));
    ND_PRINT(", vni 0x%x", vni);

    if (reserved)
        ND_PRINT(", rsvd 0x%x", reserved);

    if (ndo->ndo_eflag)
        ND_PRINT(", proto %s (0x%04x)",
                  tok2str(ethertype_values, "unknown", prot), prot);

    opts_len = (ver_opt & HDR_OPTS_LEN_MASK) * 4;

    if (len < opts_len) {
        ND_PRINT(" (opts_len %u > %u", opts_len, len);
        goto invalid;
    }

    if (opts_len > 0) {
        ND_PRINT(", options [");

        if (ndo->ndo_vflag) {
            if (! geneve_opts_print(ndo, bp, opts_len))
                goto invalid;
        }
        else {
            ND_TCHECK_LEN(bp, opts_len);
            ND_PRINT("%u bytes", opts_len);
        }

        ND_PRINT("]");
    }

    bp += opts_len;
    len -= opts_len;

    if (ndo->ndo_vflag < 1)
        ND_PRINT(": ");
    else
        ND_PRINT("\n\t");

    if (ethertype_print(ndo, prot, bp, len, ND_BYTES_AVAILABLE_AFTER(bp), NULL, NULL) == 0) {
        if (prot == ETHERTYPE_TEB)
            ether_print(ndo, bp, len, ND_BYTES_AVAILABLE_AFTER(bp), NULL, NULL);
        else {
            ND_PRINT("geneve-proto-0x%x", prot);
            ND_TCHECK_LEN(bp, len);
        }
    }

    return;

invalid:
    nd_print_invalid(ndo);
}
