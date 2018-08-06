/*
 * Copyright (c) 1998-2007 The TCPDUMP project
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
 *
 * Original code by Carles Kishimoto <carles.kishimoto@gmail.com>
 */

/* \summary: Cisco UniDirectional Link Detection (UDLD) protocol printer */

/* specification: RFC 5171 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "netdissect-stdinc.h"

#include "netdissect.h"
#include "extract.h"


#define UDLD_HEADER_LEN			4
#define UDLD_DEVICE_ID_TLV		0x0001
#define UDLD_PORT_ID_TLV		0x0002
#define UDLD_ECHO_TLV			0x0003
#define UDLD_MESSAGE_INTERVAL_TLV	0x0004
#define UDLD_TIMEOUT_INTERVAL_TLV	0x0005
#define UDLD_DEVICE_NAME_TLV		0x0006
#define UDLD_SEQ_NUMBER_TLV		0x0007

static const struct tok udld_tlv_values[] = {
    { UDLD_DEVICE_ID_TLV, "Device-ID TLV"},
    { UDLD_PORT_ID_TLV, "Port-ID TLV"},
    { UDLD_ECHO_TLV, "Echo TLV"},
    { UDLD_MESSAGE_INTERVAL_TLV, "Message Interval TLV"},
    { UDLD_TIMEOUT_INTERVAL_TLV, "Timeout Interval TLV"},
    { UDLD_DEVICE_NAME_TLV, "Device Name TLV"},
    { UDLD_SEQ_NUMBER_TLV,"Sequence Number TLV"},
    { 0, NULL}
};

static const struct tok udld_code_values[] = {
    { 0x00, "Reserved"},
    { 0x01, "Probe message"},
    { 0x02, "Echo message"},
    { 0x03, "Flush message"},
    { 0, NULL}
};

static const struct tok udld_flags_values[] = {
    { 0x00, "RT"},
    { 0x01, "RSY"},
    { 0, NULL}
};

/*
 * UDLD's Protocol Data Unit format:
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | Ver | Opcode  |     Flags     |           Checksum            |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |               List of TLVs (variable length list)             |
 * |                              ...                              |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * TLV format:
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |             TYPE              |            LENGTH             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                             VALUE                             |
 * |                              ...                              |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * LENGTH: Length in bytes of the Type, Length, and Value fields.
 */

#define	UDLD_EXTRACT_VERSION(x) (((x)&0xe0)>>5)
#define	UDLD_EXTRACT_OPCODE(x) ((x)&0x1f)

void
udld_print(netdissect_options *ndo, const u_char *pptr, u_int length)
{
    int code, type, len;
    const u_char *tptr;

    ndo->ndo_protocol = "udld";
    if (length < UDLD_HEADER_LEN)
        goto trunc;

    tptr = pptr;

    ND_TCHECK_LEN(tptr, UDLD_HEADER_LEN);

    code = UDLD_EXTRACT_OPCODE(EXTRACT_U_1(tptr));

    ND_PRINT("UDLDv%u, Code %s (%x), Flags [%s] (0x%02x), length %u",
           UDLD_EXTRACT_VERSION(EXTRACT_U_1(tptr)),
           tok2str(udld_code_values, "Reserved", code),
           code,
           bittok2str(udld_flags_values, "none", EXTRACT_U_1((tptr + 1))),
           EXTRACT_U_1((tptr + 1)),
           length);

    /*
     * In non-verbose mode, just print version and opcode type
     */
    if (ndo->ndo_vflag < 1) {
	return;
    }

    ND_PRINT("\n\tChecksum 0x%04x (unverified)", EXTRACT_BE_U_2(tptr + 2));

    tptr += UDLD_HEADER_LEN;

    while (tptr < (pptr+length)) {

        ND_TCHECK_4(tptr);
	type = EXTRACT_BE_U_2(tptr);
        len  = EXTRACT_BE_U_2(tptr + 2);

        ND_PRINT("\n\t%s (0x%04x) TLV, length %u",
               tok2str(udld_tlv_values, "Unknown", type),
               type, len);

        if (type == 0)
            goto invalid;

        /* infinite loop check */
        if (len <= 4)
            goto invalid;

        len -= 4;
        tptr += 4;

        ND_TCHECK_LEN(tptr, len);

        switch (type) {
        case UDLD_DEVICE_ID_TLV:
        case UDLD_PORT_ID_TLV:
        case UDLD_DEVICE_NAME_TLV:
            ND_PRINT(", ");
            nd_printzp(ndo, tptr, len, NULL);
            break;

        case UDLD_ECHO_TLV:
            ND_PRINT(", ");
            (void)nd_printn(ndo, tptr, len, NULL);
            break;

        case UDLD_MESSAGE_INTERVAL_TLV:
        case UDLD_TIMEOUT_INTERVAL_TLV:
            if (len != 1)
                goto invalid;
            ND_PRINT(", %us", (EXTRACT_U_1(tptr)));
            break;

        case UDLD_SEQ_NUMBER_TLV:
            if (len != 4)
                goto invalid;
            ND_PRINT(", %u", EXTRACT_BE_U_4(tptr));
            break;

        default:
            break;
        }
        tptr += len;
    }

    return;

invalid:
    ND_PRINT("%s", istr);
    return;
trunc:
    nd_print_trunc(ndo);
}
