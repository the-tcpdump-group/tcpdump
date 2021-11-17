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
 * Extended with Some/IP service discovery by Martin Kunkel (ich at martinkunkel dot de)
 */

/* \summary: Autosar SOME/IP Protocol printer */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "netdissect-stdinc.h"
#include "netdissect.h"
#include "extract.h"
#include "udp.h"

static const struct tok message_type_values[] = {
    { 0x00, "REQUEST" },
    { 0x01, "REQUEST_NO_RETURN" },
    { 0x02, "NOTIFICATION" },
    { 0x80, "RESPONSE" },
    { 0x81, "ERROR" },
    { 0x20, "TP_REQUEST" },
    { 0x21, "TP_REQUEST_NO_RETURN" },
    { 0x22, "TP_NOTIFICATION" },
    { 0xa0, "TP_RESPONSE" },
    { 0xa1, "TP_ERROR" },
    { 0, NULL }
};

static const struct tok return_code_values[] = {
    { 0x00, "E_OK" },
    { 0x01, "E_NOT_OK" },
    { 0x02, "E_UNKNOWN_SERVICE" },
    { 0x03, "E_UNKNOWN_METHOD" },
    { 0x04, "E_NOT_READY" },
    { 0x05, "E_NOT_REACHABLE" },
    { 0x06, "E_TIMEOUT" },
    { 0x07, "E_WRONG_PROTOCOL_VERSION" },
    { 0x08, "E_WRONG_INTERFACE_VERSION" },
    { 0x09, "E_MALFORMED_MESSAGE" },
    { 0x0a, "E_WRONG_MESSAGE_TYPE" },
    { 0x0b, "E_E2E_REPEATED" },
    { 0x0c, "E_E2E_WRONG_SEQUENCE" },
    { 0x0d, "E_E2E" },
    { 0x0e, "E_E2E_NOT_AVAILABLE" },
    { 0x0f, "E_E2E_NO_NEW_DATA" },
    { 0, NULL }
};

static const struct tok entry_type_values[] = {
    { 0x00, "FIND_SERVICE" },
    { 0x01, "OFFER_SERVICE" },
    { 0x06, "SUBSCRIBE" },
    { 0x07, "SUBSCRIBE_ACK" },
    { 0, NULL }
};

/*
 * SOME/IP Header (R19-11 / R20-11)
 *
 *     0                   1                   2                   3
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |               Message ID (Service ID/Method ID)               |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                           Length                              |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |               Request ID (Client ID/Session ID)               |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    | Protocol Ver  | Interface Ver | Message Type  |  Return Code  |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                            Payload                            |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct someip_header
{
    uint32_t message_id;
    uint16_t service_id;
    uint16_t method_or_event_id;
    uint8_t event_flag;
    uint32_t message_len;
    uint32_t request_id;
    uint16_t client_id;
    uint16_t session_id;
    uint8_t protocol_version;
    uint8_t interface_version;
    uint8_t message_type;
    uint8_t return_code;
};


static const u_char *someip_read_header(struct someip_header *header, netdissect_options *ndo, const u_char *bp)
{
    header->message_id = GET_BE_U_4(bp);
    header->service_id = header->message_id >> 16;
    header->event_flag = (header->message_id & 0x00008000) >> 15;
    header->method_or_event_id = header->message_id & 0x00007FFF;
    bp += 4;
    header->message_len = GET_BE_U_4(bp);
    bp += 4;
    /* message validity check */
    if (ND_BYTES_AVAILABLE_AFTER(bp) != header->message_len)
    {
        nd_print_invalid(ndo);
    }
    header->request_id = GET_BE_U_4(bp);
    header->client_id = header->request_id >> 16;
    header->session_id = header->request_id & 0x0000FFFF;
    bp += 4;
    header->protocol_version = GET_U_1(bp);
    bp += 1;
    header->interface_version = GET_U_1(bp);
    bp += 1;
    header->message_type = GET_U_1(bp);
    bp += 1;
    header->return_code = GET_U_1(bp);
    bp += 1;
    return bp;
}

static void someip_print_header(struct someip_header *header, netdissect_options *ndo)
{
    ND_PRINT(", service %u, %s %u",
             header->service_id, header->event_flag ? "event" : "method", header->method_or_event_id);
    ND_PRINT(", len %u", header->message_len);
    ND_PRINT(", client %u, session %u", header->client_id, header->session_id);
    ND_PRINT(", pver %u", header->protocol_version);
    ND_PRINT(", iver %u", header->interface_version);
    ND_PRINT(", msgtype %s",
             tok2str(message_type_values, "Unknown", header->message_type));
    ND_PRINT(", retcode %s",
             tok2str(return_code_values, "Unknown", header->return_code));
}

/*
 * SOME/IP Service Discovery Header (R20-11)
 *
 *     0                   1                   2                   3
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |     Flags     |                 Reserved                      |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                   Length of Entries Array                     |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                         Entries Array                         |
 *    |                              ...                              |
 *    |                              ...                              |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                   Length of Options Array                     |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                         Options Array                         |
 *    |                              ...                              |
 *    |                              ...                              |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct someip_sd_header
{
    uint8_t flags;
    uint32_t entries_len;
    const u_char *entries;
    uint32_t options_len;
    const u_char *options;
};

static const u_char *someip_read_sd_header(struct someip_sd_header *sd_header, netdissect_options *ndo, const u_char *bp)
{
    sd_header->flags = GET_U_1(bp);
    bp += 1;
    bp += 3; /* reserved */
    sd_header->entries_len = GET_BE_U_4(bp);
    bp += 4;
    sd_header->entries = bp;
    bp += sd_header->entries_len;
    sd_header->options_len = GET_BE_U_4(bp);
    bp += 4;
    sd_header->options = bp;
    bp += sd_header->options_len;
    return bp;
}

static void someip_print_sd_header(struct someip_sd_header *sd_header, netdissect_options *ndo)
{
    ND_PRINT("\n\tSOME/IP service discovery message, flags: 0x%02X", sd_header->flags);
    if (sd_header->flags & (1 << 7))
        ND_PRINT(" (reboot)");
    if (sd_header->flags & (1 << 6))
        ND_PRINT(" (unicast)");
    if (sd_header->flags & (1 << 5))
        ND_PRINT(" (explicit initial data control)");
}

/*
 * SOME/IP Service Discovery Entry (R20-11)
 *
 *     0                   1                   2                   3
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |     Type      | Index 1st opt | Index 2nd opt | #opt1 | #opt2 |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |          Service ID           |         Instance ID           |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    | Major Version |                   TTL                         |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Last 4 byte depend on entry type.
 * For Service Entry:
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                       Minor Version                           |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * For Entrygroup Entry:
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |   Reserved    |F|Res.2| Count |         Eventgroup ID         |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    (F = Initial Data Requested Flag)
 *    (Res.2 = Reserved2)
 */
struct someip_sd_entry
{
    uint8_t type;
    uint8_t index_1st_options;
    uint8_t index_2nd_options;
    uint8_t num_1st_options;
    uint8_t num_2nd_options;
    uint16_t service_id;
    uint16_t instance_id;
    uint8_t major_version;
    uint32_t ttl;
    uint32_t minor_version;
    uint8_t idrf;
    uint8_t counter;
    uint16_t eventgroup_id;
};

static const u_char *someip_read_sd_entry(struct someip_sd_entry *entry, netdissect_options *ndo, const u_char *bp)
{
    memset(entry, 0, sizeof(struct someip_sd_entry));
    entry->type = GET_U_1(bp);
    bp += 1;
    entry->index_1st_options = GET_U_1(bp);
    bp += 1;
    entry->index_2nd_options = GET_U_1(bp);
    bp += 1;
    uint8_t num_options = GET_U_1(bp);
    bp += 1;
    entry->num_1st_options = (num_options >> 4);
    entry->num_2nd_options = (num_options & 0x0F);
    entry->service_id = GET_BE_U_2(bp);
    bp += 2;
    entry->instance_id = GET_BE_U_2(bp);
    bp += 2;
    entry->major_version = GET_U_1(bp);
    bp += 1;
    entry->ttl = GET_BE_U_3(bp);
    bp += 3;
    /* service entry type */
    if (entry->type == 0x00 || entry->type == 0x01)
    {
        entry->minor_version = GET_BE_U_4(bp);
        bp += 4;
    }
    /* eventgroup entry */
    else
    {
        /* reserved */
        bp += 1;
        uint8_t flags_and_reserved2 = GET_U_1(bp);
        bp += 1;
        entry->idrf = (flags_and_reserved2 & (1 << 7));
        entry->counter = (flags_and_reserved2 & 0x0F);
        entry->eventgroup_id = GET_BE_U_2(bp);
        bp += 2;
    }
    return bp;
}

static void someip_print_sd_entry(struct someip_sd_entry *entry, netdissect_options *ndo)
{
    ND_PRINT("\n\t  ");
    ND_PRINT("%s", tok2str(entry_type_values, "Unknown", entry->type));
    if (entry->ttl == 0)
        ND_PRINT("(STOP)");
    ND_PRINT(": service_id 0x%04X", entry->service_id);
    ND_PRINT(", instance_id 0x%04X", entry->instance_id);
    ND_PRINT(", major_version %u", entry->major_version);
    if (entry->major_version == 0xFF)
        ND_PRINT(" (all)");
    ND_PRINT(", ttl %u", entry->ttl);
    if (entry->type == 0x00 || entry->type == 0x01)
    {
        ND_PRINT(", minor version %u", entry->minor_version);
        if (entry->minor_version == 0xFFFFFFFF)
            ND_PRINT(" (all)");
    }
    else
    {
        if (entry->idrf)
            ND_PRINT(", IDR flag set");
        ND_PRINT(", counter %u", entry->counter);
        ND_PRINT(", eventgroup_id 0x%04X", entry->eventgroup_id);
    }
}

void someip_print(netdissect_options *ndo, const u_char *bp)
{
    ndo->ndo_protocol = "someip";
    nd_print_protocol_caps(ndo);

    struct someip_header header;
    bp = someip_read_header(&header, ndo, bp);
    someip_print_header(&header, ndo);

    /* Is this a SOME/IP service discovery message? */
    if (header.message_id == 0xFFFF8100)
    {
        struct someip_sd_header sd_header;
        someip_read_sd_header(&sd_header, ndo, bp);
        someip_print_sd_header(&sd_header, ndo);

        /* entries */
        bp = sd_header.entries;
        while (bp < sd_header.entries + sd_header.entries_len)
        {
            struct someip_sd_entry entry;
            bp = someip_read_sd_entry(&entry, ndo, bp);
            someip_print_sd_entry(&entry, ndo);
        }
    }
    return;
}
