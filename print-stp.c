/*
 * Copyright (c) 2000 Lennert Buytenhek
 *
 * This software may be distributed either under the terms of the
 * BSD-style license that accompanies tcpdump or the GNU General
 * Public License
 *
 * Format and print IEEE 802.1d spanning tree protocol packets.
 * Contributed by Lennert Buytenhek <buytenh@gnu.org>
 */

#ifndef lint
static const char rcsid[] _U_ =
"@(#) $Header: /tcpdump/master/tcpdump/print-stp.c,v 1.13.2.2 2007-03-06 15:07:05 hannes Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <tcpdump-stdinc.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "interface.h"
#include "addrtoname.h"
#include "extract.h"

#define	RSTP_EXTRACT_PORT_ROLE(x) (((x)&0x0C)>>2) 
/* STP timers are expressed in multiples of 1/256th second */
#define STP_TIME_BASE 256

struct stp_bpdu_ {
    u_int8_t protocol_id[2];
    u_int8_t protocol_version;
    u_int8_t bpdu_type;
    u_int8_t flags;
    u_int8_t root_id[8];
    u_int8_t root_path_cost[4];
    u_int8_t bridge_id[8];
    u_int8_t port_id[2];
    u_int8_t message_age[2];
    u_int8_t max_age[2];
    u_int8_t hello_time[2];
    u_int8_t forward_delay[2];
    u_int8_t v1_length;
};

#define STP_PROTO_REGULAR 0x00
#define STP_PROTO_RAPID   0x02

struct tok stp_proto_values[] = {
    { STP_PROTO_REGULAR, "802.1d" },
    { STP_PROTO_RAPID, "802.1w" },
    { 0, NULL}
};

#define STP_BPDU_TYPE_CONFIG      0x00
#define STP_BPDU_TYPE_RSTP        0x02
#define STP_BPDU_TYPE_TOPO_CHANGE 0x80

struct tok stp_bpdu_flag_values[] = {
    { 0x01, "Topology change" },
    { 0x02, "Proposal" },
    { 0x10, "Learn" },
    { 0x20, "Forward" },
    { 0x40, "Agreement" },
    { 0x80, "Topology change ACK" },
    { 0, NULL}
};

struct tok stp_bpdu_type_values[] = {
    { STP_BPDU_TYPE_CONFIG, "Config" },
    { STP_BPDU_TYPE_RSTP, "Rapid SPT" },
    { STP_BPDU_TYPE_TOPO_CHANGE, "Topology Change" },
    { 0, NULL}
};

struct tok rstp_obj_port_role_values[] = {
    { 0x00, "Unknown" },
    { 0x01, "Alternate" },
    { 0x02, "Root" },
    { 0x03, "Designated" },
    { 0, NULL}
};

static char *
stp_print_bridge_id(const u_char *p)
{
    static char bridge_id_str[sizeof("pppp.aa:bb:cc:dd:ee:ff")];

    snprintf(bridge_id_str, sizeof(bridge_id_str),
             "%.2x%.2x.%.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
             p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7]);

    return bridge_id_str;
}

static void
stp_print_config_bpdu(const struct stp_bpdu_ *stp_bpdu, u_int length)
{
    printf(", Flags [%s]",
           bittok2str(stp_bpdu_flag_values, "none", stp_bpdu->flags));

    printf(", bridge-id %s.%04x, length %u",
           stp_print_bridge_id((const u_char *)&stp_bpdu->bridge_id),
           EXTRACT_16BITS(&stp_bpdu->port_id), length);

    /* in non-verbose mode just print the bridge-id */
    if (!vflag) {
        return;
    }

    printf("\n\tmessage-age %.2fs, max-age %.2fs"
           ", hello-time %.2fs, forwarding-delay %.2fs",
           (float)EXTRACT_16BITS(&stp_bpdu->message_age) / STP_TIME_BASE,
           (float)EXTRACT_16BITS(&stp_bpdu->max_age) / STP_TIME_BASE,
           (float)EXTRACT_16BITS(&stp_bpdu->hello_time) / STP_TIME_BASE,
           (float)EXTRACT_16BITS(&stp_bpdu->forward_delay) / STP_TIME_BASE);

    printf("\n\troot-id %s, root-pathcost %u",
           stp_print_bridge_id((const u_char *)&stp_bpdu->root_id),
           EXTRACT_32BITS(&stp_bpdu->root_path_cost) / STP_TIME_BASE);

    /* Port role is only valid for 802.1w */
    if (stp_bpdu->protocol_version == STP_PROTO_RAPID) {
        printf(", port-role %s",
               tok2str(rstp_obj_port_role_values, "Unknown",
                       RSTP_EXTRACT_PORT_ROLE(stp_bpdu->flags)));
    }
}

/*
 * Print 802.1d / 802.1w packets.
 */
void
stp_print(const u_char *p, u_int length)
{
    const struct stp_bpdu_ *stp_bpdu;
    
    stp_bpdu = (struct stp_bpdu_*)p;

    /* Minimum SPT Frame size. */
    if (length < 4)
        goto trunc;
	
    if (EXTRACT_16BITS(&stp_bpdu->protocol_id)) {
        printf("unknown STP version, length %u", length);
        return;
    }

    printf("STP %s", tok2str(stp_proto_values, "Unknown STP protocol (0x%02x)",
                         stp_bpdu->protocol_version));

    switch (stp_bpdu->protocol_version) {
    case STP_PROTO_REGULAR:
    case STP_PROTO_RAPID:
        break;
    default:
        return;
    }

    printf(", %s", tok2str(stp_bpdu_type_values, "Unknown BPDU Type (0x%02x)",
                           stp_bpdu->bpdu_type));

    switch (stp_bpdu->bpdu_type) {
    case STP_BPDU_TYPE_CONFIG:
        if (length < sizeof(struct stp_bpdu_) - 1) {
            goto trunc;
        }
        stp_print_config_bpdu(stp_bpdu, length);
        break;

    case STP_BPDU_TYPE_RSTP:
        if (length < sizeof(struct stp_bpdu_)) {
            goto trunc;
        }
        stp_print_config_bpdu(stp_bpdu, length);
        break;

    case STP_BPDU_TYPE_TOPO_CHANGE:
        /* always empty message - just break out */
        break;

    default:
        break;
    }

    return;
 trunc:
    printf("[|stp %d]", length);
}

/*
 * Local Variables:
 * c-style: whitesmith
 * c-basic-offset: 4
 * End:
 */
