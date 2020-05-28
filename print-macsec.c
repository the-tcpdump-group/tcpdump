/* Copyright (c) 2017, Sabrina Dubroca <sd@queasysnail.net>
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

/* \summary: MACsec printer */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <netdissect-stdinc.h>

#include <string.h>

#include "netdissect.h"
#include "addrtoname.h"
#include "ether.h"
#include "ethertype.h"
#include "extract.h"

static const char tstr[] = "[|MACsec]";

#define MACSEC_DEFAULT_ICV_LEN 16

/* Header format (SecTAG), following an Ethernet header
 * IEEE 802.1AE-2006 9.3
 *
 * +---------------------------------+----------------+----------------+
 * |        (MACsec ethertype)       |     TCI_AN     |       SL       |
 * +---------------------------------+----------------+----------------+
 * |                           Packet Number                           |
 * +-------------------------------------------------------------------+
 * |                     Secure Channel Identifier                     |
 * |                            (optional)                             |
 * +-------------------------------------------------------------------+
 *
 * MACsec ethertype = 0x88e5
 * TCI: Tag Control Information, set of flags
 * AN: association number, 2 bits
 * SL (short length): 6-bit length of the protected payload, if < 48
 * Packet Number: 32-bits packet identifier
 * Secure Channel Identifier: 64-bit unique identifier, usually
 *     composed of a MAC address + 16-bit port number
 */
struct macsec_sectag {
	nd_uint8_t  tci_an;
	nd_uint8_t  short_length;
	nd_uint32_t packet_number;
	nd_uint8_t  secure_channel_id[8]; /* optional */
};

/* IEEE 802.1AE-2006 9.5 */
#define MACSEC_TCI_VERSION 0x80
#define MACSEC_TCI_ES      0x40 /* end station */
#define MACSEC_TCI_SC      0x20 /* SCI present */
#define MACSEC_TCI_SCB     0x10 /* epon */
#define MACSEC_TCI_E       0x08 /* encryption */
#define MACSEC_TCI_C       0x04 /* changed text */
#define MACSEC_AN_MASK     0x03 /* association number */
#define MACSEC_TCI_FLAGS   (MACSEC_TCI_ES | MACSEC_TCI_SC | MACSEC_TCI_SCB | MACSEC_TCI_E | MACSEC_TCI_C)
#define MACSEC_TCI_CONFID  (MACSEC_TCI_E | MACSEC_TCI_C)
#define MACSEC_SL_MASK     0x3F /* short length */

#define MACSEC_SECTAG_LEN_NOSCI 6
#define MACSEC_SECTAG_LEN_SCI 14
static int
ieee8021ae_sectag_len(netdissect_options *ndo, const struct macsec_sectag *sectag)
{
	return (GET_U_1(sectag->tci_an) & MACSEC_TCI_SC) ?
	       MACSEC_SECTAG_LEN_SCI :
	       MACSEC_SECTAG_LEN_NOSCI;
}

static int macsec_check_length(netdissect_options *ndo, cconst struct macsec_sectag *sectag, u_int length, u_int caplen)
{
	u_int len;

	/* we need the full MACsec header in the capture */
	if (caplen < (MACSEC_SECTAG_LEN_NOSCI + 2))
		return 0;

	len = ieee8021ae_sectag_len(ndo, sectag);
	if (caplen < (len + 2))
		return 0;

	if ((GET_U_1(sectag->short_length) & MACSEC_SL_MASK) != 0) {
		/* original packet must have exact length */
		u_int exact = ETHER_HDRLEN + len + 2 + (GET_U_1(sectag->short_length) & MACSEC_SL_MASK);
		return exact == length;
	} else {
		/* original packet must not be short */
		u_int minlen = ETHER_HDRLEN + len + 2 + 48;
		return length >= minlen;
	}

	return 1;
}

#define SCI_FMT "%016" PRIx64

static const struct tok macsec_flag_values[] = {
	{ MACSEC_TCI_E,   "E" },
	{ MACSEC_TCI_C,   "C" },
	{ MACSEC_TCI_ES,  "S" },
	{ MACSEC_TCI_SCB, "B" },
	{ MACSEC_TCI_SC,  "I" },
	{ 0, NULL }
};

/* returns < 0 iff the packet can be decoded completely */
int macsec_print(netdissect_options *ndo, const u_char **bp,
		 u_int *lengthp, u_int *caplenp, u_int *hdrlenp,
		 u_short *length_type)
{
	const u_char *p = *bp;
	u_int length = *lengthp;
	u_int caplen = *caplenp;
	u_int hdrlen = *hdrlenp;
	const struct macsec_sectag *sectag = (const struct macsec_sectag *)p;
	u_int len;

	if (!macsec_check_length(sectag, length, caplen)) {
		ND_PRINT((ndo, tstr));
		return hdrlen + caplen;
	}

	if (sectag->unused || sectag->tci_an & MACSEC_TCI_VERSION) {
		ND_PRINT((ndo, "%s", istr));
		return hdrlen + caplen;
	}

	if (ndo->ndo_eflag) {
		char buf[128];
		int n = snprintf(buf, sizeof(buf), "an %u, pn %u, flags %s",
				 GET_U_1(sectag->tci_an) & MACSEC_AN_MASK,
				 GET_BE_U_4(sectag->packet_number),
				 bittok2str_nosep(macsec_flag_values, "none",
						  GET_U_1(sectag->tci_an) & MACSEC_TCI_FLAGS));
		if (n < 0)
			return hdrlen + caplen;


		if (sectag->short_length) {
			int r = snprintf(buf + n, sizeof(buf) - n, ", sl %u",
					 GET_U_1(sectag->short_length) & MACSEC_SL_MASK);
			if (r < 0)
				return hdrlen + caplen;
			n += r;
		}

		if (sectag->tci_an & MACSEC_TCI_SC) {
			uint64_t sci;
			int r;
			sci = GET_BE_U_8(sectag->secure_channel_id);
			r = snprintf(buf + n, sizeof(buf) - n, ", sci " SCI_FMT, sci);
			if (r < 0)
				return hdrlen + caplen;
			n += r;
		}

		ND_PRINT((ndo, "%s, ", buf));
	}

	len = ieee8021ae_sectag_len(ndo, sectag);
	*length_type = GET_BE_U_2(*bp + len);
	if (ndo->ndo_eflag && *length_type > ETHERMTU && !(sectag->tci_an & MACSEC_TCI_E))
		ND_PRINT((ndo, "ethertype %s, ", tok2str(ethertype_values,"0x%04x", *length_type)));

	if ((GET_U_1(sectag->tci_an) & MACSEC_TCI_CONFID)) {
		*bp += len;
		*hdrlenp += len;

		*lengthp -= len;
		*caplenp -= len;
		return 0;
	} else {
		len += 2;
		*bp += len;
		*hdrlenp += len;

		len += MACSEC_DEFAULT_ICV_LEN;
		*lengthp -= len;
		*caplenp -= len;
		return -1;
	}
}
