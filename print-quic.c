/*
 * Copyright (c) 2021 Apple, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *  3. The names of the authors may not be used to endorse or promote
 *     products derived from this software without specific prior
 *     written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

/* \summary: QUIC Protocol printer */
/* specification: https://www.rfc-editor.org/rfc/rfc9000.txt */

#include <config.h>

#include "netdissect-stdinc.h"
#include "netdissect-alloc.h"
#include "netdissect.h"
#include "extract.h"

#define QUIC_MAX_CID_LENGTH	20

typedef uint8_t quic_cid[QUIC_MAX_CID_LENGTH];

struct quic_cid_array {
	uint8_t cid[QUIC_MAX_CID_LENGTH];
	uint8_t length;
};

enum quic_lh_packet_type {
	QUIC_LH_TYPE_INITIAL = 0,
	QUIC_LH_TYPE_0RTT = 1,
	QUIC_LH_TYPE_HANDSHAKE = 2,
	QUIC_LH_TYPE_RETRY = 3
};

static void
hexprint(netdissect_options *ndo, const uint8_t *cp, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++)
		ND_PRINT("%02x", cp[i]);
}

#define QUIC_CID_LIST_MAX	512

static struct quic_cid_array quic_cid_array[QUIC_CID_LIST_MAX];

static struct quic_cid_array *
lookup_quic_cid(const u_char *cid, size_t length)
{
	for (unsigned int i = 0; i < QUIC_CID_LIST_MAX; i++) {
		if (quic_cid_array[i].length > length) {
			continue;
		}
		if (quic_cid_array[i].length == 0) {
			break;
		}
		if (memcmp(quic_cid_array[i].cid, cid,
			   quic_cid_array[i].length) == 0) {
			/*
			 * Swap the entries so that it behaves like an
			 * LRU cache.
			 */
			if (i != 0) {
				struct quic_cid_array tmp = quic_cid_array[i];
				quic_cid_array[i] = quic_cid_array[0];
				quic_cid_array[0] = tmp;
			}

			return &quic_cid_array[0];
		}
	}

	return NULL;
}

static void
register_quic_cid(const quic_cid cid, uint8_t length)
{
	static uint16_t next_cid = 0;

	if (length == 0 ||
	    lookup_quic_cid(cid, length) != NULL) {
		return;
	}
	memcpy(&quic_cid_array[next_cid].cid, cid, QUIC_MAX_CID_LENGTH);
	quic_cid_array[next_cid].length = length;
	next_cid = (next_cid + 1) % QUIC_CID_LIST_MAX;
}

/* Returns 1 if the first octet looks like a QUIC packet. */
int
quic_detect(netdissect_options *ndo, const u_char *p, const u_int len)
{
	uint8_t first_octet;

	if (len < 1)
		return 0;
	first_octet = GET_U_1(p);
	/* All QUIC packets must have the Fixed Bit set to 1. */
	if ((first_octet & 0x40) == 0x40)
		return 1;
	else
		return 0;
}

/* Extracts the variable length integer (see RFC 9000 section 16). */
static inline uint64_t
get_be_vli(netdissect_options *ndo, const u_char *p, uint8_t *out_length)
{
	uint64_t v;
	uint8_t prefix;
	uint8_t length;

	v = GET_U_1(p);
	p++;
	prefix = (uint8_t)v >> 6;
	length = 1 << prefix;
	if (out_length != NULL)
		*out_length = length;
	v = v & 0x3f;
	while (length > 1) {
		v = (v << 8) + GET_U_1(p);
		p++;
		length--;
	}

	return v;
}

#define GET_BE_VLI(p, l) get_be_vli(ndo, (const u_char *)(p), l)

static const u_char *
quic_print_packet(netdissect_options *ndo, const u_char *bp, const u_char *end)
{
	uint8_t first_octet = 0;
	uint8_t packet_type = 0;
	uint32_t version = 0;
	quic_cid dcid = {0};
	quic_cid scid = {0};
	uint8_t dcil = 0; /* DCID length */
	uint8_t scil = 0; /* SCID length */
	uint8_t vli_length = 0;
	uint8_t *token = NULL;
	uint64_t token_length = 0;

	first_octet = GET_U_1(bp);
	bp += 1;
	if (first_octet & 0x80) {
		/* Long Header */
		packet_type = (first_octet >> 4) & 0x03;
		version = GET_BE_U_4(bp);
		bp += 4;

		if (version == 0)
			ND_PRINT(", version negotiation");
		else if (packet_type == QUIC_LH_TYPE_INITIAL)
			ND_PRINT(", initial");
		else if (packet_type == QUIC_LH_TYPE_0RTT)
			ND_PRINT(", 0-rtt");
		else if (packet_type == QUIC_LH_TYPE_HANDSHAKE)
			ND_PRINT(", handshake");
		else if (packet_type == QUIC_LH_TYPE_RETRY)
			ND_PRINT(", retry");
		if (version != 0 && version != 1)
			ND_PRINT(", v%x", version);
		dcil = GET_U_1(bp);
		bp += 1;
		if (dcil > 0  && dcil <= QUIC_MAX_CID_LENGTH) {
			memset(dcid, 0, sizeof(dcid));
			GET_CPY_BYTES(&dcid, bp, dcil);
			bp += dcil;
			ND_PRINT(", dcid ");
			hexprint(ndo, dcid, dcil);
			register_quic_cid(dcid, dcil);
		}
		scil = GET_U_1(bp);
		bp += 1;
		if (scil > 0 && scil <= QUIC_MAX_CID_LENGTH) {
			memset(scid, 0, sizeof(dcid));
			GET_CPY_BYTES(&scid, bp, scil);
			bp += scil;
			ND_PRINT(", scid ");
			hexprint(ndo, scid, scil);
			register_quic_cid(scid, scil);
		}
		if (version == 0) {
			/* Version Negotiation packet */
			while (bp < end) {
				if (!ND_TTEST_4(bp)) {
					nd_print_trunc(ndo);
					bp = end;
				} else {
					uint32_t vn_version = GET_BE_U_4(bp);
					bp += 4;
					ND_PRINT(", version 0x%x", vn_version);
				}
			}
		} else {
			if (packet_type == QUIC_LH_TYPE_INITIAL) {
				token_length = GET_BE_VLI(bp, &vli_length);
				bp += vli_length;
				if (token_length > 0 && token_length < 1000) {
					token = nd_malloc(ndo, (size_t)token_length);
					GET_CPY_BYTES(token, bp, (size_t)token_length);
					bp += token_length;
					ND_PRINT(", token ");
					hexprint(ndo, token, (size_t)token_length);
				}
			}
			if (packet_type == QUIC_LH_TYPE_RETRY) {
				ND_PRINT(", token ");
				if (end > bp && end - bp > 16 &&
				    ND_TTEST_LEN(bp, end - bp - 16)) {
					token_length = end - bp - 16;
					token = nd_malloc(ndo, (size_t)token_length);
					GET_CPY_BYTES(token, bp, (size_t)token_length);
					bp += token_length;
					hexprint(ndo, token, (size_t)token_length);
				} else {
					nd_print_trunc(ndo);
				}
				bp = end;
			} else {
				/* Initial/Handshake/0-RTT */
				uint64_t payload_length =
					GET_BE_VLI(bp, &vli_length);
				bp += vli_length;
				ND_PRINT(", length %" PRIu64, payload_length);
				if (!ND_TTEST_LEN(bp, payload_length)) {
					nd_print_trunc(ndo);
					bp = end;
				} else
					bp += payload_length;
			}
		}
	} else {
		/* Short Header */
		ND_PRINT(", protected");
		if (end > bp && end - bp > 16 &&
		    ND_TTEST_LEN(bp, end - bp)) {
			struct quic_cid_array *cid_array =
				lookup_quic_cid(bp, end - bp);
			if (cid_array != NULL) {
				ND_PRINT(", dcid ");
				hexprint(ndo, cid_array->cid,
					 cid_array->length);
			}
		} else {
			nd_print_trunc(ndo);
		}
		bp = end;
	}

	return bp;
}

void
quic_print(netdissect_options *ndo, const u_char *bp)
{
	const uint8_t *end = bp + ND_BYTES_AVAILABLE_AFTER(bp);

	ndo->ndo_protocol = "quic";
	nd_print_protocol(ndo);

	while (bp < end) {
		bp = quic_print_packet(ndo, bp, end);
		/*
		 * Skip all zero bytes which are
		 * considered padding.
		 */
		while (ND_TTEST_1(bp) && GET_U_1(bp) == 0)
			bp++;
	}
}
