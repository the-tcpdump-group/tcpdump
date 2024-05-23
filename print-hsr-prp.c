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
 */

/* \summary: High-availability Seamless Redundancy (HSR) and
 * Parallel Redundancy Protocol (PRP) printer */

/* specification: https://webstore.iec.ch/publication/64423 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "netdissect-stdinc.h"
#include "netdissect.h"
#include "extract.h"
#include "addrtoname.h"

/*
 * HSR header
 *     0                   1                   2                   3
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |NetID|L|       LSDUsize        |         Sequence number       |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *     0                   1                   2                   3
 *
 * L = LanID
 * LSDUsize = Link Service Data Unit size = size of the packet excluding MAC
 * header, tags before the HSR tag (e.g. VLAN), and the HSR ethertype field.
 * For PRP it includes the PRP suffix.
 *
 *
 * PRP trailer
 *     0                   1                   2                   3
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |         Sequence number       | LanId |       LSDUsize        |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |         PRP Suffix (0x88fb)   |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *     0                   1                   2                   3
 *
 * PRP uses a trailer on the packets, making it harder to parse. The suffix
 * 0x88fb indicates that it is a PRP frame, but since this could occur
 * naturally in a packet there is also the LSDUsize that indicates the size of
 * the packet. If this size does not match then it is not a PRP trailer.
 * Unfortunately, this could still match on other packets if coincidentally
 * both the suffix and LSDUsize matches up. We could also verify that LanId is
 * valid (0xA or 0xB) to further reduce likelihood of bad matches.
 *
 * LanId in HSR header is 0 = LAN A and 1 = LAN B. In PRP frames it is
 * represented as 0xA and 0xB.
 *
 *
 * HSR/PRP Supervision frame
 *     0                   1                   2                   3
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |PathId |       version         |         Sequence number       |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |   TLV1 Type   |  TLV1 Length  |   MAC Address of DANP/DANH    |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
 *    |                                                               |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |   TLV2 Type   |  TLV2 Length  |     RedBox MAC Address        |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
 *    |                                                               |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |   TLV0 Type   |  TLV0 Length  |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *     0                   1                   2                   3
 *
 * DANP = Doubly Attached Node PRP
 * DANH = Doubly Attached Node HSR
 */

#define HSR_HDR_LEN 6
#define HSR_PRP_SUPERVISION_LEN 22

void hsr_print(netdissect_options *ndo, const u_char *bp, u_int length)
{
	int lanid, netid;
	uint16_t lsdu_size;
	uint16_t hdr;
	uint32_t seq_nr;

	ND_ICHECK_U(length, <, HSR_HDR_LEN);

	hdr = GET_BE_U_2(bp);
	lsdu_size = hdr & 0xFFF;
	lanid = (hdr >> 12) & 0x1;
	netid = hdr >> 13;

	length -= 2;
	bp += 2;
	seq_nr = GET_BE_U_2(bp);

	ND_PRINT("LSDUsize %u, SeqNr %u, LanId %s, NetId %u, ",
		 lsdu_size, seq_nr, lanid ? "A" : "B", netid);

	return;

invalid:
	nd_print_invalid(ndo);
}

void prp_print(netdissect_options *ndo, const u_char *bp, u_int length)
{
	u_int lsdu_size, lanid, seqnr;

	lsdu_size = GET_BE_U_2(bp + length - 4) & 0xfff;
	lanid = GET_BE_U_2(bp + length - 4) >> 12;

	/* If length does not match LSDUsize or LanId isn't valid it isn't a
	 * valid PRP trailer. This length assumes VLAN tags have been stripped
	 * away already.
	 */
	if (lsdu_size == length && (lanid == 0xA || lanid == 0xB)) {
		seqnr = GET_BE_U_2(bp + length - 6);
		ND_PRINT("PRP trailer (0x88fb), LSDUsize %d, SeqNr %d, LanId %s, ",
			 lsdu_size, seqnr, lanid == 0xA ? "A" : "B");
	}
}

void hsr_prp_supervision_print(netdissect_options *ndo, const u_char *bp, u_int length)
{
	int tlvtype, tlvlength;
	uint32_t seq_nr;
	uint16_t hdr;
	int version;
	int pathid;

	ndo->ndo_protocol = "hsr-prp-supervision";
	if (!ndo->ndo_eflag) {
		nd_print_protocol_caps(ndo);
		ND_PRINT(", ");
	}
	ND_ICHECK_U(length, <, HSR_PRP_SUPERVISION_LEN);

	hdr = GET_BE_U_2(bp);
	version = hdr & 0xFFF;
	/* PathId is always set to 0 according to current standard */
	pathid = (hdr >> 12);
	length -= 2;
	bp += 2;
	seq_nr = GET_BE_U_2(bp);
	length -= 2;
	bp += 2;
	ND_PRINT("Version %d, SeqNr %d, PathId %d", version, seq_nr, pathid);

	tlvtype = GET_BE_U_2(bp) >> 8;
	tlvlength = GET_BE_U_2(bp) & 0xFF;
	length -= 2;
	bp += 2;

	if (tlvlength != 6)
		goto invalid;

	/* TLV1 */
	if (tlvtype == 20) {
		/* PRP: VDAN MAC for RedBox or DANP MAC for both ports in PRP Duplicate Discard */
		ND_PRINT(", VDAN/DANP %s", GET_MAC48_STRING(bp));
	} else if (tlvtype == 21) {
		/* PRP: Not valid for RedBox. DANP MAC for both ports in PRP Duplicate Accept mode */
		ND_PRINT(", DANP %s", GET_MAC48_STRING(bp));
	} else if (tlvtype == 23) {
		/* HSR: MAC address of DANH */
		ND_PRINT(", DANH %s", GET_MAC48_STRING(bp));
	} else {
		goto invalid;
	}
	length -= 6;
	bp += 6;

	tlvtype = GET_BE_U_2(bp) >> 8;
	tlvlength = GET_BE_U_2(bp) & 0xFF;
	length -= 2;
	bp += 2;

	/* No TLV2 indicates the device is not a RedBox */
	if (tlvtype == 0 && tlvlength == 0)
		return;
	if (tlvlength != 6) {
		goto invalid;
	}

	/* TLV2 */
	if (tlvtype == 30) {
		/* HSR and PRP: RedBox MAC */
		ND_PRINT(", RedBox %s", GET_MAC48_STRING(bp));
		length -= 6;
		bp += 6;
	} else {
		goto invalid;
	}

	tlvtype = GET_BE_U_2(bp) >> 8;
	tlvlength = GET_BE_U_2(bp) & 0xFF;
	length -= 2;
	bp += 2;

	/* TLV0 */
	if (tlvtype == 0 && tlvlength == 0) {
		/* HSR and PRP closing TLV, should always be type and length 0.
		 */
		return;
	}

invalid:
	nd_print_invalid(ndo);
}

