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
 */

#define HSR_HDR_LEN 6

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

