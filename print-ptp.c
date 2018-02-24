/*
 * Copyright (c) 1988, 1989, 1990, 1991, 1992, 1993, 1994, 1995, 1996, 1997
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) all advertising materials mentioning
 * features or use of this software display the following acknowledgement:
 * ``This product includes software developed by the University of California,
 * Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
 * the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

/* \summary: PTP printer */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "netdissect-stdinc.h"
#include "netdissect.h"
#include "extract.h"

static const char tstr[] = "[|PTP]";

#define PTP_COMMON_HEADER_LEN 34

static const struct tok messageType_values[] = {
	{0, "Sync" },
	{1, "Delay Req" },
	{2, "PDelay Req" },
	{3, "PDelay Resp"},
	{8, "Follow Up" },
	{9, "Delay Resp" },
	{10, "PDelay Resp Follow Up" },
	{11, "Announce" },
	{12, "Signalling" },
	{13, "Management" },
	{0, NULL },
};

static const struct tok ptp_flags_values[] = {
	{ 0x1, "62" },
	{ 0x2, "59" },
	{ 0x4, "R" },
	{ 0x8, "TS" },
	{ 0x10, "TT" },
	{ 0x20, "FT" },
	{ 0x100, "AM" },
	{ 0x200, "2S" },
	{ 0x400, "U" },
	{ 0x2000, "P1" },
	{ 0x4000, "P2" },
	{ 0x8000, "S" },
	{0, NULL },
};

void
ptp_print(netdissect_options *ndo, const u_char *bp, u_int length)
{
	uint8_t messageType;
	uint16_t flags;
	uint16_t seq;
	uint64_t clockId;
	uint16_t srcId;

	ND_TCHECK_LEN(bp, PTP_COMMON_HEADER_LEN);

	if (length < PTP_COMMON_HEADER_LEN)
		goto trunc;

	messageType = 	EXTRACT_U_1(&bp[0]) & 0xf;
	flags = 	EXTRACT_BE_U_2(&bp[6]);
	clockId = 	EXTRACT_BE_U_8(&bp[20]);
	srcId = 	EXTRACT_BE_U_2(&bp[28]);
	seq = 		EXTRACT_BE_U_2(&bp[30]);

	ND_PRINT("PTP %u, %s, [%s], %" PRIu64 ":%d",
		 seq, tok2str(messageType_values, "Unknown (%u)", messageType),
		 bittok2str(ptp_flags_values, "none", flags),
		 clockId, srcId);
	return;
trunc:
	ND_PRINT("%s", tstr);
}

/*
 * Local Variables:
 * c-style: bsd
 * End:
 */
