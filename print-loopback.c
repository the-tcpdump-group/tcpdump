/*
 * Copyright (c) 2014 The TCPDUMP project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/* \summary: Loopback Protocol printer */

/*
 * originally defined as the Ethernet Configuration Testing Protocol.
 * specification: https://www.mit.edu/people/jhawk/ctp.pdf
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "netdissect-stdinc.h"

#include "netdissect.h"
#include "extract.h"
#include "addrtoname.h"


#define LOOPBACK_REPLY   1
#define LOOPBACK_FWDDATA 2

static const struct tok fcode_str[] = {
	{ LOOPBACK_REPLY,   "Reply"        },
	{ LOOPBACK_FWDDATA, "Forward Data" },
	{ 0, NULL }
};

static void
loopback_message_print(netdissect_options *ndo, const u_char *cp, const u_int len)
{
	const u_char *ep = ndo->ndo_snapend;
	uint16_t function;

	if (len < 2)
		goto invalid;
	/* function */
	ND_TCHECK_2(cp);
	function = GET_LE_U_2(cp);
	cp += 2;
	ND_PRINT(", %s", tok2str(fcode_str, " invalid (%u)", function));

	switch (function) {
		case LOOPBACK_REPLY:
			if (len < 4)
				goto invalid;
			/* receipt number */
			ND_TCHECK_2(cp);
			ND_PRINT(", receipt number %u", GET_LE_U_2(cp));
			cp += 2;
			/* data */
			ND_PRINT(", data (%u octets)", len - 4);
			ND_TCHECK_LEN(cp, len - 4);
			break;
		case LOOPBACK_FWDDATA:
			if (len < 8)
				goto invalid;
			/* forwarding address */
			ND_TCHECK_LEN(cp, MAC_ADDR_LEN);
			ND_PRINT(", forwarding address %s", GET_ETHERADDR_STRING(cp));
			cp += MAC_ADDR_LEN;
			/* data */
			ND_PRINT(", data (%u octets)", len - 8);
			ND_TCHECK_LEN(cp, len - 8);
			break;
		default:
			ND_TCHECK_LEN(cp, len - 2);
			break;
	}
	return;

invalid:
	nd_print_invalid(ndo);
	ND_TCHECK_LEN(cp, ep - cp);
	return;
trunc:
	nd_print_trunc(ndo);
}

void
loopback_print(netdissect_options *ndo, const u_char *cp, const u_int len)
{
	const u_char *ep = ndo->ndo_snapend;
	uint16_t skipCount;

	ndo->ndo_protocol = "loopback";
	ND_PRINT("Loopback");
	if (len < 2)
		goto invalid;
	/* skipCount */
	ND_TCHECK_2(cp);
	skipCount = GET_LE_U_2(cp);
	cp += 2;
	ND_PRINT(", skipCount %u", skipCount);
	if (skipCount % 8)
		ND_PRINT(" (bogus)");
	if (skipCount > len - 2)
		goto invalid;
	loopback_message_print(ndo, cp + skipCount, len - 2 - skipCount);
	return;

invalid:
	nd_print_invalid(ndo);
	ND_TCHECK_LEN(cp, ep - cp);
	return;
trunc:
	nd_print_trunc(ndo);
}

