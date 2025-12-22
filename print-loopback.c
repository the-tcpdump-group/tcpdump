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
 * specification:
 * https://web.archive.org/web/20060919181108/http://www.mit.edu/people/jhawk/ctp.pdf
 */

#include <config.h>

#include "netdissect-stdinc.h"

#define ND_LONGJMP_FROM_TCHECK
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
loopback_message_print(netdissect_options *ndo,
                       const u_char *cp, u_int length)
{
	uint16_t function;

	ND_ICHECK_U(length, <, 2);
	/* function */
	function = GET_LE_U_2(cp);
	cp += 2;
	length -= 2;
	ND_PRINT(", %s", tok2str(fcode_str, " invalid (%u)", function));

	switch (function) {
		case LOOPBACK_REPLY:
			ND_ICHECK_U(length, <, 2);
			/* receipt number */
			ND_PRINT(", receipt number %u", GET_LE_U_2(cp));
			cp += 2;
			length -= 2;
			/* data */
			ND_PRINT(", data (%u octets)", length);
			ND_TCHECK_LEN(cp, length);
			break;
		case LOOPBACK_FWDDATA:
			ND_ICHECK_U(length, <, MAC48_LEN);
			/* forwarding address */
			ND_PRINT(", forwarding address %s", GET_MAC48_STRING(cp));
			cp += MAC48_LEN;
			length -= MAC48_LEN;
			/* data */
			ND_PRINT(", data (%u octets)", length);
			ND_TCHECK_LEN(cp, length);
			break;
		default:
			ND_TCHECK_LEN(cp, length);
			break;
	}
	return;

invalid:
	nd_print_invalid(ndo);
	ND_TCHECK_LEN(cp, length);
}

void
loopback_print(netdissect_options *ndo,
               const u_char *cp, u_int length)
{
	uint16_t skipCount;

	ndo->ndo_protocol = "loopback";
	ND_PRINT("Loopback");
	ND_ICHECK_U(length, <, 2);
	/* skipCount */
	skipCount = GET_LE_U_2(cp);
	cp += 2;
	length -= 2;
	ND_PRINT(", skipCount %u", skipCount);
	if (skipCount % 8)
		ND_PRINT(" (bogus)");
	ND_ICHECK_U(length, <, skipCount);
	/* the octets to skip */
	ND_TCHECK_LEN(cp, skipCount);
	cp += skipCount;
	length -= skipCount;
	/* the first message to decode */
	loopback_message_print(ndo, cp, length);
	return;

invalid:
	nd_print_invalid(ndo);
	ND_TCHECK_LEN(cp, length);
}

