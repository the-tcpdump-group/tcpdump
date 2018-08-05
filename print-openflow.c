/*
 * This module implements printing of the very basic (version-independent)
 * OpenFlow header and iteration over OpenFlow messages. It is intended for
 * dispatching of version-specific OpenFlow message decoding.
 *
 *
 * Copyright (c) 2013 The TCPDUMP project
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

/* \summary: version-independent OpenFlow printer */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "netdissect-stdinc.h"

#include "netdissect.h"
#include "extract.h"
#include "openflow.h"
#include "oui.h"


#define OF_VER_1_0    0x01

const struct tok onf_exp_str[] = {
	{ ONF_EXP_ONF,               "ONF Extensions"                                  },
	{ ONF_EXP_BUTE,              "Budapest University of Technology and Economics" },
	{ ONF_EXP_NOVIFLOW,          "NoviFlow"                                        },
	{ ONF_EXP_L3,                "L3+ Extensions, Vendor Neutral"                  },
	{ ONF_EXP_L4L7,              "L4-L7 Extensions"                                },
	{ ONF_EXP_WMOB,              "Wireless and Mobility Extensions"                },
	{ ONF_EXP_FABS,              "Forwarding Abstractions Extensions"              },
	{ ONF_EXP_OTRANS,            "Optical Transport Extensions"                    },
	{ 0, NULL }
};

const char *
of_vendor_name(const uint32_t vendor)
{
	const struct tok *table = (vendor & 0xff000000) == 0 ? oui_values : onf_exp_str;
	return tok2str(table, "unknown", vendor);
}

static void
of_header_print(netdissect_options *ndo, const uint8_t version, const uint8_t type,
                      const uint16_t length, const uint32_t xid)
{
	ND_PRINT("\n\tversion unknown (0x%02x), type 0x%02x, length %u, xid 0x%08x",
	       version, type, length, xid);
}

/* Print a single OpenFlow message. */
static const u_char *
of_header_body_print(netdissect_options *ndo, const u_char *cp, const u_char *ep)
{
	uint8_t version, type;
	uint16_t length;
	uint32_t xid;

	if (ep < cp + OF_HEADER_LEN)
		goto invalid;
	/* version */
	ND_TCHECK_1(cp);
	version = EXTRACT_U_1(cp);
	cp += 1;
	/* type */
	ND_TCHECK_1(cp);
	type = EXTRACT_U_1(cp);
	cp += 1;
	/* length */
	ND_TCHECK_2(cp);
	length = EXTRACT_BE_U_2(cp);
	cp += 2;
	/* xid */
	ND_TCHECK_4(cp);
	xid = EXTRACT_BE_U_4(cp);
	cp += 4;
	/* Message length includes the header length and a message always includes
	 * the basic header. A message length underrun fails decoding of the rest of
	 * the current packet. At the same time, try decoding as much of the current
	 * message as possible even when it does not end within the current TCP
	 * segment. */
	if (length < OF_HEADER_LEN) {
		of_header_print(ndo, version, type, length, xid);
		goto invalid;
	}
	/* Decode known protocol versions further without printing the header (the
	 * type decoding is version-specific. */
	switch (version) {
	case OF_VER_1_0:
		return of10_header_body_print(ndo, cp, ep, type, length, xid);
	default:
		of_header_print(ndo, version, type, length, xid);
		ND_TCHECK_LEN(cp, length - OF_HEADER_LEN);
		return cp + length - OF_HEADER_LEN; /* done with current message */
	}

invalid: /* fail current packet */
	ND_PRINT("%s", istr);
	ND_TCHECK_LEN(cp, ep - cp);
	return ep;
trunc:
	nd_print_trunc(ndo);
	return ep;
}

/* Print a TCP segment worth of OpenFlow messages presuming the segment begins
 * on a message boundary. */
void
openflow_print(netdissect_options *ndo, const u_char *cp, const u_int len _U_)
{
	ndo->ndo_protocol = "openflow";
	ND_PRINT(": OpenFlow");
	while (cp < ndo->ndo_snapend)
		cp = of_header_body_print(ndo, cp, ndo->ndo_snapend);
}
