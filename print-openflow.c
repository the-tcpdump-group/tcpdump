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

#define ND_LONGJMP_FROM_TCHECK
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

/* Print a TCP segment worth of OpenFlow messages presuming the segment begins
 * on a message boundary. */
void
openflow_print(netdissect_options *ndo, const u_char *cp, u_int len)
{
	ndo->ndo_protocol = "openflow";
	ND_PRINT(": OpenFlow");
	while (len) {
		/* Print a single OpenFlow message. */
		uint8_t version, type;
		uint16_t length;
		uint32_t xid;

		if (len < OF_HEADER_FIXLEN)
			goto invalid;
		/* version */
		version = GET_U_1(cp);
		OF_FWD(1);
		/* type */
		type = GET_U_1(cp);
		OF_FWD(1);
		/* length */
		length = GET_BE_U_2(cp);
		OF_FWD(2);
		/* xid */
		xid = GET_BE_U_4(cp);
		OF_FWD(4);
		/*
		 * When a TCP packet can contain several protocol messages,
		 * and at the same time a protocol message can span several
		 * TCP packets, decoding an incomplete message at the end of
		 * a TCP packet requires attention to detail in this loop.
		 *
		 * Message length includes the header length and a message
		 * always includes the basic header. A message length underrun
		 * fails decoding of the rest of the current packet. At the
		 * same time, try decoding as much of the current message as
		 * possible even when it does not end within the current TCP
		 * segment.
		 *
		 * Specifically, to try to process the message body in this
		 * iteration do NOT require the header "length" to be small
		 * enough for the full declared OpenFlow message to fit into
		 * the remainder of the declared TCP segment, same as the full
		 * declared TCP segment is not required to fit into the
		 * captured packet buffer.
		 *
		 * But DO require the same at the end of this iteration to
		 * decrement "len" and to proceed to the next iteration.
		 * (Ideally the declared TCP payload end will be at or after
		 * the captured packet buffer end, but stay safe even when
		 * that's somehow not the case.)
		 */
		if (length < OF_HEADER_FIXLEN) {
			of_header_print(ndo, version, type, length, xid);
			goto invalid;
		}
		/*
		 * Decode known protocol versions further without printing the
		 * header (the type decoding is version-specific).
		 */
		switch (version) {
		case OF_VER_1_0:
			of10_header_body_print(ndo, cp, type,
			                       length - OF_HEADER_FIXLEN, xid);
			break;
		default:
			of_header_print(ndo, version, type, length, xid);
			ND_TCHECK_LEN(cp, length - OF_HEADER_FIXLEN);
		}
		if (length - OF_HEADER_FIXLEN > len)
			break;
		OF_FWD(length - OF_HEADER_FIXLEN);
	} /* while (len) */
	return;

invalid: /* fail the current packet */
	nd_print_invalid(ndo);
	ND_TCHECK_LEN(cp, len);
}
