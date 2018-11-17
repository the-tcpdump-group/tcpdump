/*
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

/* \summary: Ad Hoc Configuration Protocol (AHCP) printer */

/* Based on draft-chroboczek-ahcp-00 and source code of ahcpd-0.53 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "netdissect-stdinc.h"

#include "netdissect.h"
#include "extract.h"
#include "addrtoname.h"


#define AHCP_MAGIC_NUMBER 43
#define AHCP_VERSION_1 1
#define AHCP1_HEADER_FIX_LEN 24
#define AHCP1_BODY_MIN_LEN 4

#define AHCP1_MSG_DISCOVER 0
#define AHCP1_MSG_OFFER    1
#define AHCP1_MSG_REQUEST  2
#define AHCP1_MSG_ACK      3
#define AHCP1_MSG_NACK     4
#define AHCP1_MSG_RELEASE  5

static const struct tok ahcp1_msg_str[] = {
	{ AHCP1_MSG_DISCOVER, "Discover" },
	{ AHCP1_MSG_OFFER,    "Offer"    },
	{ AHCP1_MSG_REQUEST,  "Request"  },
	{ AHCP1_MSG_ACK,      "Ack"      },
	{ AHCP1_MSG_NACK,     "Nack"     },
	{ AHCP1_MSG_RELEASE,  "Release"  },
	{ 0, NULL }
};

#define AHCP1_OPT_PAD                     0
#define AHCP1_OPT_MANDATORY               1
#define AHCP1_OPT_ORIGIN_TIME             2
#define AHCP1_OPT_EXPIRES                 3
#define AHCP1_OPT_MY_IPV6_ADDRESS         4
#define AHCP1_OPT_MY_IPV4_ADDRESS         5
#define AHCP1_OPT_IPV6_PREFIX             6
#define AHCP1_OPT_IPV4_PREFIX             7
#define AHCP1_OPT_IPV6_ADDRESS            8
#define AHCP1_OPT_IPV4_ADDRESS            9
#define AHCP1_OPT_IPV6_PREFIX_DELEGATION 10
#define AHCP1_OPT_IPV4_PREFIX_DELEGATION 11
#define AHCP1_OPT_NAME_SERVER            12
#define AHCP1_OPT_NTP_SERVER             13
#define AHCP1_OPT_MAX                    13

static const struct tok ahcp1_opt_str[] = {
	{ AHCP1_OPT_PAD,                    "Pad"                    },
	{ AHCP1_OPT_MANDATORY,              "Mandatory"              },
	{ AHCP1_OPT_ORIGIN_TIME,            "Origin Time"            },
	{ AHCP1_OPT_EXPIRES,                "Expires"                },
	{ AHCP1_OPT_MY_IPV6_ADDRESS,        "My-IPv6-Address"        },
	{ AHCP1_OPT_MY_IPV4_ADDRESS,        "My-IPv4-Address"        },
	{ AHCP1_OPT_IPV6_PREFIX,            "IPv6 Prefix"            },
	{ AHCP1_OPT_IPV4_PREFIX,            "IPv4 Prefix"            },
	{ AHCP1_OPT_IPV6_ADDRESS,           "IPv6 Address"           },
	{ AHCP1_OPT_IPV4_ADDRESS,           "IPv4 Address"           },
	{ AHCP1_OPT_IPV6_PREFIX_DELEGATION, "IPv6 Prefix Delegation" },
	{ AHCP1_OPT_IPV4_PREFIX_DELEGATION, "IPv4 Prefix Delegation" },
	{ AHCP1_OPT_NAME_SERVER,            "Name Server"            },
	{ AHCP1_OPT_NTP_SERVER,             "NTP Server"             },
	{ 0, NULL }
};

static int
ahcp_time_print(netdissect_options *ndo, const u_char *cp, const u_char *ep)
{
	time_t t;
	struct tm *tm;
	char buf[BUFSIZE];

	if (cp + 4 != ep)
		goto invalid;
	ND_TCHECK_4(cp);
	t = EXTRACT_BE_U_4(cp);
	if (NULL == (tm = gmtime(&t)))
		ND_PRINT(": gmtime() error");
	else if (0 == strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", tm))
		ND_PRINT(": strftime() error");
	else
		ND_PRINT(": %s UTC", buf);
	return 0;

invalid:
	nd_print_invalid(ndo);
	ND_TCHECK_LEN(cp, ep - cp);
	return 0;
trunc:
	nd_print_trunc(ndo);
	return -1;
}

static int
ahcp_seconds_print(netdissect_options *ndo, const u_char *cp, const u_char *ep)
{
	if (cp + 4 != ep)
		goto invalid;
	ND_TCHECK_4(cp);
	ND_PRINT(": %us", EXTRACT_BE_U_4(cp));
	return 0;

invalid:
	nd_print_invalid(ndo);
	ND_TCHECK_LEN(cp, ep - cp);
	return 0;
trunc:
	nd_print_trunc(ndo);
	return -1;
}

static int
ahcp_ipv6_addresses_print(netdissect_options *ndo, const u_char *cp, const u_char *ep)
{
	const char *sep = ": ";

	while (cp < ep) {
		if (cp + 16 > ep)
			goto invalid;
		ND_TCHECK_16(cp);
		ND_PRINT("%s%s", sep, ip6addr_string(ndo, cp));
		cp += 16;
		sep = ", ";
	}
	return 0;

invalid:
	nd_print_invalid(ndo);
	ND_TCHECK_LEN(cp, ep - cp);
	return 0;
trunc:
	nd_print_trunc(ndo);
	return -1;
}

static int
ahcp_ipv4_addresses_print(netdissect_options *ndo, const u_char *cp, const u_char *ep)
{
	const char *sep = ": ";

	while (cp < ep) {
		if (cp + 4 > ep)
			goto invalid;
		ND_TCHECK_4(cp);
		ND_PRINT("%s%s", sep, ipaddr_string(ndo, cp));
		cp += 4;
		sep = ", ";
	}
	return 0;

invalid:
	nd_print_invalid(ndo);
	ND_TCHECK_LEN(cp, ep - cp);
	return 0;
trunc:
	nd_print_trunc(ndo);
	return -1;
}

static int
ahcp_ipv6_prefixes_print(netdissect_options *ndo, const u_char *cp, const u_char *ep)
{
	const char *sep = ": ";

	while (cp < ep) {
		if (cp + 17 > ep)
			goto invalid;
		ND_TCHECK_LEN(cp, 17);
		ND_PRINT("%s%s/%u", sep, ip6addr_string(ndo, cp), EXTRACT_U_1(cp + 16));
		cp += 17;
		sep = ", ";
	}
	return 0;

invalid:
	nd_print_invalid(ndo);
	ND_TCHECK_LEN(cp, ep - cp);
	return 0;
trunc:
	nd_print_trunc(ndo);
	return -1;
}

static int
ahcp_ipv4_prefixes_print(netdissect_options *ndo, const u_char *cp, const u_char *ep)
{
	const char *sep = ": ";

	while (cp < ep) {
		if (cp + 5 > ep)
			goto invalid;
		ND_TCHECK_5(cp);
		ND_PRINT("%s%s/%u", sep, ipaddr_string(ndo, cp), EXTRACT_U_1(cp + 4));
		cp += 5;
		sep = ", ";
	}
	return 0;

invalid:
	nd_print_invalid(ndo);
	ND_TCHECK_LEN(cp, ep - cp);
	return 0;
trunc:
	nd_print_trunc(ndo);
	return -1;
}

/* Data decoders signal truncated data with -1. */
static int
(* const data_decoders[AHCP1_OPT_MAX + 1])(netdissect_options *, const u_char *, const u_char *) = {
	/* [AHCP1_OPT_PAD]                    = */  NULL,
	/* [AHCP1_OPT_MANDATORY]              = */  NULL,
	/* [AHCP1_OPT_ORIGIN_TIME]            = */  ahcp_time_print,
	/* [AHCP1_OPT_EXPIRES]                = */  ahcp_seconds_print,
	/* [AHCP1_OPT_MY_IPV6_ADDRESS]        = */  ahcp_ipv6_addresses_print,
	/* [AHCP1_OPT_MY_IPV4_ADDRESS]        = */  ahcp_ipv4_addresses_print,
	/* [AHCP1_OPT_IPV6_PREFIX]            = */  ahcp_ipv6_prefixes_print,
	/* [AHCP1_OPT_IPV4_PREFIX]            = */  NULL,
	/* [AHCP1_OPT_IPV6_ADDRESS]           = */  ahcp_ipv6_addresses_print,
	/* [AHCP1_OPT_IPV4_ADDRESS]           = */  ahcp_ipv4_addresses_print,
	/* [AHCP1_OPT_IPV6_PREFIX_DELEGATION] = */  ahcp_ipv6_prefixes_print,
	/* [AHCP1_OPT_IPV4_PREFIX_DELEGATION] = */  ahcp_ipv4_prefixes_print,
	/* [AHCP1_OPT_NAME_SERVER]            = */  ahcp_ipv6_addresses_print,
	/* [AHCP1_OPT_NTP_SERVER]             = */  ahcp_ipv6_addresses_print,
};

static void
ahcp1_options_print(netdissect_options *ndo, const u_char *cp, const u_char *ep)
{
	uint8_t option_no, option_len;

	while (cp < ep) {
		/* Option no */
		ND_TCHECK_1(cp);
		option_no = EXTRACT_U_1(cp);
		cp += 1;
		ND_PRINT("\n\t %s", tok2str(ahcp1_opt_str, "Unknown-%u", option_no));
		if (option_no == AHCP1_OPT_PAD || option_no == AHCP1_OPT_MANDATORY)
			continue;
		/* Length */
		if (cp + 1 > ep)
			goto invalid;
		ND_TCHECK_1(cp);
		option_len = EXTRACT_U_1(cp);
		cp += 1;
		if (cp + option_len > ep)
			goto invalid;
		/* Value */
		if (option_no <= AHCP1_OPT_MAX && data_decoders[option_no] != NULL) {
			if (data_decoders[option_no](ndo, cp, cp + option_len) < 0)
				break; /* truncated and already marked up */
		} else {
			ND_PRINT(" (Length %u)", option_len);
			ND_TCHECK_LEN(cp, option_len);
		}
		cp += option_len;
	}
	return;

invalid:
	nd_print_invalid(ndo);
	ND_TCHECK_LEN(cp, ep - cp);
	return;
trunc:
	nd_print_trunc(ndo);
}

static void
ahcp1_body_print(netdissect_options *ndo, const u_char *cp, const u_char *ep)
{
	uint8_t type, mbz;
	uint16_t body_len;

	if (cp + AHCP1_BODY_MIN_LEN > ep)
		goto invalid;
	/* Type */
	ND_TCHECK_1(cp);
	type = EXTRACT_U_1(cp);
	cp += 1;
	/* MBZ */
	ND_TCHECK_1(cp);
	mbz = EXTRACT_U_1(cp);
	cp += 1;
	/* Length */
	ND_TCHECK_2(cp);
	body_len = EXTRACT_BE_U_2(cp);
	cp += 2;

	if (ndo->ndo_vflag) {
		ND_PRINT("\n\t%s", tok2str(ahcp1_msg_str, "Unknown-%u", type));
		if (mbz != 0)
			ND_PRINT(", MBZ %u", mbz);
		ND_PRINT(", Length %u", body_len);
	}
	if (cp + body_len > ep)
		goto invalid;

	/* Options */
	if (ndo->ndo_vflag >= 2)
		ahcp1_options_print(ndo, cp, cp + body_len); /* not ep (ignore extra data) */
	else
		ND_TCHECK_LEN(cp, body_len);
	return;

invalid:
	nd_print_invalid(ndo);
	ND_TCHECK_LEN(cp, ep - cp);
	return;
trunc:
	nd_print_trunc(ndo);
}

void
ahcp_print(netdissect_options *ndo, const u_char *cp, const u_int len)
{
	const u_char *ep = ndo->ndo_snapend;
	uint8_t version;

	ndo->ndo_protocol = "ahcp";
	ND_PRINT("AHCP");
	if (len < 2)
		goto invalid;
	/* Magic */
	ND_TCHECK_1(cp);
	if (EXTRACT_U_1(cp) != AHCP_MAGIC_NUMBER)
		goto invalid;
	cp += 1;
	/* Version */
	ND_TCHECK_1(cp);
	version = EXTRACT_U_1(cp);
	cp += 1;
	switch (version) {
		case AHCP_VERSION_1: {
			ND_PRINT(" Version 1");
			if (len < AHCP1_HEADER_FIX_LEN)
				goto invalid;
			if (!ndo->ndo_vflag) {
				ND_TCHECK_LEN(cp, AHCP1_HEADER_FIX_LEN - 2);
				cp += AHCP1_HEADER_FIX_LEN - 2;
			} else {
				/* Hopcount */
				ND_TCHECK_1(cp);
				ND_PRINT("\n\tHopcount %u", EXTRACT_U_1(cp));
				cp += 1;
				/* Original Hopcount */
				ND_TCHECK_1(cp);
				ND_PRINT(", Original Hopcount %u", EXTRACT_U_1(cp));
				cp += 1;
				/* Nonce */
				ND_TCHECK_4(cp);
				ND_PRINT(", Nonce 0x%08x", EXTRACT_BE_U_4(cp));
				cp += 4;
				/* Source Id */
				ND_TCHECK_8(cp);
				ND_PRINT(", Source Id %s", linkaddr_string(ndo, cp, 0, 8));
				cp += 8;
				/* Destination Id */
				ND_TCHECK_8(cp);
				ND_PRINT(", Destination Id %s", linkaddr_string(ndo, cp, 0, 8));
				cp += 8;
			}
			/* Body */
			ahcp1_body_print(ndo, cp, ep);
			break;
		}
		default:
			ND_PRINT(" Version %u (unknown)", version);
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
