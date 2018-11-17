/*
 * Copyright (C) 1998 WIDE Project.
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
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/* \summary: IPv6 header option printer */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "netdissect-stdinc.h"

#include "netdissect.h"
#include "addrtoname.h"
#include "extract.h"

#include "ip6.h"

static int
ip6_sopt_print(netdissect_options *ndo, const u_char *bp, int len)
{
    int i;
    int optlen;

    for (i = 0; i < len; i += optlen) {
	if (EXTRACT_U_1(bp + i) == IP6OPT_PAD1)
	    optlen = 1;
	else {
	    if (i + 1 < len)
		optlen = EXTRACT_U_1(bp + i + 1) + 2;
	    else
		goto trunc;
	}
	if (i + optlen > len)
	    goto trunc;

	switch (EXTRACT_U_1(bp + i)) {
	case IP6OPT_PAD1:
            ND_PRINT(", pad1");
	    break;
	case IP6OPT_PADN:
	    if (len - i < IP6OPT_MINLEN) {
		ND_PRINT(", padn: trunc");
		goto trunc;
	    }
            ND_PRINT(", padn");
	    break;
	default:
	    if (len - i < IP6OPT_MINLEN) {
		ND_PRINT(", sopt_type %u: trunc)", EXTRACT_U_1(bp + i));
		goto trunc;
	    }
	    ND_PRINT(", sopt_type 0x%02x: len=%u", EXTRACT_U_1(bp + i), EXTRACT_U_1(bp + i + 1));
	    break;
	}
    }
    return 0;

trunc:
    return -1;
}

static int
ip6_opt_print(netdissect_options *ndo, const u_char *bp, int len)
{
    int i;
    int optlen = 0;

    if (len == 0)
        return 0;
    for (i = 0; i < len; i += optlen) {
	if (EXTRACT_U_1(bp + i) == IP6OPT_PAD1)
	    optlen = 1;
	else {
	    if (i + 1 < len)
		optlen = EXTRACT_U_1(bp + i + 1) + 2;
	    else
		goto trunc;
	}
	if (i + optlen > len)
	    goto trunc;

	switch (EXTRACT_U_1(bp + i)) {
	case IP6OPT_PAD1:
            ND_PRINT("(pad1)");
	    break;
	case IP6OPT_PADN:
	    if (len - i < IP6OPT_MINLEN) {
		ND_PRINT("(padn: trunc)");
		goto trunc;
	    }
            ND_PRINT("(padn)");
	    break;
	case IP6OPT_ROUTER_ALERT:
	    if (len - i < IP6OPT_RTALERT_LEN) {
		ND_PRINT("(rtalert: trunc)");
		goto trunc;
	    }
	    if (EXTRACT_U_1(bp + i + 1) != IP6OPT_RTALERT_LEN - 2) {
		ND_PRINT("(rtalert: invalid len %u)", EXTRACT_U_1(bp + i + 1));
		goto trunc;
	    }
	    ND_PRINT("(rtalert: 0x%04x) ", EXTRACT_BE_U_2(bp + i + 2));
	    break;
	case IP6OPT_JUMBO:
	    if (len - i < IP6OPT_JUMBO_LEN) {
		ND_PRINT("(jumbo: trunc)");
		goto trunc;
	    }
	    if (EXTRACT_U_1(bp + i + 1) != IP6OPT_JUMBO_LEN - 2) {
		ND_PRINT("(jumbo: invalid len %u)", EXTRACT_U_1(bp + i + 1));
		goto trunc;
	    }
	    ND_PRINT("(jumbo: %u) ", EXTRACT_BE_U_4(bp + i + 2));
	    break;
        case IP6OPT_HOME_ADDRESS:
	    if (len - i < IP6OPT_HOMEADDR_MINLEN) {
		ND_PRINT("(homeaddr: trunc)");
		goto trunc;
	    }
	    if (EXTRACT_U_1(bp + i + 1) < IP6OPT_HOMEADDR_MINLEN - 2) {
		ND_PRINT("(homeaddr: invalid len %u)", EXTRACT_U_1(bp + i + 1));
		goto trunc;
	    }
	    ND_PRINT("(homeaddr: %s", ip6addr_string(ndo, bp + i + 2));
	    if (EXTRACT_U_1(bp + i + 1) > IP6OPT_HOMEADDR_MINLEN - 2) {
		if (ip6_sopt_print(ndo, bp + i + IP6OPT_HOMEADDR_MINLEN,
				   (optlen - IP6OPT_HOMEADDR_MINLEN)) == -1)
			goto trunc;
	    }
            ND_PRINT(")");
	    break;
	default:
	    if (len - i < IP6OPT_MINLEN) {
		ND_PRINT("(type %u: trunc)", EXTRACT_U_1(bp + i));
		goto trunc;
	    }
	    ND_PRINT("(opt_type 0x%02x: len=%u)", EXTRACT_U_1(bp + i), EXTRACT_U_1(bp + i + 1));
	    break;
	}
    }
    ND_PRINT(" ");
    return 0;

trunc:
    return -1;
}

int
hbhopt_print(netdissect_options *ndo, const u_char *bp)
{
    const struct ip6_hbh *dp = (const struct ip6_hbh *)bp;
    u_int hbhlen = 0;

    ndo->ndo_protocol = "hbhopt";
    ND_TCHECK_1(dp->ip6h_len);
    hbhlen = (EXTRACT_U_1(dp->ip6h_len) + 1) << 3;
    ND_TCHECK_LEN(dp, hbhlen);
    ND_PRINT("HBH ");
    if (ndo->ndo_vflag)
	if (ip6_opt_print(ndo, (const u_char *)dp + sizeof(*dp),
			  hbhlen - sizeof(*dp)) == -1)
	    goto trunc;
    return hbhlen;

trunc:
    nd_print_trunc(ndo);
    return -1;
}

int
dstopt_print(netdissect_options *ndo, const u_char *bp)
{
    const struct ip6_dest *dp = (const struct ip6_dest *)bp;
    u_int dstoptlen = 0;

    ndo->ndo_protocol = "dstopt";
    ND_TCHECK_1(dp->ip6d_len);
    dstoptlen = (EXTRACT_U_1(dp->ip6d_len) + 1) << 3;
    ND_TCHECK_LEN(dp, dstoptlen);
    ND_PRINT("DSTOPT ");
    if (ndo->ndo_vflag) {
	if (ip6_opt_print(ndo, (const u_char *)dp + sizeof(*dp),
			  dstoptlen - sizeof(*dp)) == -1)
	    goto trunc;
    }

    return dstoptlen;

trunc:
    nd_print_trunc(ndo);
    return -1;
}
