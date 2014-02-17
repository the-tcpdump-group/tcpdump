/*
 * Copyright (c) 2000 William C. Fenner.
 *                All rights reserved.
 *
 * Kevin Steves <ks@hp.se> July 2000
 * Modified to:
 * - print version, type string and packet length
 * - print IP address count if > 1 (-v)
 * - verify checksum (-v)
 * - print authentication string (-v)
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code
 * distributions retain the above copyright notice and this paragraph
 * in its entirety, and (2) distributions including binary code include
 * the above copyright notice and this paragraph in its entirety in
 * the documentation or other materials provided with the distribution.
 * The name of William C. Fenner may not be used to endorse or
 * promote products derived from this software without specific prior
 * written permission.  THIS SOFTWARE IS PROVIDED ``AS IS'' AND
 * WITHOUT ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, WITHOUT
 * LIMITATION, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <tcpdump-stdinc.h>

#include <stdio.h>
#include <stdlib.h>

#include "interface.h"
#include "extract.h"
#include "addrtoname.h"

#include "ip.h"
#include "ipproto.h"
/*
 * RFC 2338 (VRRP v2):
 *
 *     0                   1                   2                   3
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |Version| Type  | Virtual Rtr ID|   Priority    | Count IP Addrs|
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |   Auth Type   |   Adver Int   |          Checksum             |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                         IP Address (1)                        |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                            .                                  |
 *    |                            .                                  |
 *    |                            .                                  |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                         IP Address (n)                        |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                     Authentication Data (1)                   |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                     Authentication Data (2)                   |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *
 * RFC 5798 (VRRP v3):
 *
 *    0                   1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                    IPv4 Fields or IPv6 Fields                 |
 *   ...                                                             ...
 *    |                                                               |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |Version| Type  | Virtual Rtr ID|   Priority    |Count IPvX Addr|
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |(rsvd) |     Max Adver Int     |          Checksum             |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                                                               |
 *    +                                                               +
 *    |                       IPvX Address(es)                        |
 *    +                                                               +
 *    |                                                               |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

/* Type */
#define	VRRP_TYPE_ADVERTISEMENT	1

static const struct tok type2str[] = {
	{ VRRP_TYPE_ADVERTISEMENT,	"Advertisement"	},
	{ 0,				NULL		}
};

/* Auth Type */
#define	VRRP_AUTH_NONE		0
#define	VRRP_AUTH_SIMPLE	1
#define	VRRP_AUTH_AH		2

static const struct tok auth2str[] = {
	{ VRRP_AUTH_NONE,		"none"		},
	{ VRRP_AUTH_SIMPLE,		"simple"	},
	{ VRRP_AUTH_AH,			"ah"		},
	{ 0,				NULL		}
};

void
vrrp_print(register const u_char *bp, register u_int len,
    register const u_char *bp2, int ttl)
{
	int version, type, auth_type;
	const char *type_s;

	TCHECK(bp[0]);
	version = (bp[0] & 0xf0) >> 4;
	type = bp[0] & 0x0f;
	type_s = tok2str(type2str, "unknown type (%u)", type);
	printf("VRRPv%u, %s", version, type_s);
	if (ttl != 255)
		printf(", (ttl %u)", ttl);
	if (version < 2 || version > 3 || type != VRRP_TYPE_ADVERTISEMENT)
		return;
	TCHECK(bp[2]);
	printf(", vrid %u, prio %u", bp[1], bp[2]);
	TCHECK(bp[5]);

	if (version == 2) {
		auth_type = bp[4];
		printf(", authtype %s", tok2str(auth2str, NULL, auth_type));
		printf(", intvl %us, length %u", bp[5], len);
	} else { /* version == 3 */
		u_int16_t intvl = (bp[4] & 0x0f) << 8 | bp[5];
		printf(", intvl %ucs, length %u", intvl, len);
	}

	if (vflag) {
		int naddrs = bp[3];
		int i;
		char c;

		if (version == 2 && TTEST2(bp[0], len)) {
			struct cksum_vec vec[1];

			vec[0].ptr = bp;
			vec[0].len = len;
			if (in_cksum(vec, 1))
				printf(", (bad vrrp cksum %x)",
					EXTRACT_16BITS(&bp[6]));
		}

		if (version == 3 && TTEST2(bp[0], len)) {
			u_int16_t cksum = nextproto4_cksum((struct ip *)bp2, bp,
				len, len, IPPROTO_VRRP);
			if (cksum)
				printf(", (bad vrrp cksum %x)",
					EXTRACT_16BITS(&bp[6]));
		}

		printf(", addrs");
		if (naddrs > 1)
			printf("(%d)", naddrs);
		printf(":");
		c = ' ';
		bp += 8;
		for (i = 0; i < naddrs; i++) {
			TCHECK(bp[3]);
			printf("%c%s", c, ipaddr_string(bp));
			c = ',';
			bp += 4;
		}
		if (auth_type == VRRP_AUTH_SIMPLE) { /* simple text password */
			TCHECK(bp[7]);
			printf(" auth \"");
			if (fn_printn(bp, 8, snapend)) {
				printf("\"");
				goto trunc;
			}
			printf("\"");
		}
	}
	return;
trunc:
	printf("[|vrrp]");
}
