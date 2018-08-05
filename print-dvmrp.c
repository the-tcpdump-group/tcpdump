/*
 * Copyright (c) 1995, 1996
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

/* \summary: Distance Vector Multicast Routing Protocol printer */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "netdissect-stdinc.h"

#include "netdissect.h"
#include "extract.h"
#include "addrtoname.h"

/*
 * See: RFC 1075 and draft-ietf-idmr-dvmrp-v3
 *
 * DVMRP message types and flag values shamelessly stolen from
 * mrouted/dvmrp.h.
 */
#define DVMRP_PROBE		1	/* for finding neighbors */
#define DVMRP_REPORT		2	/* for reporting some or all routes */
#define DVMRP_ASK_NEIGHBORS	3	/* sent by mapper, asking for a list */
					/* of this router's neighbors */
#define DVMRP_NEIGHBORS		4	/* response to such a request */
#define DVMRP_ASK_NEIGHBORS2	5	/* as above, want new format reply */
#define DVMRP_NEIGHBORS2	6
#define DVMRP_PRUNE		7	/* prune message */
#define DVMRP_GRAFT		8	/* graft message */
#define DVMRP_GRAFT_ACK		9	/* graft acknowledgement */

/*
 * 'flags' byte values in DVMRP_NEIGHBORS2 reply.
 */
#define DVMRP_NF_TUNNEL		0x01	/* neighbors reached via tunnel */
#define DVMRP_NF_SRCRT		0x02	/* tunnel uses IP source routing */
#define DVMRP_NF_DOWN		0x10	/* kernel state of interface */
#define DVMRP_NF_DISABLED	0x20	/* administratively disabled */
#define DVMRP_NF_QUERIER	0x40	/* I am the subnet's querier */

static int print_probe(netdissect_options *, const u_char *, const u_char *, u_int);
static int print_report(netdissect_options *, const u_char *, const u_char *, u_int);
static int print_neighbors(netdissect_options *, const u_char *, const u_char *, u_int);
static int print_neighbors2(netdissect_options *, const u_char *, const u_char *, u_int, uint8_t, uint8_t);
static int print_prune(netdissect_options *, const u_char *);
static int print_graft(netdissect_options *, const u_char *);
static int print_graft_ack(netdissect_options *, const u_char *);

void
dvmrp_print(netdissect_options *ndo,
            const u_char *bp, u_int len)
{
	const u_char *ep;
	u_char type;
	uint8_t major_version, minor_version;

	ndo->ndo_protocol = "dvmrp";
	ep = ndo->ndo_snapend;
	if (bp >= ep)
		return;

	ND_TCHECK_1(bp + 1);
	type = EXTRACT_U_1(bp + 1);

	/* Skip IGMP header */
	bp += 8;
	len -= 8;

	switch (type) {

	case DVMRP_PROBE:
		ND_PRINT(" Probe");
		if (ndo->ndo_vflag) {
			if (print_probe(ndo, bp, ep, len) < 0)
				goto trunc;
		}
		break;

	case DVMRP_REPORT:
		ND_PRINT(" Report");
		if (ndo->ndo_vflag > 1) {
			if (print_report(ndo, bp, ep, len) < 0)
				goto trunc;
		}
		break;

	case DVMRP_ASK_NEIGHBORS:
		ND_PRINT(" Ask-neighbors(old)");
		break;

	case DVMRP_NEIGHBORS:
		ND_PRINT(" Neighbors(old)");
		if (print_neighbors(ndo, bp, ep, len) < 0)
			goto trunc;
		break;

	case DVMRP_ASK_NEIGHBORS2:
		ND_PRINT(" Ask-neighbors2");
		break;

	case DVMRP_NEIGHBORS2:
		ND_PRINT(" Neighbors2");
		/*
		 * extract version from IGMP group address field
		 */
		bp -= 4;
		ND_TCHECK_4(bp);
		major_version = EXTRACT_U_1(bp + 3);
		minor_version = EXTRACT_U_1(bp + 2);
		bp += 4;
		if (print_neighbors2(ndo, bp, ep, len, major_version,
		    minor_version) < 0)
			goto trunc;
		break;

	case DVMRP_PRUNE:
		ND_PRINT(" Prune");
		if (print_prune(ndo, bp) < 0)
			goto trunc;
		break;

	case DVMRP_GRAFT:
		ND_PRINT(" Graft");
		if (print_graft(ndo, bp) < 0)
			goto trunc;
		break;

	case DVMRP_GRAFT_ACK:
		ND_PRINT(" Graft-ACK");
		if (print_graft_ack(ndo, bp) < 0)
			goto trunc;
		break;

	default:
		ND_PRINT(" [type %u]", type);
		break;
	}
	return;

trunc:
	nd_print_trunc(ndo);
	return;
}

static int
print_report(netdissect_options *ndo,
             const u_char *bp, const u_char *ep,
             u_int len)
{
	uint32_t mask, origin;
	u_int metric, done;
	u_int i, width;

	while (len > 0) {
		if (len < 3) {
			ND_PRINT(" [|]");
			return (0);
		}
		ND_TCHECK_3(bp);
		mask = (uint32_t)0xff << 24 | EXTRACT_U_1(bp) << 16 |
			EXTRACT_U_1(bp + 1) << 8 | EXTRACT_U_1(bp + 2);
		width = 1;
		if (EXTRACT_U_1(bp))
			width = 2;
		if (EXTRACT_U_1(bp + 1))
			width = 3;
		if (EXTRACT_U_1(bp + 2))
			width = 4;

		ND_PRINT("\n\tMask %s", intoa(htonl(mask)));
		bp += 3;
		len -= 3;
		do {
			if (bp + width + 1 > ep) {
				ND_PRINT(" [|]");
				return (0);
			}
			if (len < width + 1) {
				ND_PRINT("\n\t  [Truncated Report]");
				return (0);
			}
			origin = 0;
			for (i = 0; i < width; ++i) {
				ND_TCHECK_1(bp);
				origin = origin << 8 | EXTRACT_U_1(bp);
				bp++;
			}
			for ( ; i < 4; ++i)
				origin <<= 8;

			ND_TCHECK_1(bp);
			metric = EXTRACT_U_1(bp);
			bp++;
			done = metric & 0x80;
			metric &= 0x7f;
			ND_PRINT("\n\t  %s metric %u", intoa(htonl(origin)),
				metric);
			len -= width + 1;
		} while (!done);
	}
	return (0);
trunc:
	return (-1);
}

static int
print_probe(netdissect_options *ndo,
            const u_char *bp, const u_char *ep,
            u_int len)
{
	uint32_t genid;

	ND_TCHECK_4(bp);
	if ((len < 4) || ((bp + 4) > ep)) {
		/* { (ctags) */
		ND_PRINT(" [|}");
		return (0);
	}
	genid = EXTRACT_BE_U_4(bp);
	bp += 4;
	len -= 4;
	ND_PRINT(ndo->ndo_vflag > 1 ? "\n\t" : " ");
	ND_PRINT("genid %u", genid);
	if (ndo->ndo_vflag < 2)
		return (0);

	while ((len > 0) && (bp < ep)) {
		ND_TCHECK_4(bp);
		ND_PRINT("\n\tneighbor %s", ipaddr_string(ndo, bp));
		bp += 4; len -= 4;
	}
	return (0);
trunc:
	return (-1);
}

static int
print_neighbors(netdissect_options *ndo,
                const u_char *bp, const u_char *ep,
                u_int len)
{
	const u_char *laddr;
	u_char metric;
	u_char thresh;
	int ncount;

	while (len > 0 && bp < ep) {
		ND_TCHECK_7(bp);
		laddr = bp;
		bp += 4;
		metric = EXTRACT_U_1(bp);
		bp++;
		thresh = EXTRACT_U_1(bp);
		bp++;
		ncount = EXTRACT_U_1(bp);
		bp++;
		len -= 7;
		while (--ncount >= 0) {
			ND_TCHECK_4(bp);
			ND_PRINT(" [%s ->", ipaddr_string(ndo, laddr));
			ND_PRINT(" %s, (%u/%u)]",
				   ipaddr_string(ndo, bp), metric, thresh);
			bp += 4;
			len -= 4;
		}
	}
	return (0);
trunc:
	return (-1);
}

static int
print_neighbors2(netdissect_options *ndo,
                 const u_char *bp, const u_char *ep,
                 u_int len, uint8_t major_version,
                 uint8_t minor_version)
{
	const u_char *laddr;
	u_char metric, thresh, flags;
	int ncount;

	ND_PRINT(" (v %u.%u):", major_version, minor_version);

	while (len > 0 && bp < ep) {
		ND_TCHECK_8(bp);
		laddr = bp;
		bp += 4;
		metric = EXTRACT_U_1(bp);
		bp++;
		thresh = EXTRACT_U_1(bp);
		bp++;
		flags = EXTRACT_U_1(bp);
		bp++;
		ncount = EXTRACT_U_1(bp);
		bp++;
		len -= 8;
		while (--ncount >= 0 && (len >= 4) && (bp + 4) <= ep) {
			ND_PRINT(" [%s -> ", ipaddr_string(ndo, laddr));
			ND_PRINT("%s (%u/%u", ipaddr_string(ndo, bp),
				     metric, thresh);
			if (flags & DVMRP_NF_TUNNEL)
				ND_PRINT("/tunnel");
			if (flags & DVMRP_NF_SRCRT)
				ND_PRINT("/srcrt");
			if (flags & DVMRP_NF_QUERIER)
				ND_PRINT("/querier");
			if (flags & DVMRP_NF_DISABLED)
				ND_PRINT("/disabled");
			if (flags & DVMRP_NF_DOWN)
				ND_PRINT("/down");
			ND_PRINT(")]");
			bp += 4;
			len -= 4;
		}
		if (ncount != -1) {
			ND_PRINT(" [|]");
			return (0);
		}
	}
	return (0);
trunc:
	return (-1);
}

static int
print_prune(netdissect_options *ndo,
            const u_char *bp)
{
	ND_TCHECK_LEN(bp, 12);
	ND_PRINT(" src %s grp %s", ipaddr_string(ndo, bp), ipaddr_string(ndo, bp + 4));
	bp += 8;
	ND_PRINT(" timer ");
	unsigned_relts_print(ndo, EXTRACT_BE_U_4(bp));
	return (0);
trunc:
	return (-1);
}

static int
print_graft(netdissect_options *ndo,
            const u_char *bp)
{
	ND_TCHECK_8(bp);
	ND_PRINT(" src %s grp %s", ipaddr_string(ndo, bp), ipaddr_string(ndo, bp + 4));
	return (0);
trunc:
	return (-1);
}

static int
print_graft_ack(netdissect_options *ndo,
                const u_char *bp)
{
	ND_TCHECK_8(bp);
	ND_PRINT(" src %s grp %s", ipaddr_string(ndo, bp), ipaddr_string(ndo, bp + 4));
	return (0);
trunc:
	return (-1);
}
