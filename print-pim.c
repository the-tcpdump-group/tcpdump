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

#ifndef lint
static const char rcsid[] =
    "@(#) $Header: /tcpdump/master/tcpdump/print-pim.c,v 1.14 1999-11-22 07:25:27 fenner Exp $ (LBL)";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/param.h>
#include <sys/time.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <netinet/udp.h>
#include <netinet/udp_var.h>
#include <netinet/tcp.h>

/*
 * XXX: We consider a case where IPv6 is not ready yet for portability,
 * but PIM dependent defintions should be independent of IPv6...
 */
#ifdef INET6
#include <netinet6/pim6.h>
#else
struct pim {
#if defined(WORDS_BIGENDIAN) || (defined(BYTE_ORDER) && (BYTE_ORDER == LITTLE_ENDIAN))
	u_int	pim_type:4, /* the PIM message type, currently they are:
			    * Hello, Register, Register-Stop, Join/Prune,
			    * Bootstrap, Assert, Graft (PIM-DM only),
			    * Graft-Ack (PIM-DM only), C-RP-Adv
			    */
		pim_ver:4;  /* PIM version number; 2 for PIMv2 */
#else
	u_int	pim_ver:4,	/* PIM version */
		pim_type:4;	/* PIM type    */
#endif
	u_char  pim_rsv;	/* Reserved */
	u_short	pim_cksum;	/* IP style check sum */
};
#endif 


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "interface.h"
#include "addrtoname.h"
#include "extract.h"

static void pimv2_print(register const u_char *bp, register u_int len);

static void
pimv1_join_prune_print(register const u_char *bp, register u_int len)
{
    int maddrlen, addrlen, ngroups, njoin, nprune;
    int njp;

    /* If it's a single group and a single source, use 1-line output. */
    if (TTEST2(bp[0], 30) && bp[11] == 1 &&
	((njoin = EXTRACT_16BITS(&bp[20])) + EXTRACT_16BITS(&bp[22])) == 1) {
	    int hold;

	    (void)printf(" RPF %s ", ipaddr_string(bp));
	    hold = EXTRACT_16BITS(&bp[6]);
	    if (hold != 180) {
		(void)printf("Hold ");
		relts_print(hold);
	    }
	    (void)printf("%s (%s/%d, %s", njoin ? "Join" : "Prune",
		    ipaddr_string(&bp[26]), bp[25] & 0x3f,
		    ipaddr_string(&bp[12]));
	    if (EXTRACT_32BITS(&bp[16]) != 0xffffffff)
		    (void)printf("/%s", ipaddr_string(&bp[16]));
	    (void)printf(") %s%s %s",
		    (bp[24] & 0x01) ? "Sparse" : "Dense",
		    (bp[25] & 0x80) ? " WC" : "",
		    (bp[25] & 0x40) ? "RP" : "SPT");
	    return;
    }
	
    TCHECK2(bp[0], 4);
    (void)printf("\n Upstream Nbr: %s", ipaddr_string(bp));
    TCHECK2(bp[6], 2);
    (void)printf("\n Hold time: ");
    relts_print(EXTRACT_16BITS(&bp[6]));
    bp += 8; len -= 8;

    TCHECK2(bp[0], 4);
    maddrlen = bp[1];
    addrlen = bp[2];
    ngroups = bp[3];
    bp += 4; len -= 4;
    while (ngroups--) {
	TCHECK2(bp[0], 4);
	(void)printf("\n\tGroup: %s", ipaddr_string(bp));
	if (EXTRACT_32BITS(&bp[4]) != 0xffffffff)
		(void)printf("/%s", ipaddr_string(&bp[4]));
	TCHECK2(bp[8], 4);
	njoin = EXTRACT_16BITS(&bp[8]);
	nprune = EXTRACT_16BITS(&bp[10]);
	(void)printf(" joined: %d pruned: %d", njoin, nprune);
	bp += 12; len -= 12;
	for (njp = 0; njp < (njoin + nprune); njp++) {
	    char *type;

	    if (njp < njoin) {
		type = "Join ";
	    } else {
		type = "Prune";
	    }
	    TCHECK2(bp[0], 6);
	    (void)printf("\n\t%s %s%s%s%s/%d", type,
			    (bp[0] & 0x01) ? "Sparse " : "Dense ",
			    (bp[1] & 0x80) ? "WC " : "",
			    (bp[1] & 0x40) ? "RP " : "SPT ",
			    ipaddr_string(&bp[2]), bp[1] & 0x3f);
	    bp += 6; len -= 6;
	}
    }
    return;
trunc:
    (void)printf("[|pim]");
    return;
}

void
pimv1_print(register const u_char *bp, register u_int len)
{
    register const u_char *ep;
    register u_char type;

    ep = (const u_char *)snapend;
    if (bp >= ep)
	return;

    type = bp[1];

    switch (type) {
    case 0:
	(void)printf(" Query");
	if (TTEST(bp[8])) {
		switch (bp[8] >> 4) {
		    case 0:	(void)printf(" Dense-mode");
				break;
		    case 1:	(void)printf(" Sparse-mode");
				break;
		    case 2:	(void)printf(" Sparse-Dense-mode");
				break;
		    default:	(void)printf(" mode-%d", bp[8] >> 4);
				break;
		}
	}
	if (vflag) {
	    TCHECK2(bp[10],2);
	    (void)printf(" (Hold-time ");
	    relts_print(EXTRACT_16BITS(&bp[10]));
	    (void)printf(")");
	}
	break;

    case 1:
	(void)printf(" Register");
	TCHECK2(bp[8], 20);			/* ip header */
	(void)printf(" for %s > %s", ipaddr_string(&bp[20]),
				     ipaddr_string(&bp[24]));
	break;

    case 2:
	(void)printf(" Register-Stop");
	TCHECK2(bp[12], 4);
	(void)printf(" for %s > %s", ipaddr_string(&bp[8]),
				     ipaddr_string(&bp[12]));
	break;

    case 3:
	(void)printf(" Join/Prune");
	if (vflag) {
	    pimv1_join_prune_print(&bp[8], len - 8);
	}
	break;

    case 4:
	(void)printf(" RP-reachable");
	if (vflag) {
		TCHECK2(bp[22], 2);
		(void)printf(" group %s",
			ipaddr_string(&bp[8]));
		if (EXTRACT_32BITS(&bp[12]) != 0xffffffff)
			(void)printf("/%s", ipaddr_string(&bp[12]));
		(void)printf(" RP %s hold ",
			ipaddr_string(&bp[16]));
		relts_print(EXTRACT_16BITS(&bp[22]));
	}
	break;

    case 5:
	(void)printf(" Assert");
	TCHECK2(bp[16], 4);
	(void)printf(" for %s > %s", ipaddr_string(&bp[16]),
					    ipaddr_string(&bp[8]));
	if (EXTRACT_32BITS(&bp[12]) != 0xffffffff)
		(void)printf("/%s", ipaddr_string(&bp[12]));
	TCHECK2(bp[24], 4);
	(void)printf(" %s pref %d metric %d",
		(bp[20] & 0x80) ? "RP-tree" : "SPT",
		EXTRACT_32BITS(&bp[20]) & 0x7fffffff,
		EXTRACT_32BITS(&bp[24]));
	break;

    case 6:
	(void)printf(" Graft");
	if (vflag) {
	    pimv1_join_prune_print(&bp[8], len - 8);
	}
	break;

    case 7:
	(void)printf(" Graft-ACK");
	if (vflag) {
	    pimv1_join_prune_print(&bp[8], len - 8);
	}
	break;

    case 8:
	(void)printf(" Mode");
	break;

    default:
	(void)printf(" [type %d]", type);
	break;
    }
    if ((bp[4] >> 4) != 1)
	(void)printf(" [v%d]", bp[4] >> 4);
    return;

trunc:
    (void)printf("[|pim]");
    return;
}

/*
 * auto-RP is a cisco protocol, documented at
 * ftp://ftpeng.cisco.com/ipmulticast/pim-autorp-spec01.txt
 */
void
cisco_autorp_print(register const u_char *bp, register u_int len)
{
    int type;
    int numrps;
    int hold;

    TCHECK(bp[0]);
    (void)printf(" auto-rp ");
    type = bp[0];
    switch (type) {
    case 0x11:
	(void)printf("candidate-advert");
	break;
    case 0x12:
	(void)printf("mapping");
	break;
    default:
	(void)printf("type-0x%02x", type);
	break;
    }

    TCHECK(bp[1]);
    numrps = bp[1];

    TCHECK2(bp[2], 2);
    (void)printf(" Hold ");
    hold = EXTRACT_16BITS(&bp[2]);
    if (hold)
	relts_print(EXTRACT_16BITS(&bp[2]));
    else
	printf("FOREVER");

    /* Next 4 bytes are reserved. */

    bp += 8; len -= 8;

    /*XXX skip unless -v? */

    /*
     * Rest of packet:
     * numrps entries of the form:
     * 32 bits: RP
     * 6 bits: reserved
     * 2 bits: PIM version supported, bit 0 is "supports v1", 1 is "v2".
     * 8 bits: # of entries for this RP
     * each entry: 7 bits: reserved, 1 bit: negative,
     *			8 bits: mask 32 bits: source
     * lather, rinse, repeat.
     */
    while (numrps--) {
	int nentries;
	char s;

	TCHECK2(bp[0], 4);
	(void)printf(" RP %s", ipaddr_string(bp));
	TCHECK(bp[4]);
	switch(bp[4] & 0x3) {
	case 0:	printf(" PIMv?");
		break;
	case 1:	printf(" PIMv1");
		break;
	case 2:	printf(" PIMv2");
		break;
	case 3:	printf(" PIMv1+2");
		break;
	}
	TCHECK(bp[5]);
	nentries = bp[5];
	bp += 6; len -= 6;
	s = ' ';
	for (; nentries; nentries--) {
	    TCHECK2(bp[0], 6);
	    (void)printf("%c%s%s/%d", s, bp[0] & 1 ? "!" : "",
					ipaddr_string(&bp[2]), bp[1]);
	    s = ',';
	    bp += 6; len -= 6;
	}
    }
    return;

trunc:
    (void)printf("[|autorp]");
    return;
}

void
pim_print(register const u_char *bp, register u_int len)
{
	register const u_char *ep;
	register struct pim *pim = (struct pim *)bp;

	ep = (const u_char *)snapend;
	if (bp >= ep)
		return;
#ifdef notyet			/* currently we see only version and type */
	TCHECK(pim->pim_rsv);
#endif

	switch(pim->pim_ver) {
	 case 2:		/* avoid hardcoding? */
		(void)printf("v2");
		pimv2_print(bp, len);
		break;
	 default:
		(void)printf("v%d", pim->pim_ver);
		break;
	}
	return;
}

enum pimv2_addrtype {
	pimv2_unicast, pimv2_group, pimv2_source
};
#if 0
static char *addrtypestr[] = {
	"unicast", "group", "source"
};
#endif

static int
pimv2_addr_print(const u_char *bp, enum pimv2_addrtype at, int silent)
{
	const u_char *ep;
	int af;
	char *afstr;
	int len;

	ep = (const u_char *)snapend;
	if (bp >= ep)
		return -1;

	switch (bp[0]) {
	 case 1:
		af = AF_INET;
		afstr = "IPv4";
		break;
#ifdef INET6
	 case 2:
		af = AF_INET6;
		afstr = "IPv6";
		break;
#endif
	 default:
		return -1;
	}

	if (bp[1] != 0)
		return -1;

	switch (at) {
	 case pimv2_unicast:
		if (af == AF_INET) {
			len = 4;
			if (bp + 2 + len > ep)
				return -1;
			if (!silent)
				(void)printf("%s", ipaddr_string(bp + 2));
		}
#ifdef INET6
		else if (af == AF_INET6) {
			len = 16;
			if (bp + 2 + len > ep)
				return -1;
			if (!silent)
				(void)printf("%s", ip6addr_string(bp + 2));
		}
#endif
		return 2 + len;
	 case pimv2_group:
		if (af == AF_INET) {
			len = 4;
			if (bp + 4 + len > ep)
				return -1;
			if (!silent)
				(void)printf("%s/%u", ipaddr_string(bp + 4), bp[3]);
		}
#ifdef INET6
		else if (af == AF_INET6) {
			len = 16;
			if (bp + 4 + len > ep)
				return -1;
			if (!silent)
				(void)printf("%s/%u", ip6addr_string(bp + 4), bp[3]);
		}
#endif
		return 4 + len;
	 case pimv2_source:
		if (af == AF_INET) {
			len = 4;
			if (bp + 4 + len > ep)
				return -1;
			if (!silent)
				(void)printf("%s/%u", ipaddr_string(bp + 4), bp[3]);
		}
#ifdef INET6
		else if (af == AF_INET6) {
			len = 16;
			if (bp + 4 + len > ep)
				return -1;
			if (!silent)
				(void)printf("%s/%u", ip6addr_string(bp + 4), bp[3]);
		}
#endif
		if (vflag && bp[2] && !silent) {
			(void)printf("(%s%s%s)",
				bp[2] & 0x04 ? "S" : "",
				bp[2] & 0x02 ? "W" : "",
				bp[2] & 0x01 ? "R" : "");
		}
		return 4 + len;
	default:
		return -1;
	}
}

static void
pimv2_print(register const u_char *bp, register u_int len)
{
	register const u_char *ep;
	register struct pim *pim = (struct pim *)bp;
	int advance;

	ep = (const u_char *)snapend;
	if (bp >= ep)
		return;
#ifdef notyet			/* currently we see only version and type */
	TCHECK(pim->pim_rsv);
#endif

	switch (pim->pim_type) {
	 case 0:
	    {
		u_int16_t otype, olen;
		(void)printf(" Hello");
		bp += 4;
		while (bp < ep) {
			otype = ntohs(*(u_int16_t *)(bp + 0));
			olen = ntohs(*(u_int16_t *)(bp + 2));
			if (otype == 1 && olen == 2 && bp + 4 + olen <= ep) {
				u_int16_t value;
				(void)printf(" holdtime=");
				value = ntohs(*(u_int16_t *)(bp + 4));
				if (value == 0xffff)
					(void)printf("infty");
				else
					(void)printf("%u", value);
				bp += 4 + olen;
			} else
				break;
		}
		break;
	    }

	 case 1:
	 {
		struct ip *ip;

		(void)printf(" Register");
		if (vflag && bp + 8 <= ep) {
			(void)printf(" %s%s", bp[4] & 0x80 ? "B" : "",
				bp[4] & 0x40 ? "N" : "");
		}
		bp += 8; len -= 8;

		/* encapsulated multicast packet */
		if (bp >= ep)
			break;
		ip = (struct ip *)bp;
		switch(ip->ip_v) {
		 case 4:	/* IPv4 */
			printf(" ");
			ip_print(bp, len);
			break;
#ifdef INET6
		 case 6:	/* IPv6 */
			printf(" ");
			ip6_print(bp, len);
			break;
#endif
		 default:
			(void)printf(" IP ver %d", ip->ip_v);
			break;
		}
		break;
	 }

	 case 2:
		(void)printf(" Register-Stop");
		bp += 4; len -= 4;
		if (bp >= ep)
			break;
		(void)printf(" group=");
		if ((advance = pimv2_addr_print(bp, pimv2_group, 0)) < 0) {
			(void)printf("...");
			break;
		}
		bp += advance; len -= advance;
		if (bp >= ep)
			break;
		(void)printf(" source=");
		if ((advance = pimv2_addr_print(bp, pimv2_unicast, 0)) < 0) {
			(void)printf("...");
			break;
		}
		bp += advance; len -= advance;
		break;

	 case 3:
	 case 6:
	 case 7:
	    {
		u_int8_t ngroup;
		u_int16_t holdtime;
		u_int16_t njoin;
		u_int16_t nprune;
		int i, j;

		switch (pim->pim_type) {
		 case 3:
			(void)printf(" Join/Prune");
			break;
		 case 6:
			(void)printf(" Graft");
			break;
		 case 7:
			(void)printf(" Graft-ACK");
			break;
		}
		bp += 4; len -= 4;
		if (pim->pim_type != 7) {	/*not for Graft-ACK*/
			if (bp >= ep)
				break;
			(void)printf(" upstream-neighbor=");
			if ((advance = pimv2_addr_print(bp, pimv2_unicast, 0)) < 0) {
				(void)printf("...");
				break;
			}
			bp += advance; len -= advance;
		}
		if (bp + 4 > ep)
			break;
		ngroup = bp[1];
		holdtime = ntohs(*(u_int16_t *)(bp + 2));
		(void)printf(" groups=%u", ngroup);
		if (pim->pim_type != 7) {	/*not for Graft-ACK*/
			(void)printf(" holdtime=");
			if (holdtime == 0xffff)
				(void)printf("infty");
			else
				(void)printf("%u", holdtime);
		}
		bp += 4; len -= 4;
		for (i = 0; i < ngroup; i++) {
			if (bp >= ep)
				goto jp_done;
			(void)printf(" (group%d: ", i);
			if ((advance = pimv2_addr_print(bp, pimv2_group, 0)) < 0) {
				(void)printf("...)");
				goto jp_done;
			}
			bp += advance; len -= advance;
			if (bp + 4 > ep) {
				(void)printf("...)");
				goto jp_done;
			}
			njoin = ntohs(*(u_int16_t *)(bp + 0));
			nprune = ntohs(*(u_int16_t *)(bp + 2));
			(void)printf(" join=%u", njoin);
			bp += 4; len -= 4;
			for (j = 0; j < njoin; j++) {
				(void)printf(" ");
				if ((advance = pimv2_addr_print(bp, pimv2_source, 0)) < 0) {
					(void)printf("...)");
					goto jp_done;
				}
				bp += advance; len -= advance;
			}
			(void)printf(" prune=%u", nprune);
			for (j = 0; j < nprune; j++) {
				(void)printf(" ");
				if ((advance = pimv2_addr_print(bp, pimv2_source, 0)) < 0) {
					(void)printf("...)");
					goto jp_done;
				}
				bp += advance; len -= advance;
			}
			(void)printf(")");
		}
	jp_done:
		break;
	    }

	 case 4:
	 {
		int i, j, frpcnt;

		(void)printf(" Bootstrap");
		bp += 4;

		/* Fragment Tag, Hash Mask len, and BSR-priority */
		if (bp + sizeof(u_int16_t) >= ep) break;
		(void)printf(" tag=%x", ntohs(*(u_int16_t *)bp));
		bp += sizeof(u_int16_t);
		if (bp >= ep) break;
		(void)printf(" hashmlen=%d", bp[0]);
		if (bp + 1 >= ep) break;
		(void)printf(" BSRprio=%d", bp[1]);
		bp += 2;

		/* Encoded-Unicast-BSR-Address */
		if (bp >= ep) break;
		(void)printf(" BSR=");
		if ((advance = pimv2_addr_print(bp, pimv2_unicast, 0)) < 0) {
			(void)printf("...");
			break;
		}
		bp += advance;

		for (i = 0; bp < ep; i++) {
			/* Encoded-Group Address */
			(void)printf(" (group%d: ", i);
			if ((advance = pimv2_addr_print(bp, pimv2_group, 0))
			    < 0) {
				(void)printf("...)");
				goto bs_done;
			}
			bp += advance;

			/* RP-Count, Frag RP-Cnt, and rsvd */
			if (bp >= ep) {
				(void)printf("...)");
				goto bs_done;
			}
			(void)printf(" RPcnt=%d", frpcnt = bp[0]);
			if (bp + 1 >= ep) {
				(void)printf("...)");
				goto bs_done;
			}
			(void)printf(" FRPcnt=%d", bp[1]);
			bp += 4;

			for (j = 0; j < frpcnt && bp < ep; j++) {
				/* each RP info */
				(void)printf(" RP%d=", j);
				if ((advance = pimv2_addr_print(bp,
								pimv2_unicast,
								0)) < 0) {
					(void)printf("...)");
					goto bs_done;
				}
				bp += advance;

				if (bp + 1 >= ep) {
					(void)printf("...)");
					goto bs_done;
				}
				(void)printf(",holdtime=%d",
					     ntohs(*(u_int16_t *)bp));
				if (bp + 2 >= ep) {
					(void)printf("...)");
					goto bs_done;
				}
				(void)printf(",prio=%d", bp[2]);
				bp += 4;
			}
			(void)printf(")");
		}
	   bs_done:
		break;
	 }
	 case 5:
		(void)printf(" Assert");
		bp += 4; len -= 4;
		if (bp >= ep)
			break;
		(void)printf(" group=");
		if ((advance = pimv2_addr_print(bp, pimv2_group, 0)) < 0) {
			(void)printf("...");
			break;
		}
		bp += advance; len -= advance;
		if (bp >= ep)
			break;
		(void)printf(" src=");
		if ((advance = pimv2_addr_print(bp, pimv2_unicast, 0)) < 0) {
			(void)printf("...");
			break;
		}
		bp += advance; len -= advance;
		if (bp + 8 > ep)
			break;
		if (ntohl(*(u_int32_t *)bp) & 0x80000000)
			(void)printf(" RPT");
		(void)printf(" pref=%u", ntohl(*(u_int32_t *)bp & 0x7fffffff));
		(void)printf(" metric=%u", ntohl(*(u_int32_t *)(bp + 4)));
		break;

	 case 8:
	 {
		int i, pfxcnt;

		(void)printf(" Candidate-RP-Advertisement");
		bp += 4;

		/* Prefix-Cnt, Priority, and Holdtime */
		if (bp >= ep) break;
		(void)printf(" prefix-cnt=%d", bp[0]);
		pfxcnt = bp[0];
		if (bp + 1 >= ep) break;
		(void)printf(" prio=%d", bp[1]);
		if (bp + 3 >= ep) break;
		(void)printf(" holdtime=%d", ntohs(*(u_int16_t *)(bp + 2)));
		bp += 4;

		/* Encoded-Unicast-RP-Address */
		if (bp >= ep) break;
		(void)printf(" RP=");
		if ((advance = pimv2_addr_print(bp, pimv2_unicast, 0)) < 0) {
			(void)printf("...");
			break;
		}
		bp += advance;

		/* Encoded-Group Addresses */
		for (i = 0; i < pfxcnt && bp < ep; i++) {
			(void)printf(" Group%d=", i);
			if ((advance = pimv2_addr_print(bp, pimv2_group, 0))
			    < 0) {
				(void)printf("...");
				break;
			}
			bp += advance;
		}
		break;
	 }

	 default:
		(void)printf(" [type %d]", pim->pim_type);
		break;
	}

	return;
}
