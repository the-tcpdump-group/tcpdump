/*
 * Copyright (C) 1999 WIDE Project.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef lint
static const char rcsid[] =
     "@(#) $Header: /tcpdump/master/tcpdump/print-bgp.c,v 1.37 2002-07-18 00:39:12 hannes Exp $";
#endif

#include <sys/param.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <netdb.h>

#include "interface.h"
#include "addrtoname.h"
#include "extract.h"

struct bgp {
	u_int8_t bgp_marker[16];
	u_int16_t bgp_len;
	u_int8_t bgp_type;
};
#define BGP_SIZE		19	/* unaligned */

#define BGP_OPEN		1
#define BGP_UPDATE		2
#define BGP_NOTIFICATION	3
#define BGP_KEEPALIVE		4

static struct tok bgp_msg_values[] = {
    { BGP_OPEN,                 "Open"},
    { BGP_UPDATE,               "Update"},
    { BGP_NOTIFICATION,         "Notification"},
    { BGP_KEEPALIVE,            "Keepalive"},
    { 0, NULL}
};

struct bgp_open {
	u_int8_t bgpo_marker[16];
	u_int16_t bgpo_len;
	u_int8_t bgpo_type;
	u_int8_t bgpo_version;
	u_int16_t bgpo_myas;
	u_int16_t bgpo_holdtime;
	u_int32_t bgpo_id;
	u_int8_t bgpo_optlen;
	/* options should follow */
};
#define BGP_OPEN_SIZE		29	/* unaligned */

struct bgp_opt {
	u_int8_t bgpopt_type;
	u_int8_t bgpopt_len;
	/* variable length */
};
#define BGP_OPT_SIZE		2	/* some compilers may pad to 4 bytes */

struct bgp_notification {
	u_int8_t bgpn_marker[16];
	u_int16_t bgpn_len;
	u_int8_t bgpn_type;
	u_int8_t bgpn_major;
	u_int8_t bgpn_minor;
	/* data should follow */
};
#define BGP_NOTIFICATION_SIZE		21	/* unaligned */

struct bgp_attr {
	u_int8_t bgpa_flags;
	u_int8_t bgpa_type;
	union {
		u_int8_t len;
		u_int16_t elen;
	} bgpa_len;
#define bgp_attr_len(p) \
	(((p)->bgpa_flags & 0x10) ? \
		ntohs((p)->bgpa_len.elen) : (p)->bgpa_len.len)
#define bgp_attr_off(p) \
	(((p)->bgpa_flags & 0x10) ? 4 : 3)
};

#define BGPTYPE_ORIGIN			1
#define BGPTYPE_AS_PATH			2
#define BGPTYPE_NEXT_HOP		3
#define BGPTYPE_MULTI_EXIT_DISC		4
#define BGPTYPE_LOCAL_PREF		5
#define BGPTYPE_ATOMIC_AGGREGATE	6
#define BGPTYPE_AGGREGATOR		7
#define	BGPTYPE_COMMUNITIES		8	/* RFC1997 */
#define	BGPTYPE_ORIGINATOR_ID		9	/* RFC1998 */
#define	BGPTYPE_CLUSTER_LIST		10	/* RFC1998 */
#define	BGPTYPE_DPA			11	/* draft-ietf-idr-bgp-dpa */
#define	BGPTYPE_ADVERTISERS		12	/* RFC1863 */
#define	BGPTYPE_RCID_PATH		13	/* RFC1863 */
#define BGPTYPE_MP_REACH_NLRI		14	/* RFC2283 */
#define BGPTYPE_MP_UNREACH_NLRI		15	/* RFC2283 */
#define BGPTYPE_EXTD_COMMUNITIES        16      /* draft-ietf-idr-bgp-ext-communities */

static struct tok bgp_attr_values[] = {
    { BGPTYPE_ORIGIN,           "Origin"},
    { BGPTYPE_AS_PATH,          "AS Path"},
    { BGPTYPE_NEXT_HOP,         "Next Hop"},
    { BGPTYPE_MULTI_EXIT_DISC,  "Multi Exit Discriminator"},
    { BGPTYPE_LOCAL_PREF,       "Local Preference"},
    { BGPTYPE_ATOMIC_AGGREGATE, "Atomic Aggregate"},
    { BGPTYPE_AGGREGATOR,       "Aggregator"},
    { BGPTYPE_COMMUNITIES,      "Community"},
    { BGPTYPE_ORIGINATOR_ID,    "Originator ID"},
    { BGPTYPE_CLUSTER_LIST,     "Cluster List"},
    { BGPTYPE_DPA,              "DPA"},
    { BGPTYPE_ADVERTISERS,      "Advertisers"},
    { BGPTYPE_RCID_PATH,        "RCID Path / Cluster ID"},
    { BGPTYPE_MP_REACH_NLRI,    "Multi-Protocol Reach NLRI"},
    { BGPTYPE_MP_UNREACH_NLRI,  "Multi-Protocol Unreach NLRI"},
    { BGPTYPE_EXTD_COMMUNITIES, "Extended Community"},
    { 255,                      "Reserved for development"},
    { 0, NULL}
};

#define BGP_OPT_AUTH                    1
#define BGP_OPT_CAP                     2


static struct tok bgp_opt_values[] = {
    { BGP_OPT_AUTH,             "Authentication Information"},
    { BGP_OPT_CAP,              "Capabilities Advertisement"},
    { 0, NULL}
};

#define BGP_CAPCODE_MP                  1
#define BGP_CAPCODE_RR                  2
#define BGP_CAPCODE_RR_CISCO          128

static struct tok bgp_capcode_values[] = {
    { BGP_CAPCODE_MP,           "Multiprotocol Extensions"},
    { BGP_CAPCODE_RR,           "Route Refresh"},
    { BGP_CAPCODE_RR_CISCO,     "Route Refresh (Cisco)"},
    { 0, NULL}
};

#define BGP_NOTIFY_MAJOR_MSG            1
#define BGP_NOTIFY_MAJOR_OPEN           2
#define BGP_NOTIFY_MAJOR_UPDATE         3
#define BGP_NOTIFY_MAJOR_HOLDTIME       4
#define BGP_NOTIFY_MAJOR_FSM            5
#define BGP_NOTIFY_MAJOR_CEASE          6

static struct tok bgp_notify_major_values[] = {
    { BGP_NOTIFY_MAJOR_MSG,     "Message Header Error"},
    { BGP_NOTIFY_MAJOR_OPEN,    "OPEN Message Error"},
    { BGP_NOTIFY_MAJOR_UPDATE,  "UPDATE Message Error"},
    { BGP_NOTIFY_MAJOR_HOLDTIME,"Hold Timer Expired"},
    { BGP_NOTIFY_MAJOR_FSM,     "Finite State Machine Error"},
    { BGP_NOTIFY_MAJOR_CEASE,   "Cease"},
    { 0, NULL}
};

static struct tok bgp_notify_minor_msg_values[] = {
    { 1,                        "Connection Not Synchronized"},
    { 2,                        "Bad Message Length"},
    { 3,                        "Bad Message Type"},
    { 0, NULL}
};

static struct tok bgp_notify_minor_open_values[] = {
    { 1,                        "Unsupported Version Number"},
    { 2,                        "Bad Peer AS"},
    { 3,                        "Bad BGP Identifier"},
    { 4,                        "Unsupported Optional Parameter"},
    { 5,                        "Authentication Failure"},
    { 6,                        "Unacceptable Hold Time"},
    { 0, NULL}
};

static struct tok bgp_notify_minor_update_values[] = {
    { 1,                        "Malformed Attribute List"},
    { 2,                        "Unrecognized Well-known Attribute"},
    { 3,                        "Missing Well-known Attribute"},
    { 4,                        "Attribute Flags Error"},
    { 5,                        "Attribute Length Error"},
    { 6,                        "Invalid ORIGIN Attribute"},
    { 7,                        "AS Routing Loop"},
    { 8,                        "Invalid NEXT_HOP Attribute"},
    { 9,                        "Optional Attribute Error"},
    { 10,                       "Invalid Network Field"},
    { 11,                       "Malformed AS_PATH"},
    { 0, NULL}
};

static struct tok bgp_origin_values[] = {
    { 0,                        "IGP"},
    { 1,                        "EGP"},
    { 2,                        "Incomplete"},
    { 0, NULL}
};

/* Subsequent address family identifier, RFC2283 section 7 */
#define SAFNUM_RES                      0
#define SAFNUM_UNICAST                  1
#define SAFNUM_MULTICAST                2
#define SAFNUM_UNIMULTICAST             3
/* labeled BGP RFC3107 */
#define SAFNUM_LABUNICAST               4
/* Section 4.3.4 of draft-rosen-rfc2547bis-03.txt  */
#define SAFNUM_VPNUNICAST               128
#define SAFNUM_VPNMULTICAST             129
#define SAFNUM_VPNUNIMULTICAST          130

static struct tok bgp_safi_values[] = {
    { SAFNUM_RES,               "Reserved"},
    { SAFNUM_UNICAST,           "Unicast"},
    { SAFNUM_MULTICAST,         "Multicast"},
    { SAFNUM_UNIMULTICAST,      "Unicast+Multicast"},
    { SAFNUM_LABUNICAST,        "labeled Unicast"},
    { SAFNUM_VPNUNICAST,        "labeled VPN Unicast"},
    { SAFNUM_VPNMULTICAST,      "labeled VPN Multicast"},
    { SAFNUM_VPNUNIMULTICAST,   "labeled VPN Unicast+Multicast"},
    { 0, NULL }
};

/* well-known community */
#define BGP_COMMUNITY_NO_EXPORT			0xffffff01
#define BGP_COMMUNITY_NO_ADVERT			0xffffff02
#define BGP_COMMUNITY_NO_EXPORT_SUBCONFED	0xffffff03

/* RFC1700 address family numbers */
#define AFNUM_INET	1
#define AFNUM_INET6	2
#define AFNUM_NSAP	3
#define AFNUM_HDLC	4
#define AFNUM_BBN1822	5
#define AFNUM_802	6
#define AFNUM_E163	7
#define AFNUM_E164	8
#define AFNUM_F69	9
#define AFNUM_X121	10
#define AFNUM_IPX	11
#define AFNUM_ATALK	12
#define AFNUM_DECNET	13
#define AFNUM_BANYAN	14
#define AFNUM_E164NSAP	15
/* draft-kompella-ppvpn-l2vpn */
#define AFNUM_L2VPN     196 /* still to be approved by IANA */

static struct tok bgp_afi_values[] = {
    { 0,                      "Reserved"},
    { AFNUM_INET,             "IPv4"},
    { AFNUM_INET6,            "IPv6"},
    { AFNUM_NSAP,             "NSAP"},
    { AFNUM_HDLC,             "HDLC"},
    { AFNUM_BBN1822,          "BBN 1822"},
    { AFNUM_802,              "802"},
    { AFNUM_E163,             "E.163"},
    { AFNUM_E164,             "E.164"},
    { AFNUM_F69,              "F.69"},
    { AFNUM_X121,             "X.121"},
    { AFNUM_IPX,              "Novell IPX"},
    { AFNUM_ATALK,            "Appletalk"},
    { AFNUM_DECNET,           "Decnet IV"},
    { AFNUM_BANYAN,           "Banyan Vines"},
    { AFNUM_E164NSAP,         "E.164 with NSAP subaddress"},
    { AFNUM_L2VPN,            "Layer-2 VPN"},
    { 0, NULL},
};

static int
decode_prefix4(const u_char *pd, char *buf, u_int buflen)
{
	struct in_addr addr;
	u_int plen;

	plen = pd[0];
	if (plen < 0 || 32 < plen)
		return -1;

	memset(&addr, 0, sizeof(addr));
	memcpy(&addr, &pd[1], (plen + 7) / 8);
	if (plen % 8) {
		((u_char *)&addr)[(plen + 7) / 8 - 1] &=
			((0xff00 >> (plen % 8)) & 0xff);
	}
	snprintf(buf, buflen, "%s/%d", getname((u_char *)&addr), plen);
	return 1 + (plen + 7) / 8;
}

static int
decode_labeled_prefix4(const u_char *pd, char *buf, u_int buflen)
{
	struct in_addr addr;
	u_int plen;

	plen = pd[0];   /* get prefix length */

        /* this is one of the weirdnesses of rfc3107
           the label length (actually the label + COS bits)
           is added of the prefix length;
           we also do only read out just one label -
           there is no real application for advertisment of
           stacked labels in a a single BGP message
        */

        plen-=24; /* adjust prefixlen - labellength */

	if (plen < 0 || 32 < plen)
		return -1;

	memset(&addr, 0, sizeof(addr));
	memcpy(&addr, &pd[4], (plen + 7) / 8);
	if (plen % 8) {
		((u_char *)&addr)[(plen + 7) / 8 - 1] &=
			((0xff00 >> (plen % 8)) & 0xff);
	}
        /* the label may get offsetted by 4 bits so lets shift it right */
	snprintf(buf, buflen, "%s/%d label:%u %s",
                 getname((u_char *)&addr),
                 plen,
                 EXTRACT_24BITS(pd+1)>>4,
                 ((pd[3]&1)==0) ? "(BOGUS: Bottom of Stack NOT set!)" : "(bottom)" );

	return 4 + (plen + 7) / 8;
}

#ifdef INET6
static int
decode_prefix6(const u_char *pd, char *buf, u_int buflen)
{
	struct in6_addr addr;
	u_int plen;

	plen = pd[0];
	if (plen < 0 || 128 < plen)
		return -1;

	memset(&addr, 0, sizeof(addr));
	memcpy(&addr, &pd[1], (plen + 7) / 8);
	if (plen % 8) {
		addr.s6_addr[(plen + 7) / 8 - 1] &=
			((0xff00 >> (plen % 8)) & 0xff);
	}
	snprintf(buf, buflen, "%s/%d", getname6((u_char *)&addr), plen);
	return 1 + (plen + 7) / 8;
}
#endif

static void
bgp_attr_print(const struct bgp_attr *attr, const u_char *dat, int len)
{
	int i;
	u_int16_t af;
	u_int8_t safi, snpa;
	int advance;
	int tlen;
	const u_char *p;
	char buf[MAXHOSTNAMELEN + 100];

	p = dat;
        tlen=len;

	switch (attr->bgpa_type) {
	case BGPTYPE_ORIGIN:
		if (len != 1)
			printf("invalid len");
		else
			printf("%s", tok2str(bgp_origin_values, "Unknown Origin Typecode", p[0]));
		break;
	case BGPTYPE_AS_PATH:
		if (len % 2) {
			printf("invalid len");
			break;
		}
                if (!len) {
			printf("empty");
			break;
                }
		while (p < dat + len) {
			/*
			 * under RFC1965, p[0] means:
			 * 1: AS_SET 2: AS_SEQUENCE
			 * 3: AS_CONFED_SET 4: AS_CONFED_SEQUENCE
			 */
			if (p[0] == 3 || p[0] == 4)
				printf("confed");
			printf("%s", (p[0] & 1) ? "{" : "");
			for (i = 0; i < p[1] * 2; i += 2) {
				printf("%s%u", i == 0 ? "" : " ",
					EXTRACT_16BITS(&p[2 + i]));
			}
			printf("%s", (p[0] & 1) ? "}" : "");
			p += 2 + p[1] * 2;
		}
		break;
	case BGPTYPE_NEXT_HOP:
		if (len != 4)
			printf("invalid len");
		else
			printf("%s", getname(p));
		break;
	case BGPTYPE_MULTI_EXIT_DISC:
	case BGPTYPE_LOCAL_PREF:
		if (len != 4)
			printf("invalid len");
		else
			printf("%u", EXTRACT_32BITS(p));
		break;
	case BGPTYPE_ATOMIC_AGGREGATE:
		if (len != 0)
			printf("invalid len");
		break;
	case BGPTYPE_AGGREGATOR:
		if (len != 6) {
			printf("invalid len");
			break;
		}
		printf(" AS #%u, origin %s", EXTRACT_16BITS(p),
			getname(p + 2));
		break;
	case BGPTYPE_COMMUNITIES:
		if (len % 4) {
			printf("invalid len");
			break;
		}
		while (tlen>0) {
			u_int32_t comm;
			comm = EXTRACT_32BITS(p);
			switch (comm) {
			case BGP_COMMUNITY_NO_EXPORT:
				printf(" NO_EXPORT");
				break;
			case BGP_COMMUNITY_NO_ADVERT:
				printf(" NO_ADVERTISE");
				break;
			case BGP_COMMUNITY_NO_EXPORT_SUBCONFED:
				printf(" NO_EXPORT_SUBCONFED");
				break;
			default:
				printf("%u:%u%s",
                                       (comm >> 16) & 0xffff,
                                       comm & 0xffff,
                                       (tlen>4) ? ", " : "");
				break;
			}
                        tlen -=4;
                        p +=4;
		}
		break;
        case BGPTYPE_ORIGINATOR_ID:
		if (len != 4) {
			printf("invalid len");
			break;
		}
                printf("%s",getname(p));
                break;
        case BGPTYPE_CLUSTER_LIST:
                while (tlen>0) {
                        printf("%s%s",
                               getname(p),
                                (tlen>4) ? ", " : "");
                        tlen -=4;
                        p +=4;
                }
                break;
	case BGPTYPE_MP_REACH_NLRI:
		af = EXTRACT_16BITS(p);
		safi = p[2];
	
                printf("\n\t    AFI: %s (%u), %sSAFI: %s (%u)",
                       tok2str(bgp_afi_values, "Unknown AFI", af),
                       af,
                       (safi>128) ? "vendor specific " : "", /* 128 is meanwhile wellknown */
                       tok2str(bgp_safi_values, "Unknown SAFI", safi),
                       safi);

		if (af == AFNUM_INET)
			;
#ifdef INET6
		else if (af == AFNUM_INET6)
			;
#endif
		else {
                    printf("\n\t    no AFI %u decoder",af);
                    print_unknown_data(p,"\n\t    ",tlen);
                    break;
                }

                p +=3;
		tlen = p[0];
		if (tlen) {
			printf("\n\t    nexthop: ");
			i = 0;
			while (i < tlen) {
				switch (af) {
				case AFNUM_INET:
                                    switch(safi) {
                                    case SAFNUM_UNICAST:
                                    case SAFNUM_MULTICAST:
                                    case SAFNUM_UNIMULTICAST:
                                    case SAFNUM_LABUNICAST:
					printf("%s", getname(p + 1 + i));
					i += sizeof(struct in_addr);
					break;
                                    default:
                                        printf("no SAFI %u decoder",safi);                                        
                                        print_unknown_data(p,"\n\t    ",tlen);
                                        i = tlen;
                                        break;
                                    }
                                    break;
#ifdef INET6
				case AFNUM_INET6:
                                    switch(safi) {
                                    case SAFNUM_UNICAST:
                                    case SAFNUM_MULTICAST:
                                    case SAFNUM_UNIMULTICAST:
                                    case SAFNUM_LABUNICAST:
                                        printf("%s", getname6(p + 1 + i));
                                        i += sizeof(struct in6_addr);
                                        break;
                                    default:
                                        printf("no SAFI %u decoder",safi);
                                        print_unknown_data(p,"\n\t    ",tlen);                                        
                                        i = tlen;
                                        break;
                                    }
#endif
				default:
                                    printf("no AFI %u decoder",af);
                                    print_unknown_data(p,"\n\t    ",tlen);
                                    i = tlen;	/*exit loop*/
                                    break;
				}
			}
		}
		p += 1 + tlen;

		snpa = p[0];
		p++;
		if (snpa) {
			printf("\n\t    %u SNPA", snpa);
			for (/*nothing*/; snpa > 0; snpa--) {
				printf("\n\t      %d bytes", p[0]);
				p += p[0] + 1;
			}
		} else {
                printf(", no SNPA");
                }

		while (len - (p - dat) > 0) {
			switch (af) {
			case AFNUM_INET:
                            switch (safi) {
                            case SAFNUM_UNICAST:
                            case SAFNUM_MULTICAST:
                            case SAFNUM_UNIMULTICAST:
                                advance = decode_prefix4(p, buf, sizeof(buf));
                                printf("\n\t      %s", buf);
                                break;
                            case SAFNUM_LABUNICAST:
                                advance = decode_labeled_prefix4(p, buf, sizeof(buf));
                                printf("\n\t      %s", buf);
                                break;
                            default:
                                printf("\n\t      no SAFI %u decoder",safi);
                                print_unknown_data(p-3,"\n\t    ",tlen);
                                advance = 0;
				p = dat + len;
				break;  
                            }
                            break;
#ifdef INET6
			case AFNUM_INET6:
                            switch (safi) {
                            case SAFNUM_UNICAST:
                            case SAFNUM_MULTICAST:
                            case SAFNUM_UNIMULTICAST:
				advance = decode_prefix6(p, buf, sizeof(buf));
				printf("\n\t      %s", buf);
				break;
                            default:
                                printf("\n\t      no SAFI %u decoder ",safi);
                                print_unknown_data(p-3,"\n\t    ",tlen);
                                advance = 0;
				p = dat + len;
				break;
                            }
                            break;
#endif
			default:
                            printf("\n\t      no AFI %u decoder ",af);
                            print_unknown_data(p-3,"\n\t    ",tlen);
                            advance = 0;
                            p = dat + len;
                            break;
			}

			p += advance;
		}

		break;

	case BGPTYPE_MP_UNREACH_NLRI:
		af = EXTRACT_16BITS(p);
		safi = p[2];

                printf("\n\t    AFI: %s (%u), %sSAFI: %s (%u)",
                       tok2str(bgp_afi_values, "Unknown AFI", af),
                       af,
                       (safi>128) ? "vendor specific " : "", /* 128 is meanwhile wellknown */
                       tok2str(bgp_safi_values, "Unknown SAFI", safi),
                       safi);

		p += 3;

		printf("\n\t    Withdrawn routes");
                
		while (len - (p - dat) > 0) {
			switch (af) {
			case AFNUM_INET:
                            switch (safi) {
                            case SAFNUM_UNICAST:
                            case SAFNUM_MULTICAST:
                            case SAFNUM_UNIMULTICAST:
                                advance = decode_prefix4(p, buf, sizeof(buf));
                                printf("\n\t      %s", buf);
                                break;
                            case SAFNUM_LABUNICAST:
                                advance = decode_labeled_prefix4(p, buf, sizeof(buf));
                                printf("\n\t      %s", buf);
                                break;
                            default:
                                printf("\n\t      no SAFI %u decoder",safi);
                                print_unknown_data(p-3,"\n\t    ",tlen);
                                advance = 0;
				p = dat + len;
				break;  
                            }
                            break;

#ifdef INET6
			case AFNUM_INET6:
                            switch (safi) {
                            case SAFNUM_UNICAST:
                            case SAFNUM_MULTICAST:
                            case SAFNUM_UNIMULTICAST:
				advance = decode_prefix6(p, buf, sizeof(buf));
				printf("\n\t      %s", buf);
				break;
                            default:
                                printf("\n\t      no SAFI %u decoder",safi);
                                print_unknown_data(p-3,"\n\t    ",tlen);
                                advance = 0;
				p = dat + len;
				break;
                            }
                            break;
#endif
			default:
				printf("\n\t      no AFI %u decoder",af);
                                print_unknown_data(p-3,"\n\t    ",tlen);
				advance = 0;
				p = dat + len;
				break;
			}

			p += advance;
		}
		break;
	default:
            printf("\n\t    no Attribute %u decoder",attr->bgpa_type); /* we have no decoder for the attribute */
            print_unknown_data(p,"\n\t    ",tlen);
		break;
	}
}

static void
bgp_open_print(const u_char *dat, int length)
{
	struct bgp_open bgpo;
	struct bgp_opt bgpopt;
	int hlen;
	const u_char *opt;
	int i,cap_type,cap_len;

	TCHECK2(dat[0], BGP_OPEN_SIZE);
	memcpy(&bgpo, dat, BGP_OPEN_SIZE);
	hlen = ntohs(bgpo.bgpo_len);

	printf("\n\t  Version %d, ", bgpo.bgpo_version);
	printf("my AS %u, ", ntohs(bgpo.bgpo_myas));
	printf("Holdtime %us, ", ntohs(bgpo.bgpo_holdtime));
	printf("ID %s", getname((u_char *)&bgpo.bgpo_id));
	printf("\n\t  Optional parameters, length %u", bgpo.bgpo_optlen);

	/* ugly! */
	opt = &((const struct bgp_open *)dat)->bgpo_optlen;
	opt++;

	i = 0;
	while (i < bgpo.bgpo_optlen) {
		TCHECK2(opt[i], BGP_OPT_SIZE);
		memcpy(&bgpopt, &opt[i], BGP_OPT_SIZE);
		if (i + 2 + bgpopt.bgpopt_len > bgpo.bgpo_optlen) {
                        printf("\n\t     Option %d, length %d", bgpopt.bgpopt_type, bgpopt.bgpopt_len);
			break;
		}

		printf("\n\t    Option %s (%u), length %d",
                       tok2str(bgp_opt_values,"Unknown", bgpopt.bgpopt_type),
                       bgpopt.bgpopt_type,
                       bgpopt.bgpopt_len);

                /* now lets decode the options we know*/
                switch(bgpopt.bgpopt_type) {
                case BGP_OPT_CAP:
                    cap_type=opt[i+BGP_OPT_SIZE];
                    cap_len=opt[i+BGP_OPT_SIZE+1];
                    printf("\n\t      %s, length %u",
                           tok2str(bgp_capcode_values,"Unknown", cap_type),
                           cap_len);
                    switch(cap_type) {
                    case BGP_CAPCODE_MP:
                        printf("\n\t\tAFI %s (%u), SAFI %s (%u)",
                               tok2str(bgp_afi_values,"Unknown", EXTRACT_16BITS(opt+i+BGP_OPT_SIZE+2)),
                               EXTRACT_16BITS(opt+i+BGP_OPT_SIZE+2),
                               tok2str(bgp_safi_values,"Unknown", opt[i+BGP_OPT_SIZE+5]),
                               opt[i+BGP_OPT_SIZE+5]);
                        break;
                    case BGP_CAPCODE_RR:
                    case BGP_CAPCODE_RR_CISCO:
                        break;
                    default:
                        printf("\n\t\tno decoder for Capability %u",
                               cap_type);
                        break;
                    }
                    break;
                case BGP_OPT_AUTH:
                default:
                       printf("\n\t      no decoder for option %u",
                           bgpopt.bgpopt_type);
                       break;
                }

		i += BGP_OPT_SIZE + bgpopt.bgpopt_len;
	}
	return;
trunc:
	printf("[|BGP]");
}

static void
bgp_update_print(const u_char *dat, int length)
{
	struct bgp bgp;
	struct bgp_attr bgpa;
	int hlen;
	const u_char *p;
	int len;
	int i;

	TCHECK2(dat[0], BGP_SIZE);
	memcpy(&bgp, dat, BGP_SIZE);
	hlen = ntohs(bgp.bgp_len);
	p = dat + BGP_SIZE;	/*XXX*/

	/* Unfeasible routes */
	len = EXTRACT_16BITS(p);
	if (len) {
		/*
		 * Without keeping state from the original NLRI message,
		 * it's not possible to tell if this a v4 or v6 route,
		 * so only try to decode it if we're not v6 enabled.
	         */
#ifdef INET6
		printf("\n\t  Withdrawn routes: %d bytes", len);
#else
		char buf[MAXHOSTNAMELEN + 100];

		TCHECK2(p[2], len);
		i = 2;

		printf("\n\t  Withdrawn routes:");

		while(i < 2 + len) {
			i += decode_prefix4(&p[i], buf, sizeof(buf));
			printf("\n\t    %s", buf);
		}
#endif
	}
	p += 2 + len;

	TCHECK2(p[0], 2);
	len = EXTRACT_16BITS(p);
	if (len) {
		/* do something more useful!*/
		i = 2;
		while (i < 2 + len) {
			int alen, aoff;

			TCHECK2(p[i], sizeof(bgpa));
			memcpy(&bgpa, &p[i], sizeof(bgpa));
			alen = bgp_attr_len(&bgpa);
			aoff = bgp_attr_off(&bgpa);

		       printf("\n\t  %s (%u), length: %u",
                              tok2str(bgp_attr_values, "Unknown Attribute", bgpa.bgpa_type),
                              bgpa.bgpa_type,
                              alen);

			if (bgpa.bgpa_flags) {
				printf(", flags [%s%s%s%s",
					bgpa.bgpa_flags & 0x80 ? "O" : "",
					bgpa.bgpa_flags & 0x40 ? "T" : "",
					bgpa.bgpa_flags & 0x20 ? "P" : "",
					bgpa.bgpa_flags & 0x10 ? "E" : "");
				if (bgpa.bgpa_flags & 0xf)
					printf("+%x", bgpa.bgpa_flags & 0xf);
				printf("]: ");
			}
			bgp_attr_print(&bgpa, &p[i + aoff], alen);
			i += aoff + alen;
		}
	}
	p += 2 + len;

	if (dat + length > p) {
            printf("\n\t  Updated routes:");
		while (dat + length > p) {
			char buf[MAXHOSTNAMELEN + 100];
			i = decode_prefix4(p, buf, sizeof(buf));
			printf("\n\t    %s", buf);
			if (i < 0)
				break;
			p += i;
		}
	}
	return;
trunc:
	printf("[|BGP]");
}

static void
bgp_notification_print(const u_char *dat, int length)
{
	struct bgp_notification bgpn;
	int hlen;

	TCHECK2(dat[0], BGP_NOTIFICATION_SIZE);
	memcpy(&bgpn, dat, BGP_NOTIFICATION_SIZE);
	hlen = ntohs(bgpn.bgpn_len);

	printf(", Error - %s", tok2str(bgp_notify_major_values, "Unknown", bgpn.bgpn_major));

        switch (bgpn.bgpn_major) {

        case BGP_NOTIFY_MAJOR_MSG:
            printf(" subcode %s", tok2str(bgp_notify_minor_msg_values, "Unknown", bgpn.bgpn_minor));
            break;
        case BGP_NOTIFY_MAJOR_OPEN:
            printf(" subcode %s", tok2str(bgp_notify_minor_open_values, "Unknown", bgpn.bgpn_minor));
            break;
        case BGP_NOTIFY_MAJOR_UPDATE:
            printf(" subcode %s", tok2str(bgp_notify_minor_update_values, "Unknown", bgpn.bgpn_minor));
            break;
        default:
            break;
        }

	return;
trunc:
	printf("[|BGP]");
}

static void
bgp_header_print(const u_char *dat, int length)
{
	struct bgp bgp;

	TCHECK2(dat[0], BGP_SIZE);
	memcpy(&bgp, dat, BGP_SIZE);
	printf("\n\t%s Message (%u), length: %u ",
               tok2str(bgp_msg_values, "Unknown", bgp.bgp_type),
               bgp.bgp_type,
               length);

	switch (bgp.bgp_type) {
	case BGP_OPEN:
		bgp_open_print(dat, length);
		break;
	case BGP_UPDATE:
		bgp_update_print(dat, length);
		break;
	case BGP_NOTIFICATION:
		bgp_notification_print(dat, length);
		break;
        case BGP_KEEPALIVE:
                break;
        default:
            /* we have no decoder for the BGP message */
            printf("\n\t  no Message %u decoder",bgp.bgp_type);
            print_unknown_data(dat,"\n\t  ",length);
                break;
	}
	return;
trunc:
	printf("[|BGP]");
}

void
bgp_print(const u_char *dat, int length)
{
	const u_char *p;
	const u_char *ep;
	const u_char *start;
	const u_char marker[] = {
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	};
	struct bgp bgp;
	u_int16_t hlen;

	ep = dat + length;
	if (snapend < dat + length)
		ep = snapend;

	printf(": BGP");

	p = dat;
	start = p;
	while (p < snapend) {
		if (!TTEST2(p[0], 1))
			break;
		if (p[0] != 0xff) {
			p++;
			continue;
		}

		if (!TTEST2(p[0], sizeof(marker)))
			break;
		if (memcmp(p, marker, sizeof(marker)) != 0) {
			p++;
			continue;
		}

		/* found BGP header */
		TCHECK2(p[0], BGP_SIZE);	/*XXX*/
		memcpy(&bgp, p, BGP_SIZE);

		if (start != p)
			printf(" [|BGP]");

		hlen = ntohs(bgp.bgp_len);

		if (TTEST2(p[0], hlen)) {
			bgp_header_print(p, hlen);
			p += hlen;
			start = p;
		} else {
			printf("[|BGP %s]", tok2str(bgp_msg_values, "Unknown Message Type",bgp.bgp_type));
			break;
		}
	}

	return;

trunc:
	printf(" [|BGP]");
}











