/*
 * NETBIOS protocol formats
 *
 * @(#) $Header: /tcpdump/master/tcpdump/netbios.h,v 1.2 2002-11-09 17:19:22 itojun Exp $
 */

struct p8022Hdr {
    u_char	dsap;
    u_char	ssap;
    u_char	flags;
} __attribute__((packed));

#define	p8022Size	3		/* min 802.2 header size */

#define UI		0x03		/* 802.2 flags */

