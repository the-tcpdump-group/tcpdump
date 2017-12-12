/* CyberReboot edition:
 *
 * In new creating sanitization methods for tcpdump, it became necessary
 * to make modifications to pcap_dump() supplied by pcap/sf-pcap -- and in
 * so doing, required an awareness of internal structs located in the
 * pcap-int.h (a component of libpcap). To simplify things, required data
 * structs have been extrapolated and given new names to avoid conflict,
 * and while these are completely extricated from libpcap's internal
 * structure, data types and sizes should be identical (as they've been
 * shamelessly cut-and-pasted from pcap-int.h).
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>

#include <netdissect-stdinc.h>

#include <inttypes.h>
#include "netdissect.h"
#include <pcap/pcap.h>
#include "clean_cap_dump.h"
#include "extract.h"
#include "ethertype.h"
#include "ip.h"
#include "tcp.h"
#include "udp.h"

// includes max packet size of IP packet, plus eth header
#define MAXPACKET	65549
#define ETHER_HDRLEN	14

/*
 * Structure of an Ethernet header.
 */
struct  ether_header {
        nd_mac_addr     ether_dhost;
        nd_mac_addr     ether_shost;
        nd_uint16_t     ether_length_type;
};

/* Assumes ether type; returns pointer to IP header or NULL if not found. */
u_char *
get_iph_ptr(const struct pcap_pkthdr *h, u_char *bp) {
	u_short length_type;
	u_char *s;
	const struct ip *ip;
	const struct ether_header *ep = (const struct ether_header *)bp;

	if (h == NULL || bp == NULL) {
		return NULL;
	}

	if (h->caplen < ETHER_HDRLEN || h->len < ETHER_HDRLEN) {
		return NULL;
	}
	length_type = EXTRACT_BE_U_2(&ep->ether_length_type);
	if (length_type == ETHERTYPE_IP) {
		s = bp + ETHER_HDRLEN;
	ip = (const struct ip *)s;
	if (IP_V(ip) == 4)
		return s;
	}
	return NULL;
}

/* Converts network address string to uint */
static uint32_t
nd_ipv4_to_network_uint(nd_ipv4 a) {
	char ip[INET_ADDRSTRLEN];
	uint32_t ip_uint = 0;

	snprintf(ip, INET_ADDRSTRLEN, "%d.%d.%d.%d",
		 a.bytes[0], a.bytes[1], a.bytes[2], a.bytes[3]);
	inet_pton(AF_INET, ip, &ip_uint);

	return ip_uint;
}

/* Converts network uint to address string */
static nd_ipv4
network_uint_to_nd_ipv4(uint32_t a) {
	nd_ipv4 addr;

	addr.bytes[3] = (a>>24) & 0xff;
	addr.bytes[2] = (a>>16) & 0xff;
	addr.bytes[1] = (a>>8) & 0xff;
	addr.bytes[0] = a & 0xff;

	return addr;
}

/* Returns 1 if IP address presented in nd_ipv4 falls within reserved IP range;
 * else returns 0. */
static int
is_reserved(nd_ipv4 a) {
	/* List of all the reserved IPv4 address spaces, per RFC5735,
	 * ...PROVIDED IN NETWORK BYTE ORDER!! */
	struct netblock specialblock[] = {
		{ .netip = 0x00000000, .netmask = 0x000000ff  }, /* 0.0.0.0/8 */
		{ .netip = 0x0000000a, .netmask = 0x000000ff  }, /* 10.0.0.0/8 */
		{ .netip = 0x0000007f, .netmask = 0x000000ff  }, /* 127.0.0.0/8 */
		{ .netip = 0x0000fea9, .netmask = 0x0000ffff  }, /* 169.254.0.0/16 */
		{ .netip = 0x000010ac, .netmask = 0x00000fff  }, /* 172.16.0.0/12 */
		{ .netip = 0x000000c0, .netmask = 0x00ffffff  }, /* 192.0.0.0/24 */
		{ .netip = 0x000200c0, .netmask = 0x00ffffff  }, /* 192.0.2.0/24 */
		{ .netip = 0x006433c0, .netmask = 0x00ffffff  }, /* 192.88.99.0/24 */
		{ .netip = 0x0000a8c0, .netmask = 0x0000ffff  }, /* 192.168.0.0/16 */
		{ .netip = 0x000012c0, .netmask = 0x0000fffe  }, /* 192.18.0.0/15 */
		{ .netip = 0x006433c0, .netmask = 0x00ffffff  }, /* 198.51.100.0/24 */
		{ .netip = 0x007100cb, .netmask = 0x00ffffff  }, /* 203.0.113.0/24 */
		{ .netip = 0x000000e0, .netmask = 0x000000f0  }, /* 224.0.0.0/4 */
		{ .netip = 0x000000f0, .netmask = 0x000000f0  }, /* 240.0.0.0/4 */
		{ .netip = 0xffffffff, .netmask = 0xffffffff  }  /* 255.255.255.255 */
	};
	int sb_sz = sizeof(specialblock)/sizeof(specialblock[0]);
	int reserved = 0;
	int i = 0;
	uint32_t addr = nd_ipv4_to_network_uint(a);

	for (i = 0; i < sb_sz; i++) {
		if ((addr & specialblock[i].netmask) == 
		    (specialblock[i].netip & specialblock[i].netmask)) {
			reserved = 1;
			break;
		}
	}

	return reserved;
}

/* Takes as input the IP header struct pointer and length of packet, and
 * returns -1 if the IP header is parseable; else returns 0. */
static int
validate_iph_len(u_char *iph, unsigned int len) {
	struct ip *ip = (struct ip *)iph;
	if (IP_V(ip) != 4) {
		printf("DEBUG: Not IP4 packet -- version %u\n", IP_V(ip));
		return -1;
	}

	if (len < sizeof(struct ip)) {
		printf("DEBUG: truncated IP or bad datagram length\n");
		return -1;
	}

	if ((IP_HL(ip)*4) < sizeof(struct ip)) {
		printf("DEBUG: bad header length\n");
		return -1;
	}
	return 0;
}

/* Compare the addresses to reserved address ranges and mask if it's not within
 * range. Returns 0 if successful, -1 on malformed datagram, 1 if not reserveds.
 */
int
mask_ip(u_char *iph, unsigned int len, const char * maskIP) {
	struct ip *ip = (struct ip *)iph;
	uint32_t m = 0;
	inet_pton(AF_INET, maskIP, &m);

	if (validate_iph_len(iph, len) < 0)
		return -1;

	if (is_reserved(ip->ip_src) == 0) {
		nd_ipv4 mask = network_uint_to_nd_ipv4(m);
		memcpy(&(ip->ip_src), &mask, sizeof(mask));
	}
	if (is_reserved(ip->ip_dst) == 0) {
		nd_ipv4 mask = network_uint_to_nd_ipv4(m);
		memcpy(&(ip->ip_dst), &mask, sizeof(mask));
	}

	return 0;
}

void
pcap_mod_and_dump(u_char *user, const struct pcap_pkthdr *h, const u_char *sp,
	      int dlt, int no_payload_flag, int mask_ip_flag, const char *maskIP) {
	register FILE *f;
	struct clean_cap_sf_pkthdr sf_hdr;
	u_char *ip, *p_end;
	u_char *modp;
	unsigned int p_len, modp_len;
	p_len = modp_len = h->caplen;

	if ((modp = (u_char *)malloc(MAXPACKET)) == NULL) {
		fprintf(stderr,
			"Unable to malloc %d bytes for packet modification", MAXPACKET);
		exit(1);
	} else
		memset(modp, '\0', MAXPACKET);

	memcpy(modp, sp, h->caplen);

	f = (FILE *)user;
	sf_hdr.ts.tv_sec    = h->ts.tv_sec;
	sf_hdr.ts.tv_usec   = h->ts.tv_usec;
	sf_hdr.caplen       = h->caplen;
	sf_hdr.len          = h->len;

	switch(dlt) {
	case DLT_EN10MB:
		if ((ip = get_iph_ptr(h, modp)) == NULL)
			break;
		p_len -= ETHER_HDRLEN;

		if (mask_ip_flag && maskIP != NULL) {
			mask_ip(ip, p_len, maskIP);
		}

		if (no_payload_flag > 0 && validate_iph_len(ip, p_len) > -1) {
			struct ip *p = (struct ip *)ip;
			int ph_len = IP_HL(p) * 4;
			if (*p->ip_p != IPPROTO_TCP && *p->ip_p != IPPROTO_UDP) {
				break;
			}

			p_end = ip + h->caplen; // here to stifle warning about being uninitialized

			if (*p->ip_p == IPPROTO_TCP) {
				struct tcphdr *t = (struct tcphdr *)(ip+ph_len);
				p_len = TH_OFF(t) * 4;
				if (p_len < sizeof(*t)) {
					break;
				}
				p_end = ip + ph_len + p_len;

			} else if (*p->ip_p == IPPROTO_UDP) {
				struct udphdr *u = (struct udphdr *)(ip+ph_len);
				if (p_len < sizeof(struct udphdr) ||
				    EXTRACT_BE_U_2(&u->uh_ulen) < sizeof(struct udphdr)) {
					break;
				} else {
					p_end = (u_char *)(ip + ph_len + sizeof(struct udphdr));
				}
			}

			if (no_payload_flag > 1) {
			    sf_hdr.caplen = modp_len = p_end - modp;
			} else {
				size_t diff = p_end - modp;
				memset(p_end, 0, h->len - diff);
			}
		}
		break;

	/* default:
	 *	printf("DEBUG: not Ethernet LL.\n");
	 */
	}

	(void)fwrite(&sf_hdr, sizeof(sf_hdr), 1, f);
	(void)fwrite(modp, modp_len, 1, f);

	free(modp);
}
