#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <tcpdump-stdinc.h>

#include <stdio.h>
#include <pcap.h>

#include "netdissect.h"
#include "addrtoname.h"
#include "ipnet.h"

#ifdef DLT_IPNET

int ipnet_encap_print(netdissect_options *,u_short, const u_char *, u_int, u_int);

const struct tok ipnet_values[] = {
	{ IPH_AF_INET,		"IPv4" },
	{ IPH_AF_INET6,		"IPv6" },
	{ 0,			NULL }
};

static inline void
ipnet_hdr_print(struct netdissect_options *ndo, const u_char *bp, u_int length)
{
	const ipnet_hdr_t *hdr;
	hdr = (const ipnet_hdr_t *)bp;

	ND_PRINT((ndo, "%d > %d", hdr->iph_zsrc, hdr->iph_zdst));

	if (!ndo->ndo_qflag) {
		ND_PRINT((ndo,", family %s (%d)",
                          tok2str(ipnet_values, "Unknown",
                                  hdr->iph_family),
                          hdr->iph_family));
        } else {
		ND_PRINT((ndo,", %s",
                          tok2str(ipnet_values,
                                  "Unknown Ethertype (0x%04x)",
                                  hdr->iph_family)));
        }

	ND_PRINT((ndo, ", length %u: ", length));
}

void
ipnet_print(struct netdissect_options *ndo, const u_char *p, u_int length, u_int caplen)
{
	ipnet_hdr_t *hdr;

	if (caplen < sizeof(ipnet_hdr_t)) {
		ND_PRINT((ndo, "[|ipnet]"));
		return;
	}

	if (ndo->ndo_eflag)
		ipnet_hdr_print(ndo, p, length);

	length -= sizeof(ipnet_hdr_t);
	caplen -= sizeof(ipnet_hdr_t);
	hdr = (ipnet_hdr_t *)p;
	p += sizeof(ipnet_hdr_t);

	if (ipnet_encap_print(ndo, hdr->iph_family, p, length, caplen) == 0) {
		if (!ndo->ndo_eflag)
			ipnet_hdr_print(ndo, (u_char *)hdr,
					length + sizeof(ipnet_hdr_t));

		if (!ndo->ndo_suppress_default_print)
			ndo->ndo_default_print(ndo, p, caplen);
	} 
}

/*
 * This is the top level routine of the printer.  'p' points
 * to the ether header of the packet, 'h->ts' is the timestamp,
 * 'h->len' is the length of the packet off the wire, and 'h->caplen'
 * is the number of bytes actually captured.
 */
u_int
ipnet_if_print(struct netdissect_options *ndo, const struct pcap_pkthdr *h, const u_char *p)
{
	ipnet_print(ndo, p, h->len, h->caplen);

	return (sizeof(ipnet_hdr_t));
}

/*
 * Prints the packet encapsulated in an Ethernet data segment
 * (or an equivalent encapsulation), given the Ethernet type code.
 *
 * Returns non-zero if it can do so, zero if the ethertype is unknown.
 *
 * The Ethernet type code is passed through a pointer; if it was
 * ETHERTYPE_8021Q, it gets updated to be the Ethernet type of
 * the 802.1Q payload, for the benefit of lower layers that might
 * want to know what it is.
 */

int
ipnet_encap_print(struct netdissect_options *ndo, u_short family, const u_char *p,
    u_int length, u_int caplen)
{
 recurse:

	switch (family) {

	case IPH_AF_INET:
	        ip_print(ndo, p, length);
		return (1);

#ifdef INET6
	case IPH_AF_INET6:
		ip6_print(p, length);
		return (1);
#endif /*INET6*/

	default:
		return(0);
	}
}


/*
 * Local Variables:
 * c-style: whitesmith
 * c-basic-offset: 8
 * End:
 */

#endif /* DLT_IPNET */
