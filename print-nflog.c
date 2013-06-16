#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <tcpdump-stdinc.h>

#include <stdio.h>
#include <pcap.h>

#include "netdissect.h"
#include "interface.h"

#ifdef DLT_NFLOG

static void
nflog_print(struct netdissect_options *ndo, const u_char *p, u_int length, u_int caplen _U_)
{
	ip_print(ndo, p, length);
	return;
}

u_int
nflog_if_print(struct netdissect_options *ndo,
	       const struct pcap_pkthdr *h, const u_char *p)
{
	if (h->len < 104 || h->caplen < 104) {
		ND_PRINT((ndo, "[!nflog]"));
		return h->caplen;
	}

	nflog_print(ndo, p + 104, h->len - 104, h->caplen - 104);

	return 104;
}

#endif /* DLT_NFLOG */
