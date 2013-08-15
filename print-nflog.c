/*
 * Copyright (c) 2013, Petar Alilovic,
 * Faculty of Electrical Engineering and Computing, University of Zagreb
 * All rights reserved
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice,
 *	 this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright
 *	 notice, this list of conditions and the following disclaimer in the
 *	 documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <tcpdump-stdinc.h>

#include <stdio.h>
#include <pcap.h>

#include "netdissect.h"
#include "interface.h"

#ifdef HAVE_LINUX_NETFILTER_NFNETLINK_LOG_H
#include <linux/netfilter/nfnetlink_log.h>
#include "nflog.h"

#ifdef DLT_NFLOG

const struct tok nflog_values[] = {
	{ AF_INET,		"IPv4" },
	{ AF_INET6,		"IPv6" },
	{ 0,				NULL }
};

static inline void
nflog_hdr_print(struct netdissect_options *ndo, const u_char *bp, u_int length)
{
	const nflog_hdr_t *hdr;
	hdr = (const nflog_hdr_t *)bp;

	ND_PRINT((ndo, "version %d, resource ID %d", hdr->nflog_version, ntohs(hdr->nflog_rid)));

	if (!ndo->ndo_qflag) {
		ND_PRINT((ndo,", family %s (%d)",
						  tok2str(nflog_values, "Unknown",
								  hdr->nflog_family),
						  hdr->nflog_family));
		} else {
		ND_PRINT((ndo,", %s",
						  tok2str(nflog_values,
								  "Unknown NFLOG (0x%02x)",
								  hdr->nflog_family)));
		}

	ND_PRINT((ndo, ", length %u: ", length));
}

static void
nflog_print(struct netdissect_options *ndo, const u_char *p, u_int length, u_int caplen)
{
	const nflog_hdr_t *hdr;
	const nflog_tlv_t *tlv;
	u_int16_t size;

	if (caplen < (int) sizeof(nflog_hdr_t)) {
		ND_PRINT((ndo, "[|nflog]"));
		return;
	}

	if (ndo->ndo_eflag)
		nflog_hdr_print(ndo, p, length);

	length -= sizeof(nflog_hdr_t);
	caplen -= sizeof(nflog_hdr_t);
	hdr = (const nflog_hdr_t *)p;
	p += sizeof(nflog_hdr_t);

	do {
		tlv = (const nflog_tlv_t *) p;
		size = tlv->tlv_length;

		/* wrong size of the packet */
		if (size > length )
			return;

		/* wrong tlv type */
		if (tlv->tlv_type > NFULA_MAX)
			return;

		if (size % 4 != 0)
			size += 4 - size % 4;

		p += size;
		length = length - size;
		caplen = caplen - size;

	} while (tlv->tlv_type != NFULA_PAYLOAD);

	/* dont skip payload just tlv length and type */
	p = p - size + 4;
	length += size - 4;
	caplen += size - 4;

	switch (hdr->nflog_family) {

	case AF_INET:
			ip_print(ndo, p, length);
		break;

#ifdef INET6
	case AF_INET6:
		ip6_print(ndo, p, length);
		break;
#endif /*INET6*/

	default:
		if (!ndo->ndo_eflag)
			nflog_hdr_print(ndo, (u_char *)hdr,
				length + sizeof(nflog_hdr_t));

		if (!ndo->ndo_suppress_default_print)
			ndo->ndo_default_print(ndo, p, caplen);
		break;
	}
}

u_int
nflog_if_print(struct netdissect_options *ndo,
			   const struct pcap_pkthdr *h, const u_char *p)
{

	nflog_print(ndo, p, h->len, h->caplen);
	return (sizeof(nflog_hdr_t));
}

#endif /* HAVE_LINUX_NETFILTER_NFNETLINK_LOG_H */
#endif /* DLT_NFLOG */
