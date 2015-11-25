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

#include <netdissect-stdinc.h>

#include "netdissect.h"

#if defined(DLT_NFLOG) && defined(HAVE_PCAP_NFLOG_H)
#include <pcap/nflog.h>

static const struct tok nflog_values[] = {
	{ AF_INET,		"IPv4" },
#ifdef AF_INET6
	{ AF_INET6,		"IPv6" },
#endif /*AF_INET6*/
	{ 0,			NULL }
};

static inline void
nflog_hdr_print(netdissect_options *ndo, const nflog_hdr_t *hdr, u_int length)
{
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

static char *hook_names[] = { "PRE","IN","FWD","OUT","POST" };

static const char *hook2txt(int hook) {
  if(hook >= sizeof(hook_names)/sizeof(hook_names[0])) return "UNK";
  return hook_names[hook];
}

u_int
nflog_if_print(netdissect_options *ndo,
			   const struct pcap_pkthdr *h, const u_char *p)
{
	const nflog_hdr_t *hdr = (const nflog_hdr_t *)p;
	const nflog_tlv_t *tlv;
	uint16_t size;
	uint16_t hw_hdrlen = 0;
	uint16_t hw_addrlen = 0;
	uint16_t h_size = sizeof(nflog_hdr_t);
	u_int caplen = h->caplen;
	u_int length = h->len;

	if (caplen < (int) sizeof(nflog_hdr_t) || length < (int) sizeof(nflog_hdr_t)) {
		ND_PRINT((ndo, "[|nflog]"));
		return h_size;
	}

	if (!(hdr->nflog_version) == 0) {
		ND_PRINT((ndo, "version %u (unknown)", hdr->nflog_version));
		return h_size;
	}

	if (ndo->ndo_eflag)
		nflog_hdr_print(ndo, hdr, length);

	p += sizeof(nflog_hdr_t);
	length -= sizeof(nflog_hdr_t);
	caplen -= sizeof(nflog_hdr_t);

	while (length > 0) {
		/* We have some data.  Do we have enough for the TLV header? */
		if (caplen < sizeof(nflog_tlv_t) || length < sizeof(nflog_tlv_t)) {
			/* No. */
			ND_PRINT((ndo, "[|nflog]"));
			return h_size;
		}

		tlv = (const nflog_tlv_t *) p;
		size = tlv->tlv_length;
		if (size % 4 != 0)
			size += 4 - size % 4;

		/* Is the TLV's length less than the minimum? */
		if (size < sizeof(nflog_tlv_t)) {
			/* Yes. Give up now. */
			ND_PRINT((ndo, "[|nflog]"));
			return h_size;
		}

		/* Do we have enough data for the full TLV? */
		if (caplen < size || length < size) {
			/* No. */
			ND_PRINT((ndo, "[|nflog]"));
			return h_size;
		}

		if (tlv->tlv_type == NFULA_PAYLOAD) {
			/*
			 * This TLV's data is the packet payload.
			 * Skip past the TLV header, and break out
			 * of the loop so we print the packet data.
			 */
			p += sizeof(nflog_tlv_t);
			h_size += sizeof(nflog_tlv_t);
			length -= sizeof(nflog_tlv_t);
			caplen -= sizeof(nflog_tlv_t);
			break;
		}
		{
		  const u_char *adata = p+sizeof(nflog_tlv_t);
		  switch(tlv->tlv_type) {
			case NFULA_TIMESTAMP:
			case NFULA_HWTYPE:
				break;
			case NFULA_PACKET_HDR:
				if(ndo->ndo_vflag)
				    ND_PRINT((ndo, "HOOK:%s ",
					hook2txt(((nflog_packet_hdr_t *)adata)->hook)));
				break;
			case NFULA_MARK:
				ND_PRINT((ndo, "MARK:0x%x ",
					htonl(*(u_int32_t *)adata)));
				break;
			case NFULA_UID:
				if(ndo->ndo_vflag)
				    ND_PRINT((ndo, "UID:%u ",
					htonl(*(u_int32_t *)adata)));
				break;
			case NFULA_GID:
				if(ndo->ndo_vflag)
				    ND_PRINT((ndo, "GID:%u ",
					htonl(*(u_int32_t *)adata)));
				break;
			case NFULA_PREFIX:
				if(p[sizeof(nflog_tlv_t)])
				    ND_PRINT((ndo, "Prefix:%.*s ",
					size-sizeof(nflog_tlv_t), adata));
				break;
			case NFULA_IFINDEX_INDEV:
				if(ndo->ndo_vflag > 1)
				    ND_PRINT((ndo, "iif:%u ",
					htonl(*(u_int32_t *)adata)));
				break;
			case NFULA_IFINDEX_OUTDEV:
				if(ndo->ndo_vflag > 1)
				    ND_PRINT((ndo, "oif:%u ",
					htonl(*(u_int32_t *)adata)));
				break;
			case NFULA_IFINDEX_PHYSINDEV:
				if(ndo->ndo_vflag > 1)
				    ND_PRINT((ndo, "phyiif:%u ",
					htonl(*(u_int32_t *)adata)));
				break;
			case NFULA_IFINDEX_PHYSOUTDEV:
				if(ndo->ndo_vflag > 1)
				    ND_PRINT((ndo, "phyoif:%u ",
					htonl(*(u_int32_t *)adata)));
				break;
			case NFULA_HWADDR:
				hw_addrlen = htons(((nflog_hwaddr_t *)adata)->hw_addrlen);
				break;
			case NFULA_HWLEN:
				hw_hdrlen = htons((*(u_int16_t *)adata));
				break;
			case NFULA_HWHEADER:
				if (!hw_hdrlen || ndo->ndo_vflag < 2) break;
				{
				  char attr_buf[128];
				  int n,l;
				  memset(attr_buf,0,sizeof(attr_buf));
				  for(n=0,l=0; n < hw_hdrlen && l < sizeof(attr_buf)-3; n++) {
					if(hw_addrlen && 
					   (n == hw_addrlen || n == hw_addrlen*2))
						attr_buf[l++] = ':';
					l += snprintf(&attr_buf[l],3,"%02x",adata[n]);
				  }
				  ND_PRINT((ndo, "HWHDR=%s ",attr_buf));
				}
				break;
			default:
				if (ndo->ndo_vflag < 3) break;
				ND_PRINT((ndo, "ATTR%d/%d ",tlv->tlv_type,size));
		  }
		}

		p += size;
		h_size += size;
		length -= size;
		caplen -= size;
	}

	switch (hdr->nflog_family) {

	case AF_INET:
		ip_print(ndo, p, length);
		break;

#ifdef AF_INET6
	case AF_INET6:
		ip6_print(ndo, p, length);
		break;
#endif /* AF_INET6 */

	default:
		if (!ndo->ndo_eflag)
			nflog_hdr_print(ndo, hdr,
				length + sizeof(nflog_hdr_t));

		if (!ndo->ndo_suppress_default_print)
			ND_DEFAULTPRINT(p, caplen);
		break;
	}

	return h_size;
}

#endif /* defined(DLT_NFLOG) && defined(HAVE_PCAP_NFLOG_H) */
