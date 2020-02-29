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

/* \summary: DLT_NFLOG printer */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "netdissect-stdinc.h"

#include "netdissect.h"
#include "extract.h"

#ifdef DLT_NFLOG

/*
 * Structure of an NFLOG header and TLV parts, as described at
 * https://www.tcpdump.org/linktypes/LINKTYPE_NFLOG.html
 *
 * The NFLOG header is big-endian.
 *
 * The TLV length and type are in host byte order.  The value is either
 * big-endian or is an array of bytes in some externally-specified byte
 * order (text string, link-layer address, link-layer header, packet
 * data, etc.).
 */
typedef struct nflog_hdr {
	nd_uint8_t	nflog_family;		/* address family */
	nd_uint8_t	nflog_version;		/* version */
	nd_uint16_t	nflog_rid;		/* resource ID */
} nflog_hdr_t;

typedef struct nflog_tlv {
	nd_uint16_t	tlv_length;		/* tlv length */
	nd_uint16_t	tlv_type;		/* tlv type */
	/* value follows this */
} nflog_tlv_t;

typedef struct nflog_packet_hdr {
	nd_uint16_t	hw_protocol;	/* hw protocol */
	nd_uint8_t	hook;		/* netfilter hook */
	nd_byte		pad[1];		/* padding to 32 bits */
} nflog_packet_hdr_t;

typedef struct nflog_hwaddr {
	nd_uint16_t	hw_addrlen;	/* address length */
	nd_byte		pad[2];		/* padding to 32-bit boundary */
	nd_byte		hw_addr[8];	/* address, up to 8 bytes */
} nflog_hwaddr_t;

typedef struct nflog_timestamp {
	nd_uint64_t	sec;
	nd_uint64_t	usec;
} nflog_timestamp_t;

/*
 * TLV types.
 */
#define NFULA_PACKET_HDR		1	/* nflog_packet_hdr_t */
#define NFULA_MARK			2	/* packet mark from skbuff */
#define NFULA_TIMESTAMP			3	/* nflog_timestamp_t for skbuff's time stamp */
#define NFULA_IFINDEX_INDEV		4	/* ifindex of device on which packet received (possibly bridge group) */
#define NFULA_IFINDEX_OUTDEV		5	/* ifindex of device on which packet transmitted (possibly bridge group) */
#define NFULA_IFINDEX_PHYSINDEV		6	/* ifindex of physical device on which packet received (not bridge group) */
#define NFULA_IFINDEX_PHYSOUTDEV	7	/* ifindex of physical device on which packet transmitted (not bridge group) */
#define NFULA_HWADDR			8	/* nflog_hwaddr_t for hardware address */
#define NFULA_PAYLOAD			9	/* packet payload */
#define NFULA_PREFIX			10	/* text string - null-terminated, count includes NUL */
#define NFULA_UID			11	/* UID owning socket on which packet was sent/received */
#define NFULA_SEQ			12	/* sequence number of packets on this NFLOG socket */
#define NFULA_SEQ_GLOBAL		13	/* sequence number of pakets on all NFLOG sockets */
#define NFULA_GID			14	/* GID owning socket on which packet was sent/received */
#define NFULA_HWTYPE			15	/* ARPHRD_ type of skbuff's device */
#define NFULA_HWHEADER			16	/* skbuff's MAC-layer header */
#define NFULA_HWLEN			17	/* length of skbuff's MAC-layer header */

static const struct tok nflog_values[] = {
	{ AF_INET,		"IPv4" },
#ifdef AF_INET6
	{ AF_INET6,		"IPv6" },
#endif /*AF_INET6*/
	{ 0,			NULL }
};

static void
nflog_hdr_print(netdissect_options *ndo, const nflog_hdr_t *hdr, u_int length)
{
	ND_PRINT("version %u, resource ID %u",
	    GET_U_1(hdr->nflog_version), GET_BE_U_2(hdr->nflog_rid));

	if (!ndo->ndo_qflag) {
		ND_PRINT(", family %s (%u)",
			 tok2str(nflog_values, "Unknown",
				 GET_U_1(hdr->nflog_family)),
			 GET_U_1(hdr->nflog_family));
		} else {
		ND_PRINT(", %s",
			 tok2str(nflog_values,
				 "Unknown NFLOG (0x%02x)",
			 GET_U_1(hdr->nflog_family)));
		}

	ND_PRINT(", length %u: ", length);
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
	uint16_t size;
	uint16_t hw_hdrlen = 0;
	uint16_t hw_addrlen = 0;
	uint16_t h_size = sizeof(nflog_hdr_t);
	u_int caplen = h->caplen;
	u_int length = h->len;

	ndo->ndo_protocol = "nflog_if";
	if (caplen < sizeof(nflog_hdr_t))
		goto trunc;

	ND_TCHECK_SIZE(hdr);
	if (GET_U_1(hdr->nflog_version) != 0) {
		ND_PRINT("version %u (unknown)", GET_U_1(hdr->nflog_version));
		return h_size;
	}

	if (ndo->ndo_eflag)
		nflog_hdr_print(ndo, hdr, length);

	p += sizeof(nflog_hdr_t);
	length -= sizeof(nflog_hdr_t);
	caplen -= sizeof(nflog_hdr_t);

	while (length > 0) {
		const nflog_tlv_t *tlv;

		/* We have some data.  Do we have enough for the TLV header? */
		if (caplen < sizeof(nflog_tlv_t))
			goto trunc;	/* No. */

		tlv = (const nflog_tlv_t *) p;
		ND_TCHECK_SIZE(tlv);
		size = GET_HE_U_2(tlv->tlv_length);
		if (size % 4 != 0)
			size += 4 - size % 4;

		/* Is the TLV's length less than the minimum? */
		if (size < sizeof(nflog_tlv_t))
			goto trunc;	/* Yes. Give up now. */

		/* Do we have enough data for the full TLV? */
		if (caplen < size)
			goto trunc;	/* No. */

		if (GET_HE_U_2(tlv->tlv_type) == NFULA_PAYLOAD) {
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

	switch (GET_U_1(hdr->nflog_family)) {

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
trunc:
	nd_print_trunc(ndo);
	return h_size;
}

#endif /* DLT_NFLOG */
