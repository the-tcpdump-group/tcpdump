/*
 * Copyright 2026 Google LLC
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *   3. Neither the name of the copyright holder nor the names of its
 *      contributors may be used to endorse or promote products derived
 *      from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/* \summary: PSP (PSP Security Protocol) printer */
/* specification: https://github.com/google/psp */

#include <config.h>

#include "netdissect-stdinc.h"

#define ND_LONGJMP_FROM_TCHECK
#include "netdissect.h"
#include "addrtoname.h"
#include "extract.h"
#include "ip.h"
#include "ip6.h"
#include "ipproto.h"
#include "psp.h"
#include "tcp.h"
#include "udp.h"

/* Length of the source and destination ports of a TCP or UDP header */
#define PSP_L4_PORTS_LEN	4

/* Returns 1 if the packet satisfies PSP protocol invariants, 0 otherwise */
int
psp_detect(netdissect_options *ndo, const u_char *bp, u_int length)
{
	const struct psp_hdr *hdr;
	uint8_t nh, extlen, verfl, version;
	u_int total_hdr_len;

	/* Invariant 1: Buffer must contain at least base header size */
	if (length < PSP_BASE_HLEN || !ND_TTEST_LEN(bp, PSP_BASE_HLEN))
		return 0;

	hdr = (const struct psp_hdr *)bp;
	verfl = GET_U_1(hdr->psp_verfl);

	/* Invariant 2: Protocol invariant bit 0 MUST be 1 */
	if ((verfl & PSP_HDR_VERFL_ONE) == 0)
		return 0;

	/* Invariant 3: Version must be a defined one (0 to 3) */
	version = (verfl & PSP_HDR_VERFL_VERSION_MASK) >>
		  PSP_HDR_VERFL_VERSION_SHIFT;
	if (version > PSP_VERSION_AES_GMAC_256)
		return 0;

	/* Invariant 4: Recognized next header */
	nh = GET_U_1(hdr->psp_nh);
	if (nh != IPPROTO_TCP && nh != IPPROTO_UDP && nh != IPPROTO_IPV4 &&
	    nh != IPPROTO_IPV6)
		return 0;

	/*
	 * Invariant 5: Header Extension Length must be >= 1 (accounting for
	 * 8-byte IV).
	 */
	extlen = GET_U_1(hdr->psp_hlen);
	if (extlen < 1)
		return 0;

	/*
	 * Invariant 6: Total PSP header and the ICV trailer must fit in
	 * available packet data (on the host, before the NIC adds the ICV,
	 * the inner TCP header is at least as long as the ICV)
	 */
	total_hdr_len = PSP_BASE_HLEN + (extlen - 1) * PSP_EXT_LEN_UNIT;
	if (total_hdr_len + PSP_ICV_LEN > length)
		return 0;

	return 1;
}

/*
 * Print a TCP or UDP header that is not entirely in the clear: the ports
 * if they are before the Crypt Offset, then a note that the rest of the
 * header is encrypted.
 */
static void
psp_l4_encrypted_print(netdissect_options *ndo, const u_char *bp,
		       u_int clear_len, uint8_t nh, u_int cryptoff)
{
	const char *proto = (nh == IPPROTO_TCP) ? "TCP" : "UDP";
	uint16_t sport, dport;

	if (clear_len < PSP_L4_PORTS_LEN) {
		ND_PRINT("[%s header encrypted, cryptoff %u]", proto, cryptoff);
		return;
	}
	sport = GET_BE_U_2(bp);
	dport = GET_BE_U_2(bp + 2);
	if (nh == IPPROTO_TCP)
		ND_PRINT("%s > %s: ", tcpport_string(ndo, sport),
			 tcpport_string(ndo, dport));
	else
		ND_PRINT("%s > %s: ", udpport_string(ndo, sport),
			 udpport_string(ndo, dport));
	ND_PRINT("[%s header encrypted beyond ports, cryptoff %u]", proto,
		 cryptoff);
}

/*
 * Print the inner TCP segment of a Transport Mode packet.  tcp_len is the
 * length of the segment and clear_len is the number of bytes at its start
 * that are in the clear.
 *
 * Only the TCP header is dissected, never the TCP payload.
 */
static void
psp_tcp_print(netdissect_options *ndo, const u_char *bp, u_int tcp_len,
	      u_int clear_len, const u_char *bp2, u_int cryptoff)
{
	const struct tcphdr *tp = (const struct tcphdr *)bp;
	u_int th_len;

	if (tcp_len < sizeof(struct tcphdr)) {
		nd_print_invalid(ndo);
		return;
	}

	if (clear_len < sizeof(struct tcphdr)) {
		psp_l4_encrypted_print(ndo, bp, clear_len, IPPROTO_TCP,
				       cryptoff);
		return;
	}

	/*
	 * Stop the dissection at the end of the TCP header, or at the end of
	 * the cleartext if the Crypt Offset falls inside the TCP options, as
	 * if the capture ended there: tcp_print() prints the TCP header and
	 * the payload length, but cannot dissect the payload.  If the capture
	 * itself ends before the data offset, tcp_print() reports the
	 * truncation.
	 */
	th_len = sizeof(struct tcphdr);
	if (ND_TTEST_1(tp->th_offx2) && (u_int)TH_OFF(tp) * 4 > th_len)
		th_len = (u_int)TH_OFF(tp) * 4;
	if (!nd_push_snaplen(ndo, bp, ND_MIN(th_len, clear_len)))
		(*ndo->ndo_error)(ndo, S_ERR_ND_MEM_ALLOC,
			"%s: can't push snaplen on buffer stack", __func__);
	tcp_print(ndo, bp, tcp_len, bp2, 0);
	nd_pop_packet_info(ndo);
}

void
psp_print(netdissect_options *ndo, const u_char *bp, u_int length,
	  const u_char *bp2)
{
	const struct psp_hdr *hdr;
	uint8_t nh, extlen, cryptoff_rsvd, verfl, version;
	uint32_t raw_spi, key_id;
	uint64_t iv, vc;
	u_int cryptoff, total_hdr_len, opt_ext_len;
	int phase, gmac, host;
	const u_char *inner_bp;
	u_int inner_len, payload_len, clear_len;

	ndo->ndo_protocol = "psp";

	if (length < PSP_BASE_HLEN) {
		nd_print_invalid(ndo);
		return;
	}

	ND_TCHECK_LEN(bp, PSP_BASE_HLEN);
	hdr = (const struct psp_hdr *)bp;

	nh = GET_U_1(hdr->psp_nh);
	extlen = GET_U_1(hdr->psp_hlen);
	cryptoff_rsvd = GET_U_1(hdr->psp_cryptoff);
	cryptoff = cryptoff_rsvd & PSP_CRYPTOFF_MASK;
	verfl = GET_U_1(hdr->psp_verfl);
	raw_spi = GET_BE_U_4(hdr->psp_spi);
	iv = GET_BE_U_8(hdr->psp_iv);

	version = (verfl & PSP_HDR_VERFL_VERSION_MASK) >>
		  PSP_HDR_VERFL_VERSION_SHIFT;
	phase = (raw_spi & PSP_SPI_PHASE_BIT) ? 1 : 0;
	key_id = raw_spi & PSP_SPI_KEY_MASK;
	/* AES-GMAC authenticates the payload but does not encrypt it */
	gmac = (version == PSP_VERSION_AES_GMAC_128 ||
		version == PSP_VERSION_AES_GMAC_256);
	/*
	 * A zero IV means that the packet was captured on the host, in the
	 * clear, rather than on the wire: the kernel leaves the IV for the
	 * NIC to fill in when the NIC encrypts the packet on transmit.  Such
	 * packets have no ICV trailer yet.
	 */
	host = (iv == 0);

	if (extlen < 1) {
		nd_print_invalid(ndo);
		return;
	}
	total_hdr_len = PSP_BASE_HLEN + (extlen - 1) * PSP_EXT_LEN_UNIT;
	if (total_hdr_len > length) {
		nd_print_invalid(ndo);
		return;
	}
	ND_TCHECK_LEN(bp, total_hdr_len);
	opt_ext_len = (extlen - 1) * PSP_EXT_LEN_UNIT;

	/* Print PSP Header Summary */
	nd_print_protocol_caps(ndo);
	if (ndo->ndo_vflag == 0) {
		ND_PRINT(" (spi 0x%08x, phase %d): ", key_id, phase);
	} else {
		ND_PRINT(" (ver %u, spi 0x%08x, phase %d, cryptoff %u",
			 version, key_id, phase, cryptoff);
		if (cryptoff_rsvd & PSP_CRYPTOFF_RSVD_MASK)
			ND_PRINT(", rsvd 0x%x",
				 (cryptoff_rsvd & PSP_CRYPTOFF_RSVD_MASK) >>
				 PSP_CRYPTOFF_RSVD_SHIFT);
		ND_PRINT(", iv 0x%016" PRIx64, iv);
		if (verfl & PSP_HDR_VERFL_SAMPLE)
			ND_PRINT(", sample");
		if (verfl & PSP_HDR_VERFL_DROP)
			ND_PRINT(", drop");
		if (verfl & PSP_HDR_VERFL_VIRT) {
			if (extlen < 2) {
				ND_PRINT(", vc [invalid len]");
			} else if (!host && !gmac &&
				   cryptoff * PSP_CRYPT_OFFSET_UNIT <
				   PSP_VC_SIZE) {
				/* Crypt Offset counts from the end of the IV */
				ND_PRINT(", vc [encrypted]");
			} else {
				vc = GET_BE_U_8(bp + PSP_BASE_HLEN);
				ND_PRINT(", vc 0x%016" PRIx64, vc);
			}
		}
		ND_PRINT("): ");
	}

	if (version > PSP_VERSION_AES_GMAC_256) {
		ND_PRINT("unknown version %u", version);
		return;
	}

	inner_bp = bp + total_hdr_len;
	inner_len = length - total_hdr_len;
	if (host) {
		payload_len = inner_len;
	} else {
		/* On the wire, the payload is followed by the ICV trailer */
		ND_ICHECKMSG_U("remaining length", inner_len, <, PSP_ICV_LEN);
		payload_len = inner_len - PSP_ICV_LEN;
	}

	/*
	 * Number of payload bytes in the clear.  With AES-GCM, encryption
	 * starts at the Crypt Offset, which counts from the end of the IV
	 * and so includes any header extension, such as the Virtualization
	 * Cookie.  On the host, the inner TCP header is in the clear past
	 * the Crypt Offset too (the kernel only sends TCP over PSP), so it
	 * is dissected in full; tunnel mode and inner UDP stop at the Crypt
	 * Offset either way.
	 */
	if (gmac || (host && nh == IPPROTO_TCP))
		clear_len = payload_len;
	else if (cryptoff * PSP_CRYPT_OFFSET_UNIT > opt_ext_len)
		clear_len = ND_MIN(cryptoff * PSP_CRYPT_OFFSET_UNIT -
				   opt_ext_len, payload_len);
	else
		clear_len = 0;

	/*
	 * Dissect the inner packet only up to the end of the cleartext, as
	 * if the capture ended there, so that ciphertext is never decoded.
	 */
	if (!nd_push_snaplen(ndo, inner_bp, clear_len))
		(*ndo->ndo_error)(ndo, S_ERR_ND_MEM_ALLOC,
			"%s: can't push snaplen on buffer stack", __func__);

	switch (nh) {
	case IPPROTO_TCP:
		/*
		 * Transport Mode TCP:
		 * Outer IP == Inner IP. Outer endpoints were printed by
		 * udp_print(). tcp_print() automatically detects outer protocol
		 * is UDP (via bp2) and prints inner ports:
		 * "<sport> > <dport>: Flags [...], seq ..."
		 */
		psp_tcp_print(ndo, inner_bp, payload_len, clear_len, bp2,
			      cryptoff);
		break;

	case IPPROTO_IPV4:
		/* Tunnel Mode IPv4: Underlay IP != Overlay IP */
		ND_PRINT("tunnel-encap: ");
		if (clear_len < sizeof(struct ip))
			ND_PRINT("[IP header encrypted, cryptoff %u]",
				 cryptoff);
		else
			ip_print(ndo, inner_bp, payload_len);
		break;

	case IPPROTO_IPV6:
		/* Tunnel Mode IPv6: Underlay IP != Overlay IP */
		ND_PRINT("tunnel-encap: ");
		if (clear_len < sizeof(struct ip6_hdr))
			ND_PRINT("[IP6 header encrypted, cryptoff %u]",
				 cryptoff);
		else
			ip6_print(ndo, inner_bp, payload_len);
		break;

	case IPPROTO_UDP:
		/* Transport Mode UDP / Falcon / GRT */
		if (clear_len < sizeof(struct udphdr))
			psp_l4_encrypted_print(ndo, inner_bp, clear_len, nh,
					       cryptoff);
		else
			udp_print(ndo, inner_bp, payload_len, bp2, 0, 0);
		break;

	default:
		ND_PRINT("nexthdr %s (%u), length %u",
			 tok2str(ipproto_values, "unknown", nh), nh,
			 payload_len);
		break;
	}

	nd_pop_packet_info(ndo);
	return;

invalid:
	nd_print_invalid(ndo);
}
