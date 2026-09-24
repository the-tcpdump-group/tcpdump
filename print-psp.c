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
#include "ipproto.h"
#include "psp.h"

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

	/* Invariant 3: Supported version must be 0 or 1 */
	version = (verfl & PSP_HDR_VERFL_VERSION_MASK) >>
		  PSP_HDR_VERFL_VERSION_SHIFT;
	if (version > 1)
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

	/* Invariant 6: Total PSP header must fit in available packet data */
	total_hdr_len = PSP_BASE_HLEN + (extlen - 1) * PSP_EXT_LEN_UNIT;
	if (total_hdr_len > length)
		return 0;

	return 1;
}

void
psp_print(netdissect_options *ndo, const u_char *bp, u_int length,
	  const u_char *bp2)
{
	const struct psp_hdr *hdr;
	uint8_t nh, extlen, cryptoff, verfl, version;
	uint32_t raw_spi, key_id;
	uint64_t iv, vc;
	u_int total_hdr_len, cryptoff_bytes, opt_ext_len;
	int phase;
	const u_char *inner_bp;
	u_int inner_len;

	ndo->ndo_protocol = "psp";

	if (length < PSP_BASE_HLEN) {
		nd_print_invalid(ndo);
		return;
	}

	ND_TCHECK_LEN(bp, PSP_BASE_HLEN);
	hdr = (const struct psp_hdr *)bp;

	nh = GET_U_1(hdr->psp_nh);
	extlen = GET_U_1(hdr->psp_hlen);
	cryptoff = GET_U_1(hdr->psp_cryptoff);
	verfl = GET_U_1(hdr->psp_verfl);
	raw_spi = GET_BE_U_4(hdr->psp_spi);
	iv = GET_BE_U_8(hdr->psp_iv);

	version = (verfl & PSP_HDR_VERFL_VERSION_MASK) >>
		  PSP_HDR_VERFL_VERSION_SHIFT;
	phase = (raw_spi & PSP_SPI_PHASE_BIT) ? 1 : 0;
	key_id = raw_spi & PSP_SPI_KEY_MASK;

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

	/* Print PSP Header Summary */
	nd_print_protocol_caps(ndo);
	if (ndo->ndo_vflag == 0) {
		ND_PRINT(" (spi 0x%08x, phase %d): ", key_id, phase);
	} else {
		ND_PRINT(" (ver %u, spi 0x%08x, phase %d, cryptoff %u, "
			 "iv 0x%016" PRIx64,
			 version, key_id, phase, cryptoff, iv);
		if (verfl & PSP_HDR_VERFL_SAMPLE)
			ND_PRINT(", sample");
		if (verfl & PSP_HDR_VERFL_DROP)
			ND_PRINT(", drop");
		if (verfl & PSP_HDR_VERFL_VIRT) {
			if (extlen >= 2) {
				vc = GET_BE_U_8(bp + PSP_BASE_HLEN);
				ND_PRINT(", vc 0x%016" PRIx64, vc);
			} else {
				ND_PRINT(", vc [invalid len]");
			}
		}
		ND_PRINT("): ");
	}

	inner_bp = bp + total_hdr_len;
	inner_len = length - total_hdr_len;
	opt_ext_len = (extlen - 1) * PSP_EXT_LEN_UNIT;
	if (cryptoff * PSP_CRYPT_OFFSET_UNIT > opt_ext_len)
		cryptoff_bytes = cryptoff * PSP_CRYPT_OFFSET_UNIT - opt_ext_len;
	else
		cryptoff_bytes = 0;

	switch (nh) {
	case IPPROTO_TCP:
		/*
		 * Transport Mode TCP:
		 * Outer IP == Inner IP. Outer endpoints were printed by
		 * udp_print(). tcp_print() automatically detects outer protocol
		 * is UDP (via bp2) and prints inner ports:
		 * "<sport> > <dport>: Flags [...], seq ..."
		 */
		if (cryptoff_bytes >= 20) {
			u_int tcp_parse_len = cryptoff_bytes;

			if (tcp_parse_len > inner_len)
				tcp_parse_len = inner_len;

			tcp_print(ndo, inner_bp, tcp_parse_len, bp2, 0);
		} else if (cryptoff_bytes >= 4) {
			uint16_t isport, idport;

			if (inner_len < 4) {
				nd_print_invalid(ndo);
				break;
			}
			ND_TCHECK_LEN(inner_bp, 4);
			isport = GET_BE_U_2(inner_bp);
			idport = GET_BE_U_2(inner_bp + 2);
			ND_PRINT("%s > %s: [TCP header encrypted beyond "
				 "ports, cryptoff %u]",
				 tcpport_string(ndo, isport),
				 tcpport_string(ndo, idport),
				 cryptoff);
		} else {
			ND_PRINT("[TCP header encrypted, cryptoff 0]");
		}
		break;

	case IPPROTO_IPV4:
		/* Tunnel Mode IPv4: Underlay IP != Overlay IP */
		ND_PRINT("tunnel-encap: ");
		ip_print(ndo, inner_bp, inner_len);
		break;

	case IPPROTO_IPV6:
		/* Tunnel Mode IPv6: Underlay IP != Overlay IP */
		ND_PRINT("tunnel-encap: ");
		ip6_print(ndo, inner_bp, inner_len);
		break;

	case IPPROTO_UDP:
		/* Transport Mode UDP / Falcon / GRT */
		udp_print(ndo, inner_bp, inner_len, bp2, 0, 0);
		break;

	default:
		ND_PRINT("nexthdr %s (%u), length %u",
			 tok2str(ipproto_values, "unknown", nh), nh, inner_len);
		break;
	}
}
