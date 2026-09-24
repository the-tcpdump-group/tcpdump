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

#ifndef ND_PSP_H_
#define ND_PSP_H_

/* Default UDP destination/source port for PSP encapsulation */
#define PSP_DEFAULT_UDP_PORT		1000

/* PSP Base Header length (without optional extensions) */
#define PSP_BASE_HLEN			16

/* Extension unit size in bytes */
#define PSP_EXT_LEN_UNIT		8

/* Crypt offset unit size in bytes (32-bit words) */
#define PSP_CRYPT_OFFSET_UNIT		4

/* ICV (Integrity Check Value) trailer length */
#define PSP_ICV_LEN			16

/* Virtualization Cookie size */
#define PSP_VC_SIZE			8

/*
 * PSP Base Header Wire Format (16 octets minimum):
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  Next Header  |  Hdr Ext Len  |  Crypt Offset |S|D| Version |V|1|
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |               Security Parameters Index (SPI)                 |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                                                               |
 * +                  Initialization Vector (IV)                   +
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |               Virtualization Cookie (VC) [Optional]           |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

struct psp_hdr {
	nd_uint8_t	psp_nh;		/* Next Header protocol (IPPROTO_*) */
	nd_uint8_t	psp_hlen;	/* Header Ext Len (8-byte units) */
	nd_uint8_t	psp_cryptoff;	/* Crypt Offset (4-byte units) */
	nd_uint8_t	psp_verfl;	/* Version and flags */
	nd_uint32_t	psp_spi;	/* SPI: Phase bit (31), Key ID (30:0) */
	nd_uint64_t	psp_iv;		/* 64-bit Initialization Vector */
};

/*
 * Bit definitions for psp_verfl:
 * Bit 7: Sample bit (S)
 * Bit 6: Drop bit (D)
 * Bits 5:2: Version field (0 or 1)
 * Bit 1: Virtualization Cookie present (V)
 * Bit 0: Invariant bit (always 1)
 */
#define PSP_HDR_VERFL_SAMPLE		0x80
#define PSP_HDR_VERFL_DROP		0x40
#define PSP_HDR_VERFL_VERSION_MASK	0x3C
#define PSP_HDR_VERFL_VERSION_SHIFT	2
#define PSP_HDR_VERFL_VIRT		0x02
#define PSP_HDR_VERFL_ONE		0x01

/*
 * Bit definitions for psp_spi:
 * Bit 31: Phase bit (key generation selector)
 * Bits 30-0: SPI / Key ID
 */
#define PSP_SPI_PHASE_BIT		0x80000000U
#define PSP_SPI_KEY_MASK		0x7FFFFFFFU

#endif /* ND_PSP_H_ */
