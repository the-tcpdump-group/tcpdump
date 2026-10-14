/*
 * Copyright (c) 2026
 *	The Tcpdump Group and contributors.  All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/* \summary: macros to byte-swap integral quantities */

#ifndef BYTESWAP_H
#define BYTESWAP_H

#include "netdissect-stdinc.h"
/*
 * We use the "receiver-makes-right" approach to byte order;
 * because time is at a premium when we are writing the file.
 * In other words, the pcap_file_header and pcap_pkthdr,
 * records are written in host byte order.
 * Note that the bytes of packet data are written out in the order in
 * which they were received, so multi-byte fields in packets are not
 * written in host byte order, they're written in whatever order the
 * sending machine put them in.
 *
 * We also use this for fixing up packet data headers from a remote
 * capture, where the server may have a different byte order from the
 * client.
 *
 * ntoh[ls] aren't sufficient because we might need to swap on a big-endian
 * machine (if the file was written in little-end order).
 *
 * These macros are used to generate case labels in switch statements,
 * so they can't be done as inline functions, and, when passed a
 * compile-time constant argument, must produce a compile-time constant
 * result.  This means that they must either use builtin functions that
 * are recognized by the compiler as producing constant results when
 * passed a constant argument, or must be done with expressions that
 * evaluate to compile-time constants when passed a compile-time
 * constant.
 *
 * (In practical terms, to define HAVE_BUILTIN_BSWAPnn it is sufficient to
 * verify that respective builtin can be used as a case label in a switch
 * statement.)
 *
 * Newer versions of GCC, Clang, Visual Studio C/C++, and possibly
 * some other compilers recognize the expressions as byte-swapping
 * idioms and generate optimized machine-specific code for architectures
 * that include instructions that can be used to swap bytes.
 */
#ifdef HAVE_BUILTIN_BSWAP64
#define ND_BSWAP_64(y) __builtin_bswap64((uint64_t)(y))
#else
#define ND_BSWAP_64(y) \
    ((uint64_t)(((((uint64_t)(y)) & UINT64_C(0xff00000000000000)) >> 56) | \
                ((((uint64_t)(y)) & UINT64_C(0x00ff000000000000)) >> 40) | \
                ((((uint64_t)(y)) & UINT64_C(0x0000ff0000000000)) >> 24) | \
                ((((uint64_t)(y)) & UINT64_C(0x000000ff00000000)) >> 8)  | \
                ((((uint64_t)(y)) & UINT64_C(0x00000000ff000000)) << 8)  | \
                ((((uint64_t)(y)) & UINT64_C(0x0000000000ff0000)) << 24) | \
                ((((uint64_t)(y)) & UINT64_C(0x000000000000ff00)) << 40) | \
                ((((uint64_t)(y)) & UINT64_C(0x00000000000000ff)) << 56)))
#endif // 64-bit

#ifdef HAVE_BUILTIN_BSWAP32
#define ND_BSWAP_32(y) __builtin_bswap32((uint32_t)(y))
#else
#define ND_BSWAP_32(y) \
    ((uint32_t)(((((uint32_t)(y)) & UINT32_C(0xff000000)) >> 24) | \
                ((((uint32_t)(y)) & UINT32_C(0x00ff0000)) >> 8)  | \
                ((((uint32_t)(y)) & UINT32_C(0x0000ff00)) << 8)  | \
                ((((uint32_t)(y)) & UINT32_C(0x000000ff)) << 24)))
#endif // 32-bit

#ifdef HAVE_BUILTIN_BSWAP16
#define ND_BSWAP_16(y) __builtin_bswap16((uint16_t)(y))
#else
#define ND_BSWAP_16(y) \
    ((uint16_t)(((((uint16_t)(y)) & UINT16_C(0x00ff)) << 8) | \
                ((((uint16_t)(y)) & UINT16_C(0xff00)) >> 8)))
#endif // 16-bit

#endif /* BYTESWAP_H */
