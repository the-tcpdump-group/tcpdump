/*-
 * Copyright (c) 1990, 1991, 1992, 1993, 1994, 1995, 1996, 1997
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from the Stanford/CMU enet packet filter,
 * (net/enet.c) distributed as part of 4.3BSD, and code contributed
 * to Berkeley by Steven McCanne and Van Jacobson both of Lawrence 
 * Berkeley Laboratory.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by the University of
 *      California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * @(#) $Header: /tcpdump/master/tcpdump/sll.h,v 1.1 2000-12-21 10:43:23 guy Exp $ (LBL)
 */

/*
 * For captures on Linux cooked sockets, we construct a fake header
 * that includes:
 *
 *	a 2-byte "packet type" which is one of:
 *
 *		LINUX_SLL_HOST		packet was sent to us
 *		LINUX_SLL_BROADCAST	packet was broadcast
 *		LINUX_SLL_MULTICAST	packet was multicast
 *		LINUX_SLL_OTHERHOST	packet was sent to somebody else
 *		LINUX_SLL_OUTGOING	packet was sent *by* us;
 *
 *	a 2-byte Ethernet protocol field;
 *
 *	a 2-byte link-layer type;
 *
 *	a 2-byte link-layer address length;
 *
 *	an 8-byte source link-layer address, whose actual length is
 *	specified by the previous value.
 *
 * All fields except for the link-layer address are in network byte order.
 */

/*
 * A DLT_LINUX_SLL fake link-layer header.
 */
#define SLL_HDR_LEN	16		/* total header length */
#define SLL_ADDRLEN	8		/* length of address field */

struct sll_header {
	u_int16_t	sll_pkttype;	/* packet type */
	u_int16_t	sll_protocol;	/* protocol */
	u_int16_t	sll_hatype;	/* link-layer address type */
	u_int16_t	sll_halen;	/* link-layer address length */
	u_int8_t	sll_addr[SLL_ADDRLEN];	/* link-layer address */
};

/*
 * The LINUX_SLL_ values; they are defined here so that they're available
 * even on systems other than Linux, but they should be given the same
 * values as the corresponding PACKET_ values on Linux.  (Let's hope
 * those values never change.)
 */
#define LINUX_SLL_HOST		0
#define LINUX_SLL_BROADCAST	1
#define LINUX_SLL_MULTICAST	2
#define LINUX_SLL_OTHERHOST	3
#define LINUX_SLL_OUTGOING	4
