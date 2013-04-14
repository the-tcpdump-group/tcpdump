/**
 * Copyright (c) 2012
 *
 * Gregory Detal <gregory.detal@uclouvain.be>
 * Christoph Paasch <christoph.paasch@uclouvain.be>
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
 * 3. Neither the name of the University nor of the Laboratory may be used
 *    to endorse or promote products derived from this software without
 *    specific prior written permission.
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
 */

#define MPTCP_SUB_CAPABLE       0x0
#define MPTCP_SUB_JOIN          0x1
#define MPTCP_SUB_DSS           0x2
#define MPTCP_SUB_ADD_ADDR      0x3
#define MPTCP_SUB_REMOVE_ADDR   0x4
#define MPTCP_SUB_PRIO          0x5
#define MPTCP_SUB_FAIL          0x6
#define MPTCP_SUB_FCLOSE        0x7


struct mptcp_option {
        u_int8_t        kind;
        u_int8_t        len;
#if !LBL_ALIGN
        u_int8_t        ver:4,
                        sub:4;
#else
        u_int8_t        sub:4,
                        ver:4;
#endif
};

struct mp_capable {
        u_int8_t        kind;
        u_int8_t        len;
#if !LBL_ALIGN
        u_int8_t        ver:4,
                        sub:4;
        u_int8_t        s:1,
                        rsv:6,
                        c:1;
#else
        u_int8_t        sub:4,
                        ver:4;
        u_int8_t        c:1,
                        rsv:6,
                        s:1;
#endif
        u_int64_t        sender_key;
        u_int64_t        receiver_key;
} __attribute__((__packed__));

struct mp_join {
        u_int8_t        kind;
        u_int8_t        len;
#if !LBL_ALIGN
        u_int8_t        b:1,
                        rsv:3,
                        sub:4;
#else
        u_int8_t        sub:4,
                        rsv:3,
                        b:1;
#endif
        u_int8_t        addr_id;
        union {
                struct {
                        u_int32_t        token;
                        u_int32_t        nonce;
                } syn;
                struct {
                        u_int64_t        mac;
                        u_int32_t        nonce;
                } synack;
                struct {
                        u_int8_t        mac[20];
                } ack;
        } u;
} __attribute__((__packed__));

struct mp_dss {
        u_int8_t        kind;
        u_int8_t        len;
#if !LBL_ALIGN
        u_int16_t        rsv1:4,
                        sub:4,
                        A:1,
                        a:1,
                        M:1,
                        m:1,
                        F:1,
                        rsv2:3;
#else
        u_int16_t        sub:4,
                        rsv1:4,
                        rsv2:3,
                        F:1,
                        m:1,
                        M:1,
                        a:1,
                        A:1;
#endif
};

struct mp_add_addr {
        u_int8_t        kind;
        u_int8_t        len;
#if !LBL_ALIGN
        u_int8_t        ipver:4,
                        sub:4;
#else
        u_int8_t        sub:4,
                        ipver:4;
#endif
        u_int8_t        addr_id;
        union {
                struct {
                        struct in_addr   addr;
                        u_int16_t        port;
                } v4;
                struct {
                        struct in6_addr  addr;
                        u_int16_t        port;
                } v6;
        } u;
} __attribute__((__packed__));

struct mp_remove_addr {
        u_int8_t        kind;
        u_int8_t        len;
#if !LBL_ALIGN
        u_int8_t        rsv:4,
                        sub:4;
#else
        u_int8_t        sub:4,
                        rsv:4;
#endif
        /* list of addr_id */
        u_int8_t        addrs_id;
};

struct mp_fail {
        u_int8_t        kind;
        u_int8_t        len;
#if !LBL_ALIGN
        u_int16_t       rsv1:4,
                        sub:4,
                        rsv2:8;
#else
        u_int16_t       sub:4,
                        rsv1:4,
                        rsv2:8;
#endif
        u_int64_t        data_seq;
} __attribute__((__packed__));

struct mp_fclose {
        u_int8_t        kind;
        u_int8_t        len;
#if !LBL_ALIGN
        u_int16_t       rsv1:4,
                        sub:4,
                        rsv2:8;
#else
        u_int16_t       sub:4,
                        rsv1:4,
                        rsv2:8;
#endif
        u_int64_t        key;
} __attribute__((__packed__));

struct mp_prio {
        u_int8_t        kind;
        u_int8_t        len;
#if !LBL_ALIGN
        u_int8_t        b:1,
                        rsv:3,
                        sub:4;
#else
        u_int8_t        sub:4,
                        rsv:3,
                        b:1;
#endif
        u_int8_t        addr_id;
} __attribute__((__packed__));

