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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <tcpdump-stdinc.h>

#include <stdio.h>
#include <string.h>

#include "interface.h"
#include "extract.h"
#include "addrtoname.h"

#include "ipproto.h"
#include "mptcp.h"
#include "tcp.h"

static int dummy_print(const u_char *opt _U_, u_int opt_len _U_, u_char flags _U_)
{
        return 1;
}

static int mp_capable_print(const u_char *opt, u_int opt_len, u_char flags)
{
        struct mp_capable *mpc = (struct mp_capable *) opt;

        if (!(opt_len == 12 && flags & TH_SYN) &&
            !(opt_len == 20 && (flags & (TH_SYN | TH_ACK)) == TH_ACK))
                return 0;

        if (mpc->ver != 0) {
                printf(" Unknown Version (%d)", mpc->ver);
                return 1;
        }

        if (mpc->c)
                printf(" csum");
        printf(" {0x%" PRIx64, EXTRACT_64BITS(&mpc->sender_key));
        if (opt_len == 20) /* ACK */
                printf(",0x%" PRIx64, EXTRACT_64BITS(&mpc->receiver_key));
        printf("}");
        return 1;
}

static int mp_join_print(const u_char *opt, u_int opt_len, u_char flags)
{
        struct mp_join *mpj = (struct mp_join *) opt;

        if (!(opt_len == 12 && flags & TH_SYN) &&
            !(opt_len == 16 && (flags & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK)) &&
            !(opt_len == 24 && flags & TH_ACK))
                return 0;

        if (opt_len != 24) {
                if (mpj->b)
                        printf(" backup");
                printf(" id %u", mpj->addr_id);
        }

        switch (opt_len) {
        case 12: /* SYN */
                printf(" token 0x%" PRIx32 " nonce 0x%" PRIx32,
                        EXTRACT_32BITS(&mpj->u.syn.token),
                        EXTRACT_32BITS(&mpj->u.syn.nonce));
                break;
        case 16: /* SYN/ACK */
                printf(" hmac 0x%" PRIx64 " nonce 0x%" PRIx32,
                        EXTRACT_64BITS(&mpj->u.synack.mac),
                        EXTRACT_32BITS(&mpj->u.synack.nonce));
                break;
        case 24: {/* ACK */
                int i;
                printf(" hmac 0x");
                for (i = 0; i < sizeof(mpj->u.ack.mac); ++i)
                        printf("%02x", mpj->u.ack.mac[i]);
        }
        default:
                break;
        }
        return 1;
}

static u_int mp_dss_len(struct mp_dss *m, int csum)
{
        return 4 + m->A * (4 + m->a * 4) + m->M * (10 + m->m * 4 + csum * 2);
}

static int mp_dss_print(const u_char *opt, u_int opt_len, u_char flags)
{
        struct mp_dss *mdss = (struct mp_dss *) opt;

        if ((opt_len != mp_dss_len(mdss, 1) &&
             opt_len != mp_dss_len(mdss, 0)) || flags & TH_SYN)
                return 0;

        if (mdss->F)
                printf(" fin");

        opt += 4;
        if (mdss->A) {
                printf(" ack ");
                if (mdss->a)
                        printf("%" PRIu64, EXTRACT_64BITS(opt));
                else
                        printf("%" PRIu32, EXTRACT_32BITS(opt));
                opt += mdss->a ? 8 : 4;
        }

        if (mdss->M) {
                printf(" seq ");
                if (mdss->m)
                        printf("%" PRIu64, EXTRACT_64BITS(opt));
                else
                        printf("%" PRIu32, EXTRACT_32BITS(opt));
                opt += mdss->m ? 8 : 4;
                printf(" subseq %" PRIu32, EXTRACT_32BITS(opt));
                opt += 4;
                printf(" len %" PRIu16, EXTRACT_16BITS(opt));
                opt += 2;

                if (opt_len == mp_dss_len(mdss, 1))
                        printf(" csum 0x%" PRIx16, EXTRACT_16BITS(opt));
        }
        return 1;
}

static int add_addr_print(const u_char *opt, u_int opt_len, u_char flags _U_)
{
        struct mp_add_addr *add_addr = (struct mp_add_addr *) opt;

        if (!((opt_len == 8 || opt_len == 10) && add_addr->ipver == 4) &&
            !((opt_len == 20 || opt_len == 22) && add_addr->ipver == 6))
                return 0;

        printf(" id %u", add_addr->addr_id);
        switch (add_addr->ipver) {
        case 4:
                printf(" %s", ipaddr_string(&add_addr->u.v4.addr));
                break;
        case 6:
#ifdef INET6
                printf(" %s", ip6addr_string(&add_addr->u.v6.addr));
#endif
                break;
        default:
                return 0;
        }

        if (opt_len == 10 || opt_len == 22)
                printf(":%" PRIu16, ntohs(add_addr->ipver == 4 ?
                                         add_addr->u.v4.port :
                                         add_addr->u.v6.port));
        return 1;
}

static int remove_addr_print(const u_char *opt, u_int opt_len, u_char flags _U_)
{
        struct mp_remove_addr *rem_addr = (struct mp_remove_addr *) opt;
        u_int8_t *addr_id = &rem_addr->addrs_id;

        if (opt_len < 4)
                return 0;

        opt_len -= 3;
        printf(" id");
        while (opt_len--)
                printf(" %u", *addr_id++);
        return 1;
}

static int mp_prio_print(const u_char *opt, u_int opt_len, u_char flags _U_)
{
        struct mp_prio *mpp = (struct mp_prio *) opt;

        if (opt_len != 3 && opt_len != 4)
                return 0;

        if (mpp->b)
                printf(" backup");
        else
                printf(" non-backup");
        if (opt_len == 4)
                printf(" id %u", mpp->addr_id);

        return 1;
}

static int mp_fail_print(const u_char *opt, u_int opt_len, u_char flags)
{
        if (opt_len != 12)
                return 0;

        printf(" seq %" PRIu64, EXTRACT_64BITS(opt + 4));
        return 1;
}

static int mp_fast_close_print(const u_char *opt, u_int opt_len, u_char flags)
{
        if (opt_len != 12)
                return 0;

        printf(" key 0x%" PRIx64, EXTRACT_64BITS(opt + 4));
        return 1;
}

static struct {
        const char *name;
        int (*print)(const u_char *, u_int, u_char);
} mptcp_options[] = {
        { "capable", mp_capable_print},
        { "join",       mp_join_print },
        { "dss",        mp_dss_print },
        { "add-addr",   add_addr_print },
        { "rem-addr",   remove_addr_print },
        { "prio",       mp_prio_print },
        { "fail",       mp_fail_print },
        { "fast-close", mp_fast_close_print },
        { "unknown",    dummy_print },
};

int mptcp_print(const u_char *cp, u_int len, u_char flags)
{
        struct mptcp_option *opt;
        u_int subtype;

        if (len < 3)
                return 0;

        opt = (struct mptcp_option *) cp;
        subtype = min(opt->sub, MPTCP_SUB_FCLOSE + 1);

        printf(" %s", mptcp_options[subtype].name);
        return mptcp_options[subtype].print(cp, len, flags);
}
