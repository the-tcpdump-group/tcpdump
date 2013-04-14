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

static int dummy_print(const u_char *opt, u_int opt_len)
{
        return 1;
}

static int mp_capable_print(const u_char *opt, u_int opt_len)
{
        struct mp_capable *mpc = (struct mp_capable *) opt;

        if (mpc->c)
                printf(" csum");
        printf(" {0x%" PRIx64, mpc->sender_key);
        if (opt_len == 20)
                printf(",0x%" PRIx64, mpc->receiver_key);
        printf("}");
        return 1;
}

static int mp_join_print(const u_char *opt, u_int opt_len)
{
        struct mp_join *mpj = (struct mp_join *) opt;

        if (mpj->b)
                printf(" backup");
        printf(" id %" PRIu8, mpj->addr_id);

        if (opt_len == 12)
                printf(" token 0x%" PRIx32, mpj->u.syn.token);

        return 1;
}

static u_int mp_dss_len(struct mp_dss *m, u_int csum)
{
        return 4 + m->A * (4 + m->a * 4) + m->M * (10 + m->m * 4 + csum * 2);
}

static int mp_dss_print(const u_char *opt, u_int opt_len)
{
        struct mp_dss *mdss = (struct mp_dss *) opt;

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

static int add_addr_print(const u_char *opt, u_int opt_len)
{
        struct mp_add_addr *add_addr = (struct mp_add_addr *) opt;

        printf(" id %" PRIu8, add_addr->addr_id);
        switch (add_addr->ipver) {
        case 4:
                printf(" %s", ipaddr_string(&add_addr->u.v4.addr));
                break;
#ifdef INET6
        case 6:
                printf(" %s", ip6addr_string(&add_addr->u.v6.addr));
                break;
#endif
        default:
                return 0;
        }
        if (opt_len == 10 || opt_len == 22)
                printf(":%" PRIu16, ntohs(add_addr->ipver == 4 ?
                                         add_addr->u.v4.port :
                                         add_addr->u.v6.port));
        return 1;
}

static int remove_addr_print(const u_char *opt, u_int opt_len)
{
        struct mp_remove_addr *rem_addr = (struct mp_remove_addr *) opt;
        u_int8_t *addr_id = &rem_addr->addrs_id;

        opt_len -= 3;
        printf(" id");
        while (opt_len--)
                printf(" %" PRIu8, *addr_id++);
        return 1;
}

static int mp_prio_print(const u_char *opt, u_int opt_len)
{
        struct mp_prio *mpp = (struct mp_prio *) opt;

        if (mpp->b)
                printf(" backup");
        else
                printf(" non-backup");
        if (opt_len == 4)
                printf(" id %" PRIu8, mpp->addr_id);

        return 1;
}

static int mp_fail_print(const u_char *opt, u_int opt_len)
{
        opt += 4;
        printf(" seq %" PRIu64, EXTRACT_64BITS(opt));
}

static int mp_fast_close_print(const u_char *opt, u_int opt_len)
{
        opt += 4;
        printf(" key 0x%" PRIx64, *((uint64_t *)opt));
}

static struct {
        const char *name;
        int (*print)(const u_char *, u_int);
} mptcp_options[] = {
        { "capable",        mp_capable_print },
        { "join",        mp_join_print },
        { "dss",        mp_dss_print },
        { "add-addr",        add_addr_print },
        { "rem-addr",        remove_addr_print },
        { "prio",        mp_prio_print },
        { "fail",        mp_fail_print },
        { "fast-close",        mp_fast_close_print },
        { "unknown",        dummy_print },
};

int mptcp_print(const u_char *cp, u_int len)
{
        struct mptcp_option *opt = (struct mptcp_option *) cp;
        u_int subtype = min(opt->sub, MPTCP_SUB_FCLOSE + 1);

        printf(" %s", mptcp_options[subtype].name);
        return mptcp_options[subtype].print(cp, len);
}
