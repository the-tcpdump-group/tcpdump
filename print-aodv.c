/*
 * Copyright (c) 2003 Bruce M. Simpson <bms@spc.org>
 * All rights reserved.
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
 *        This product includes software developed by Bruce M. Simpson.
 * 4. Neither the name of Bruce M. Simpson nor the names of co-
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY Bruce M. Simpson AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL Bruce M. Simpson OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef lint
static const char rcsid[] =
    "@(#) $Header: /tcpdump/master/tcpdump/print-aodv.c,v 1.1 2003-08-06 06:49:40 guy Exp $ (LBL)";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/param.h>
#include <sys/time.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <stddef.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>

#include "interface.h"
#include "addrtoname.h"
#include "extract.h"			/* must come after interface.h */

#include "aodv.h"

static void
aodv_extension(struct aodv_ext *ep, u_int length)
{
	u_int i;
	struct aodv_hello *ah;

	switch (ep->type) {
	case AODV_EXT_HELLO:
		if (snapend < (u_char *) ep) {
			printf(" [|hello]");
			return;
		}
		i = min(length, (u_int)(snapend - (u_char *) ep));
		if (i < sizeof(struct aodv_hello)) {
			printf(" [|hello]");
			return;
		}
		i -= sizeof(struct aodv_hello);
		ah = (void *) ep;
		printf("\n\text HELLO %d ms",
			EXTRACT_32BITS(ah->interval));
		break;

	default:
		printf("\n\text %d %d", ep->type, ep->length);
		break;
	}
}

static void
aodv_rreq(union aodv *ap, const u_char *dat, u_int length, void *ip6
#ifndef INET6
	_U_
#endif
	)
{
	u_int i;

	if (snapend < dat) {
		printf(" [|aodv]");
		return;
	}
	i = min(length, (u_int)(snapend - dat));
	if (i < sizeof(ap->rreq)) {
		printf(" [|rreq]");
		return;
	}
	i -= sizeof(ap->rreq);
#ifdef INET6
	if (ip6 != NULL) {
		printf(" rreq %d %s%s%s%s%shops %d id 0x%08lx\n"
			"\tdst %s seq %d src %s seq %d", length,
			ap->rreq6.rreq_type & RREQ_JOIN ? "[J]" : "",
			ap->rreq6.rreq_type & RREQ_REPAIR ? "[R]" : "",
			ap->rreq6.rreq_type & RREQ_GRAT ? "[G]" : "",
			ap->rreq6.rreq_type & RREQ_DEST ? "[D]" : "",
			ap->rreq6.rreq_type & RREQ_UNKNOWN ? "[U] " : " ",
			ap->rreq6.rreq_hops,
			EXTRACT_32BITS(ap->rreq6.rreq_id),
			ip6addr_string(&ap->rreq6.rreq_da),
			EXTRACT_32BITS(ap->rreq6.rreq_ds),
			ip6addr_string(&ap->rreq6.rreq_oa),
			EXTRACT_32BITS(ap->rreq6.rreq_os));
		if (i >= sizeof(ap->rreq6) + sizeof(struct aodv_ext)) {
			aodv_extension((void *) (&ap->rreq6 + 1),
					length - sizeof(ap->rreq6));
		}
		} else
#endif
	{
		printf(" rreq %d %s%s%s%s%shops %d id 0x%08x\n"
			"\tdst %s seq %d src %s seq %d", length,
			ap->rreq.rreq_type & RREQ_JOIN ? "[J]" : "",
			ap->rreq.rreq_type & RREQ_REPAIR ? "[R]" : "",
			ap->rreq.rreq_type & RREQ_GRAT ? "[G]" : "",
			ap->rreq.rreq_type & RREQ_DEST ? "[D]" : "",
			ap->rreq.rreq_type & RREQ_UNKNOWN ? "[U] " : " ",
			ap->rreq.rreq_hops,
			EXTRACT_32BITS(ap->rreq.rreq_id),
			ipaddr_string(ap->rreq.rreq_da),
			EXTRACT_32BITS(ap->rreq.rreq_ds),
			ipaddr_string(ap->rreq.rreq_oa),
			EXTRACT_32BITS(ap->rreq.rreq_os));
		if (i >= sizeof(ap->rreq) + sizeof(struct aodv_ext)) {
			aodv_extension((void *) (&ap->rreq + 1),
					length - sizeof(ap->rreq));
		}
	}
}

static void
aodv_rrep(union aodv *ap, const u_char *dat, u_int length, void *ip6
#ifndef INET6
	_U_
#endif
	)
{
	u_int i;

	if (snapend < dat) {
		printf(" [|aodv]");
		return;
	}
	i = min(length, (u_int)(snapend - dat));
	if (i < sizeof(ap->rrep)) {
		printf(" [|rrep]");
		return;
	}
	i -= sizeof(ap->rrep);
#ifdef INET6
	if (ip6 != NULL) {
		printf(" rrep %d %s%sprefix %d hops %d\n"
		       "\tdst %s dseq %d src %s %d ms", length,
			ap->rrep6.rrep_type & RREP_REPAIR ? "[R]" : "",
			ap->rrep6.rrep_type & RREP_ACK ? "[A] " : " ",
			ap->rrep6.rrep_ps & RREP_PREFIX_MASK,
			ap->rrep6.rrep_hops,
			ip6addr_string(&ap->rrep6.rrep_da),
			EXTRACT_32BITS(ap->rrep6.rrep_ds),
			ip6addr_string(&ap->rrep6.rrep_oa),
			EXTRACT_32BITS(ap->rrep6.rrep_life));
		if (i >= sizeof(ap->rrep6) + sizeof(struct aodv_ext)) {
			aodv_extension((void *) (&ap->rrep6 + 1),
					length - sizeof(ap->rrep6));
		}
	} else
#endif
	{
		printf(" rrep %d %s%sprefix %d hops %d\n"
		       "\tdst %s dseq %d src %s %d ms", length,
			ap->rrep.rrep_type & RREP_REPAIR ? "[R]" : "",
			ap->rrep.rrep_type & RREP_ACK ? "[A] " : " ",
			ap->rrep.rrep_ps & RREP_PREFIX_MASK,
			ap->rrep.rrep_hops,
			ipaddr_string(ap->rrep.rrep_da),
			EXTRACT_32BITS(ap->rrep.rrep_ds),
			ipaddr_string(ap->rrep.rrep_oa),
			EXTRACT_32BITS(ap->rrep.rrep_life));
		if (i >= sizeof(ap->rrep) + sizeof(struct aodv_ext)) {
			aodv_extension((void *) (&ap->rrep + 1),
					length - sizeof(ap->rrep));
		}
	}
}

static void
aodv_rerr(union aodv *ap, u_int length, void *ip6
#ifndef INET6
	_U_
#endif
	)
{
	int i, j, n, trunc;
	struct rerr_unreach *dp;
#ifdef INET6
	struct rerr_unreach6 *dp6;
#endif

	i = length - offsetof(struct aodv_rerr, r);
#ifdef INET6
	if (ip6 != NULL) {
		j = sizeof(ap->rerr.r.dest6[0]);
		dp6 = &ap->rerr.r.dest6[0];
	} else
#endif
	{
		j = sizeof(ap->rerr.r.dest[0]);
		dp = &ap->rerr.r.dest[0];
	}
	n = ap->rerr.rerr_dc * j;
	printf(" rerr %s [items %d] [%d]:",
		ap->rerr.rerr_flags & RERR_NODELETE ? "[D]" : "",
		ap->rerr.rerr_dc, length);
	trunc = n - (i/j);
#ifdef INET6
	if (ip6 != NULL) {
		for (; i -= j >= 0; ++dp6) {
			printf(" {%s}(%d)", ip6addr_string(&dp6->u_da),
				EXTRACT_32BITS(dp6->u_ds));
		}
	} else
#endif
	{
		for (; i -= j >= 0; ++dp) {
			printf(" {%s}(%d)", ipaddr_string(dp->u_da),
				EXTRACT_32BITS(dp->u_ds));
		}
	}
	if (trunc)
		printf("[|rerr]");
}

void
aodv_print(const u_char *dat, u_int length, void *ip6)
{
	union aodv *ap;

	ap = (union aodv *)dat;
	if (snapend < dat) {
		printf(" [|aodv]");
		return;
	}
	if (min(length, (u_int)(snapend - dat)) < sizeof(ap->rrep_ack)) {
		printf(" [|aodv]");
		return;
	}
	printf(" aodv");

	switch (ap->rerr.rerr_type) {
	case AODV_RREQ:
		aodv_rreq(ap, dat, length, ip6);
		break;
	case AODV_RREP:
		aodv_rrep(ap, dat, length, ip6);
		break;
	case AODV_RERR:
		aodv_rerr(ap, length, ip6);
		break;
	case AODV_RREP_ACK:
		printf(" rrep-ack %d", ap->rrep_ack.ra_type);
		break;

	default:
		printf(" %d %d", ap->rreq.rreq_type, length);
	}
}
