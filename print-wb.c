/*
 * Copyright (c) 1993, 1994, 1995, 1996
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) all advertising materials mentioning
 * features or use of this software display the following acknowledgement:
 * ``This product includes software developed by the University of California,
 * Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
 * the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

/* \summary: White Board printer */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "netdissect-stdinc.h"

#include "netdissect.h"
#include "addrtoname.h"
#include "extract.h"


/* XXX need to add byte-swapping macros! */
/* XXX - you mean like the ones in "extract.h"? */

/*
 * Largest packet size.  Everything should fit within this space.
 * For instance, multiline objects are sent piecewise.
 */
#define MAXFRAMESIZE 1024

/*
 * Multiple drawing ops can be sent in one packet.  Each one starts on a
 * an even multiple of DOP_ALIGN bytes, which must be a power of two.
 */
#define DOP_ALIGN 4
#define DOP_ROUNDUP(x)	((((int)(x)) + (DOP_ALIGN - 1)) & ~(DOP_ALIGN - 1))
#define DOP_NEXT(d)\
	((const struct dophdr *)((const u_char *)(d) + \
				DOP_ROUNDUP(EXTRACT_BE_U_2((d)->dh_len) + sizeof(*(d)))))

/*
 * Format of the whiteboard packet header.
 * The transport level header.
 */
struct pkt_hdr {
	nd_uint32_t ph_src;	/* site id of source */
	nd_uint32_t ph_ts;	/* time stamp (for skew computation) */
	nd_uint16_t ph_version;	/* version number */
	nd_uint8_t ph_type;	/* message type */
	nd_uint8_t ph_flags;	/* message flags */
};

/* Packet types */
#define PT_DRAWOP	0	/* drawing operation */
#define PT_ID		1	/* announcement packet */
#define PT_RREQ		2	/* repair request */
#define PT_RREP		3	/* repair reply */
#define PT_KILL		4	/* terminate participation */
#define PT_PREQ         5       /* page vector request */
#define PT_PREP         7       /* page vector reply */

#ifdef PF_USER
#undef PF_USER			/* {Digital,Tru64} UNIX define this, alas */
#endif

/* flags */
#define PF_USER		0x01	/* hint that packet has interactive data */
#define PF_VIS		0x02	/* only visible ops wanted */

struct PageID {
	nd_uint32_t p_sid;		/* session id of initiator */
	nd_uint32_t p_uid;		/* page number */
};

struct dophdr {
	nd_uint32_t	dh_ts;		/* sender's timestamp */
	nd_uint16_t	dh_len;		/* body length */
	nd_uint8_t	dh_flags;
	nd_uint8_t	dh_type;	/* body type */
	/* body follows */
};
/*
 * Drawing op sub-types.
 */
#define DT_RECT         2
#define DT_LINE         3
#define DT_ML           4
#define DT_DEL          5
#define DT_XFORM        6
#define DT_ELL          7
#define DT_CHAR         8
#define DT_STR          9
#define DT_NOP          10
#define DT_PSCODE       11
#define DT_PSCOMP       12
#define DT_REF          13
#define DT_SKIP         14
#define DT_HOLE         15
#define DT_MAXTYPE      15

/*
 * A drawing operation.
 */
struct pkt_dop {
	struct PageID pd_page;	/* page that operations apply to */
	nd_uint32_t	pd_sseq;	/* start sequence number */
	nd_uint32_t	pd_eseq;	/* end sequence number */
	/* drawing ops follow */
};

/*
 * A repair request.
 */
struct pkt_rreq {
        nd_uint32_t pr_id;        /* source id of drawops to be repaired */
        struct PageID pr_page;    /* page of drawops */
        nd_uint32_t pr_sseq;      /* start seqno */
        nd_uint32_t pr_eseq;      /* end seqno */
};

/*
 * A repair reply.
 */
struct pkt_rrep {
	nd_uint32_t pr_id;	/* original site id of ops  */
	struct pkt_dop pr_dop;
	/* drawing ops follow */
};

struct id_off {
        nd_uint32_t id;
        nd_uint32_t off;
};

struct pgstate {
	nd_uint32_t slot;
	struct PageID page;
	nd_uint16_t nid;
	nd_uint16_t rsvd;
        /* seqptr's */
};

/*
 * An announcement packet.
 */
struct pkt_id {
	nd_uint32_t pi_mslot;
        struct PageID    pi_mpage;        /* current page */
	struct pgstate pi_ps;
        /* seqptr's */
        /* null-terminated site name */
};

struct pkt_preq {
        struct PageID  pp_page;
        nd_uint32_t  pp_low;
        nd_uint32_t  pp_high;
};

struct pkt_prep {
        nd_uint32_t  pp_n;           /* size of pageid array */
        /* pgstate's follow */
};

static int
wb_id(netdissect_options *ndo,
      const struct pkt_id *id, u_int len)
{
	u_int i;
	const char *cp;
	const struct id_off *io;
	char c;
	u_int nid;

	ND_PRINT(" wb-id:");
	if (len < sizeof(*id) || !ND_TTEST_SIZE(id))
		return (-1);
	len -= sizeof(*id);

	ND_PRINT(" %u/%s:%u (max %u/%s:%u) ",
	       EXTRACT_BE_U_4(id->pi_ps.slot),
	       ipaddr_string(ndo, id->pi_ps.page.p_sid),
	       EXTRACT_BE_U_4(id->pi_ps.page.p_uid),
	       EXTRACT_BE_U_4(id->pi_mslot),
	       ipaddr_string(ndo, id->pi_mpage.p_sid),
	       EXTRACT_BE_U_4(id->pi_mpage.p_uid));

	nid = EXTRACT_BE_U_2(id->pi_ps.nid);
	len -= sizeof(*io) * nid;
	io = (const struct id_off *)(id + 1);
	cp = (const char *)(io + nid);
	if (ND_TTEST_LEN(cp, len)) {
		ND_PRINT("\"");
		nd_print(ndo, (const u_char *)cp, (const u_char *)cp + len);
		ND_PRINT("\"");
	}

	c = '<';
	for (i = 0; i < nid && ND_TTEST_SIZE(io); ++io, ++i) {
		ND_PRINT("%c%s:%u",
		    c, ipaddr_string(ndo, io->id), EXTRACT_BE_U_4(io->off));
		c = ',';
	}
	if (i >= nid) {
		ND_PRINT(">");
		return (0);
	}
	return (-1);
}

static int
wb_rreq(netdissect_options *ndo,
        const struct pkt_rreq *rreq, u_int len)
{
	ND_PRINT(" wb-rreq:");
	if (len < sizeof(*rreq) || !ND_TTEST_SIZE(rreq))
		return (-1);

	ND_PRINT(" please repair %s %s:%u<%u:%u>",
	       ipaddr_string(ndo, rreq->pr_id),
	       ipaddr_string(ndo, rreq->pr_page.p_sid),
	       EXTRACT_BE_U_4(rreq->pr_page.p_uid),
	       EXTRACT_BE_U_4(rreq->pr_sseq),
	       EXTRACT_BE_U_4(rreq->pr_eseq));
	return (0);
}

static int
wb_preq(netdissect_options *ndo,
        const struct pkt_preq *preq, u_int len)
{
	ND_PRINT(" wb-preq:");
	if (len < sizeof(*preq) || !ND_TTEST_SIZE(preq))
		return (-1);

	ND_PRINT(" need %u/%s:%u",
	       EXTRACT_BE_U_4(preq->pp_low),
	       ipaddr_string(ndo, preq->pp_page.p_sid),
	       EXTRACT_BE_U_4(preq->pp_page.p_uid));
	return (0);
}

static int
wb_prep(netdissect_options *ndo,
        const struct pkt_prep *prep, u_int len)
{
	u_int n;
	const struct pgstate *ps;
	const u_char *ep = ndo->ndo_snapend;

	ND_PRINT(" wb-prep:");
	if (len < sizeof(*prep) || !ND_TTEST_SIZE(prep))
		return (-1);
	n = EXTRACT_BE_U_4(prep->pp_n);
	ps = (const struct pgstate *)(prep + 1);
	while (n != 0 && ND_TTEST_SIZE(ps)) {
		const struct id_off *io, *ie;
		char c = '<';

		ND_PRINT(" %u/%s:%u",
		    EXTRACT_BE_U_4(ps->slot),
		    ipaddr_string(ndo, ps->page.p_sid),
		    EXTRACT_BE_U_4(ps->page.p_uid));
		io = (const struct id_off *)(ps + 1);
		for (ie = io + EXTRACT_U_1(ps->nid); io < ie && ND_TTEST_SIZE(io); ++io) {
			ND_PRINT("%c%s:%u", c, ipaddr_string(ndo, io->id),
			    EXTRACT_BE_U_4(io->off));
			c = ',';
		}
		ND_PRINT(">");
		ps = (const struct pgstate *)io;
		n--;
	}
	return ((const u_char *)ps <= ep? 0 : -1);
}


static const char *dopstr[] = {
	"dop-0!",
	"dop-1!",
	"RECT",
	"LINE",
	"ML",
	"DEL",
	"XFORM",
	"ELL",
	"CHAR",
	"STR",
	"NOP",
	"PSCODE",
	"PSCOMP",
	"REF",
	"SKIP",
	"HOLE",
};

static int
wb_dops(netdissect_options *ndo, const struct pkt_dop *dop,
        uint32_t ss, uint32_t es)
{
	const struct dophdr *dh = (const struct dophdr *)((const u_char *)dop + sizeof(*dop));

	ND_PRINT(" <");
	for ( ; ss <= es; ++ss) {
		u_int t;

		if (!ND_TTEST_SIZE(dh)) {
			nd_print_trunc(ndo);
			break;
		}
		t = EXTRACT_U_1(dh->dh_type);

		if (t > DT_MAXTYPE)
			ND_PRINT(" dop-%u!", t);
		else {
			ND_PRINT(" %s", dopstr[t]);
			if (t == DT_SKIP || t == DT_HOLE) {
				uint32_t ts = EXTRACT_BE_U_4(dh->dh_ts);
				ND_PRINT("%u", ts - ss + 1);
				if (ss > ts || ts > es) {
					ND_PRINT("[|]");
					if (ts < ss)
						return (0);
				}
				ss = ts;
			}
		}
		dh = DOP_NEXT(dh);
	}
	ND_PRINT(" >");
	return (0);
}

static int
wb_rrep(netdissect_options *ndo,
        const struct pkt_rrep *rrep, u_int len)
{
	const struct pkt_dop *dop = &rrep->pr_dop;

	ND_PRINT(" wb-rrep:");
	if (len < sizeof(*rrep) || !ND_TTEST_SIZE(rrep))
		return (-1);
	len -= sizeof(*rrep);

	ND_PRINT(" for %s %s:%u<%u:%u>",
	    ipaddr_string(ndo, rrep->pr_id),
	    ipaddr_string(ndo, dop->pd_page.p_sid),
	    EXTRACT_BE_U_4(dop->pd_page.p_uid),
	    EXTRACT_BE_U_4(dop->pd_sseq),
	    EXTRACT_BE_U_4(dop->pd_eseq));

	if (ndo->ndo_vflag)
		return (wb_dops(ndo, dop,
		    EXTRACT_BE_U_4(dop->pd_sseq),
		    EXTRACT_BE_U_4(dop->pd_eseq)));
	return (0);
}

static int
wb_drawop(netdissect_options *ndo,
          const struct pkt_dop *dop, u_int len)
{
	ND_PRINT(" wb-dop:");
	if (len < sizeof(*dop) || !ND_TTEST_SIZE(dop))
		return (-1);
	len -= sizeof(*dop);

	ND_PRINT(" %s:%u<%u:%u>",
	    ipaddr_string(ndo, dop->pd_page.p_sid),
	    EXTRACT_BE_U_4(dop->pd_page.p_uid),
	    EXTRACT_BE_U_4(dop->pd_sseq),
	    EXTRACT_BE_U_4(dop->pd_eseq));

	if (ndo->ndo_vflag)
		return (wb_dops(ndo, dop,
				EXTRACT_BE_U_4(dop->pd_sseq),
				EXTRACT_BE_U_4(dop->pd_eseq)));
	return (0);
}

/*
 * Print whiteboard multicast packets.
 */
void
wb_print(netdissect_options *ndo,
         const u_char *hdr, u_int len)
{
	const struct pkt_hdr *ph;
	uint8_t type;

	ndo->ndo_protocol = "wb";
	ph = (const struct pkt_hdr *)hdr;
	if (len < sizeof(*ph) || !ND_TTEST_SIZE(ph)) {
		nd_print_trunc(ndo);
		return;
	}
	len -= sizeof(*ph);

	if (EXTRACT_U_1(ph->ph_flags))
		ND_PRINT("*");
	type = EXTRACT_U_1(ph->ph_type);
	switch (type) {

	case PT_KILL:
		ND_PRINT(" wb-kill");
		return;

	case PT_ID:
		if (wb_id(ndo, (const struct pkt_id *)(ph + 1), len) >= 0)
			return;
		nd_print_trunc(ndo);
		break;

	case PT_RREQ:
		if (wb_rreq(ndo, (const struct pkt_rreq *)(ph + 1), len) >= 0)
			return;
		nd_print_trunc(ndo);
		break;

	case PT_RREP:
		if (wb_rrep(ndo, (const struct pkt_rrep *)(ph + 1), len) >= 0)
			return;
		nd_print_trunc(ndo);
		break;

	case PT_DRAWOP:
		if (wb_drawop(ndo, (const struct pkt_dop *)(ph + 1), len) >= 0)
			return;
		nd_print_trunc(ndo);
		break;

	case PT_PREQ:
		if (wb_preq(ndo, (const struct pkt_preq *)(ph + 1), len) >= 0)
			return;
		nd_print_trunc(ndo);
		break;

	case PT_PREP:
		if (wb_prep(ndo, (const struct pkt_prep *)(ph + 1), len) >= 0)
			return;
		nd_print_trunc(ndo);
		break;

	default:
		ND_PRINT(" wb-%u!", type);
		return;
	}
}
