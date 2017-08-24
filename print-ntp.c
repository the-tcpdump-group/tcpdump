/*
 * Copyright (c) 1990, 1991, 1992, 1993, 1994, 1995, 1996, 1997
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
 *
 *	By Jeffrey Mogul/DECWRL
 *	loosely based on print-bootp.c
 */

/* \summary: Network Time Protocol (NTP) printer */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <netdissect-stdinc.h>

#ifdef HAVE_STRFTIME
#include <time.h>
#endif

#include "netdissect.h"
#include "addrtoname.h"
#include "extract.h"

/*
 * Based on ntp.h from the U of MD implementation
 *	This file is based on Version 2 of the NTP spec (RFC1119).
 */

/*
 *  Definitions for the masses
 */
#define	JAN_1970	2208988800U	/* 1970 - 1900 in seconds */

/*
 * Structure definitions for NTP fixed point values
 *
 *    0			  1		      2			  3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |			       Integer Part			     |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |			       Fraction Part			     |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *    0			  1		      2			  3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |		  Integer Part	     |	   Fraction Part	     |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
struct l_fixedpt {
	uint32_t int_part;
	uint32_t fraction;
};

struct s_fixedpt {
	uint16_t int_part;
	uint16_t fraction;
};

/* rfc2030
 *                      1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |LI | VN  |Mode |    Stratum    |     Poll      |   Precision   |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                          Root Delay                           |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                       Root Dispersion                         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                     Reference Identifier                      |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                                                               |
 * |                   Reference Timestamp (64)                    |
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                                                               |
 * |                   Originate Timestamp (64)                    |
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                                                               |
 * |                    Receive Timestamp (64)                     |
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                                                               |
 * |                    Transmit Timestamp (64)                    |
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                 Key Identifier (optional) (32)                |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                                                               |
 * |                                                               |
 * |                 Message Digest (optional) (128)               |
 * |                                                               |
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

struct ntp_time_data {
	u_char status;		/* status of local clock and leap info */
	u_char stratum;		/* Stratum level */
	u_char ppoll;		/* poll value */
	int precision:8;
	struct s_fixedpt root_delay;
	struct s_fixedpt root_dispersion;
	uint32_t refid;
	struct l_fixedpt ref_timestamp;
	struct l_fixedpt org_timestamp;
	struct l_fixedpt rec_timestamp;
	struct l_fixedpt xmt_timestamp;
        uint32_t key_id;
        uint8_t  message_digest[16];
};
/*
 *	Leap Second Codes
 */
#define	LI_NOMINAL	0x00	/* no warning */
#define	LI_ADD_LEAP	0x01	/* add a second (61 seconds) */
#define	LI_DEL_LEAP	0x02	/* minus a second (59 seconds) */
#define	LI_ALARM	0x03	/* alarm condition (clock unsynchronized) */

/*
 *	Clock Status Bits that Encode Version
 */
#define	NTPVERSION_1	0x08
#define	VERSIONMASK	0x38
#define	VERSIONSHIFT	3
#define LEAPMASK	0xc0
#define LEAPSHIFT	6
#ifdef MODEMASK
#undef MODEMASK					/* Solaris sucks */
#endif
#define	MODEMASK	0x07
#define	MODESHIFT	0

/*
 *	Code values
 */
#define	MODE_UNSPEC	0	/* unspecified */
#define	MODE_SYM_ACT	1	/* symmetric active */
#define	MODE_SYM_PAS	2	/* symmetric passive */
#define	MODE_CLIENT	3	/* client */
#define	MODE_SERVER	4	/* server */
#define	MODE_BROADCAST	5	/* broadcast */
#define	MODE_CONTROL	6	/* control message */
#define	MODE_RES2	7	/* reserved */

/*
 *	Stratum Definitions
 */
#define	UNSPECIFIED	0
#define	PRIM_REF	1	/* radio clock */
#define	INFO_QUERY	62	/* **** THIS implementation dependent **** */
#define	INFO_REPLY	63	/* **** THIS implementation dependent **** */

static void p_sfix(netdissect_options *ndo, const struct s_fixedpt *);
static void p_ntp_time(netdissect_options *, const struct l_fixedpt *);
static void p_ntp_delta(netdissect_options *, const struct l_fixedpt *, const struct l_fixedpt *);

static const struct tok ntp_mode_values[] = {
    { MODE_UNSPEC,    "unspecified" },
    { MODE_SYM_ACT,   "symmetric active" },
    { MODE_SYM_PAS,   "symmetric passive" },
    { MODE_CLIENT,    "Client" },
    { MODE_SERVER,    "Server" },
    { MODE_BROADCAST, "Broadcast" },
    { MODE_CONTROL,   "Control Message" },
    { MODE_RES2,      "Reserved" },
    { 0, NULL }
};

static const struct tok ntp_leapind_values[] = {
    { LI_NOMINAL,     "Nominal" },
    { LI_ADD_LEAP,    "Add leap" },
    { LI_DEL_LEAP,    "Del leap" },
    { LI_ALARM,       "clock unsync." },
    { 0, NULL }
};

static const struct tok ntp_stratum_values[] = {
	{ UNSPECIFIED,	"unspecified" },
	{ PRIM_REF, 	"primary reference" },
	{ 0, NULL }
};

/* draft-ietf-ntp-mode-6-cmds-02
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |LI |  VN |Mode |R|E|M| OpCode  |       Sequence Number         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |            Status             |       Association ID          |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |            Offset             |            Count              |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                                                               |
 * /                    Data (up to 468 bytes)                     /
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Padding (optional)                         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                                                               |
 * /              Authenticator (optional, 96 bytes)               /
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *               Figure 1: NTP Control Message Header
 */
struct ntp_control_data {
	u_char		magic;		/* LI, VN, Mode */
	u_char		control;	/* R, E, M, OpCode */
	uint16_t	sequence;	/* Sequence Number */
	uint16_t	status;		/* Status */
	uint16_t	assoc;		/* Association ID */
	uint16_t	offset;		/* Offset */
	uint16_t	count;		/* Count */
	u_char		data[564];	/* Data, [Padding, [Authenticator]] */
};

/* Operation Code (OpCode) for NTP control messages */
typedef	enum {
	OPC_Reserved_0,		/* reserved (0) */
	OPC_Read_Status,	/* read status command/response (1) */
	OPC_Read_Vars,		/* read variables command/response (2) */
	OPC_Write_Vars,		/* write variables command/response (3) */
	OPC_Read_Clock_Vars,	/* read clock variables command/response (4) */
	OPC_Write_Clock_Vars,	/* write clock variables command/response (5) */
	OPC_Set_Trap,		/* set trap address/port command/response (6) */
	OPC_Trap_Response,	/* trap response (7) */
	OPC_Configuration,	/* runtime configuration command/response (8) */
	OPC_Export_Config,	/* export configuration command/response (9) */
	OPC_Get_Remote_Status,	/* retrieve remote stats command/response (10) */
	OPC_Get_List,		/* retrieve ordered list command/response (11) */
	OPC_Reserved_12,		/* reserved (12) */
	OPC_Reserved_13,		/* reserved (13) */
	OPC_Reserved_14,		/* reserved (14) */
	OPC_Reserved_15,		/* reserved (15) */
	OPC_Reserved_16,		/* reserved (16) */
	OPC_Reserved_17,		/* reserved (17) */
	OPC_Reserved_18,		/* reserved (18) */
	OPC_Reserved_19,		/* reserved (19) */
	OPC_Reserved_20,		/* reserved (20) */
	OPC_Reserved_21,		/* reserved (21) */
	OPC_Reserved_22,		/* reserved (22) */
	OPC_Reserved_23,		/* reserved (23) */
	OPC_Reserved_24,		/* reserved (24) */
	OPC_Reserved_25,		/* reserved (25) */
	OPC_Reserved_26,		/* reserved (26) */
	OPC_Reserved_27,		/* reserved (27) */
	OPC_Reserved_28,		/* reserved (28) */
	OPC_Reserved_29,		/* reserved (29) */
	OPC_Reserved_30,		/* reserved (30) */
	OPC_Request_Nonce,	/* request nonce command/response (12) */
	OPC_Unset_Trap		/* unset trap address/port command/response (31) */
} NTP_Control_OpCode;

static const struct tok ntp_control_op_values[] = {
	{ OPC_Reserved_0,		"reserved" },
	{ OPC_Read_Status,		"read status" },
	{ OPC_Read_Vars,		"read variables" },
	{ OPC_Write_Vars,		"write variables" },
	{ OPC_Read_Clock_Vars,		"read clock variables" },
	{ OPC_Write_Clock_Vars,		"write clock variables" },
	{ OPC_Set_Trap,			"set trap address/port" },
	{ OPC_Trap_Response,		"trap response (7)" },
	{ OPC_Configuration,		"runtime configuration" },
	{ OPC_Export_Config,		"export configuration" },
	{ OPC_Get_Remote_Status,	"retrieve remote stats" },
	{ OPC_Get_List,			"retrieve ordered list" },
	{ OPC_Reserved_12,		"reserved" },
	{ OPC_Reserved_13,		"reserved" },
	{ OPC_Reserved_14,		"reserved" },
	{ OPC_Reserved_15,		"reserved" },
	{ OPC_Reserved_16,		"reserved" },
	{ OPC_Reserved_17,		"reserved" },
	{ OPC_Reserved_18,		"reserved" },
	{ OPC_Reserved_19,		"reserved" },
	{ OPC_Reserved_20,		"reserved" },
	{ OPC_Reserved_21,		"reserved" },
	{ OPC_Reserved_22,		"reserved" },
	{ OPC_Reserved_23,		"reserved" },
	{ OPC_Reserved_24,		"reserved" },
	{ OPC_Reserved_25,		"reserved" },
	{ OPC_Reserved_26,		"reserved" },
	{ OPC_Reserved_27,		"reserved" },
	{ OPC_Reserved_28,		"reserved" },
	{ OPC_Reserved_29,		"reserved" },
	{ OPC_Reserved_30,		"reserved" },
	{ OPC_Request_Nonce,		"request nonce" },
	{ OPC_Unset_Trap,		"unset trap address/port" },
	{ 0, NULL }
};

union ntpdata {
	struct ntp_time_data	td;
	struct ntp_control_data	cd;
};

/*
 * Print NTP time requests and responses
 */
static void
ntp_time_print(netdissect_options *ndo,
	       register const struct ntp_time_data *td, u_int length)
{
	ND_TCHECK(td->stratum);
	ND_PRINT((ndo, "\n\tStratum %u (%s)",
		td->stratum,
		tok2str(ntp_stratum_values,
			(td->stratum >= 2 && td->stratum <= 15) ?
			"secondary reference" : "reserved", td->stratum)));

	ND_TCHECK(td->ppoll);
	ND_PRINT((ndo, ", poll %u (%us)", td->ppoll, 1 << td->ppoll));

	/* Can't ND_TCHECK td->precision bitfield, so check next field with
	 * length zero instead
	 */
	ND_TCHECK2(td->root_delay, 0);
	ND_PRINT((ndo, ", precision %d", td->precision));

	ND_TCHECK(td->root_delay);
	ND_PRINT((ndo, "\n\tRoot Delay: "));
	p_sfix(ndo, &td->root_delay);

	ND_TCHECK(td->root_dispersion);
	ND_PRINT((ndo, ", Root dispersion: "));
	p_sfix(ndo, &td->root_dispersion);

	ND_TCHECK(td->refid);
	ND_PRINT((ndo, ", Reference-ID: "));
	/* Interpretation depends on stratum */
	switch (td->stratum) {
	case UNSPECIFIED:
		ND_PRINT((ndo, "%#08x", (unsigned) td->refid));
		break;

	case PRIM_REF:
		if (fn_printn(ndo, (const u_char *)&(td->refid), 4,
			      ndo->ndo_snapend))
			goto trunc;
		break;

	case INFO_QUERY:
		ND_PRINT((ndo, "%s INFO_QUERY",
			  ipaddr_string(ndo, &(td->refid))));
		/* this doesn't have more content */
		return;

	case INFO_REPLY:
		ND_PRINT((ndo, "%s INFO_REPLY",
			  ipaddr_string(ndo, &(td->refid))));
		/* this is too complex to be worth printing */
		return;

	default:
		ND_PRINT((ndo, "%s", ipaddr_string(ndo, &(td->refid))));
		break;
	}

	ND_TCHECK(td->ref_timestamp);
	ND_PRINT((ndo, "\n\t  Reference Timestamp:  "));
	p_ntp_time(ndo, &(td->ref_timestamp));

	ND_TCHECK(td->org_timestamp);
	ND_PRINT((ndo, "\n\t  Originator Timestamp: "));
	p_ntp_time(ndo, &(td->org_timestamp));

	ND_TCHECK(td->rec_timestamp);
	ND_PRINT((ndo, "\n\t  Receive Timestamp:    "));
	p_ntp_time(ndo, &(td->rec_timestamp));

	ND_TCHECK(td->xmt_timestamp);
	ND_PRINT((ndo, "\n\t  Transmit Timestamp:   "));
	p_ntp_time(ndo, &(td->xmt_timestamp));

	ND_PRINT((ndo, "\n\t    Originator - Receive Timestamp:  "));
	p_ntp_delta(ndo, &(td->org_timestamp), &(td->rec_timestamp));

	ND_PRINT((ndo, "\n\t    Originator - Transmit Timestamp: "));
	p_ntp_delta(ndo, &(td->org_timestamp), &(td->xmt_timestamp));

	if ((sizeof(*td) - length) == 16) { 	/* Optional: key-id */
		ND_TCHECK(td->key_id);
		ND_PRINT((ndo, "\n\tKey id: %u", td->key_id));
	} else if ((sizeof(*td) - length) == 0) {
		/* Optional: key-id + authentication */
		ND_TCHECK(td->key_id);
		ND_PRINT((ndo, "\n\tKey id: %u", td->key_id));
		ND_TCHECK2(td->message_digest, sizeof (td->message_digest));
                ND_PRINT((ndo, "\n\tAuthentication: %08x%08x%08x%08x",
			  EXTRACT_32BITS(td->message_digest),
			  EXTRACT_32BITS(td->message_digest + 4),
			  EXTRACT_32BITS(td->message_digest + 8),
			  EXTRACT_32BITS(td->message_digest + 12)));
        }
	return;

trunc:
	ND_PRINT((ndo, " [|ntp]"));
}

/*
 * Print NTP control message requests and responses
 */
static void
ntp_control_print(netdissect_options *ndo,
		  register const struct ntp_control_data *cd, u_int length)
{
	u_char R, E, M, opcode;
	uint16_t sequence, status, assoc, offset, count;

	ND_TCHECK(cd->control);
	R = (cd->control & 0x80) != 0;
	E = (cd->control & 0x40) != 0;
	M = (cd->control & 0x20) != 0;
	opcode = cd->control & 0x1f;
	if (ndo->ndo_vflag < 2) {
		ND_PRINT((ndo, "\n\tREM=%c%c%c, OpCode=%u\n",
			  R ? 'R' : '_', E ? 'E' : '_', M ? 'M' : '_',
			  (unsigned)opcode));
	} else {
		ND_PRINT((ndo, "\n\t%s, %s, %s, OpCode=%s\n",
			  R ? "Response" : "Request", E ? "Error" : "OK",
			  M ? "More" : "Last",
			  tok2str(ntp_control_op_values, NULL, opcode)));
	}

	ND_TCHECK(cd->sequence);
	sequence = EXTRACT_16BITS(&cd->sequence);
	ND_PRINT((ndo, "\tSequence=%hu", sequence));

	ND_TCHECK(cd->status);
	status = EXTRACT_16BITS(&cd->status);
	ND_PRINT((ndo, ", Status=%#hx", status));

	ND_TCHECK(cd->assoc);
	assoc = EXTRACT_16BITS(&cd->assoc);
	ND_PRINT((ndo, ", Assoc.=%hu", assoc));

	ND_TCHECK(cd->offset);
	offset = EXTRACT_16BITS(&cd->offset);
	ND_PRINT((ndo, ", Offset=%hu", offset));

	ND_TCHECK(cd->count);
	count = EXTRACT_16BITS(&cd->count);
	ND_PRINT((ndo, ", Count=%hu", count));

	if ((int) (length - sizeof(*cd)) > 0)
		ND_PRINT((ndo, "\n\t%u extra octets",
			  length - (unsigned)sizeof(*cd)));
	if (count != 0) {
		ND_TCHECK2(cd->data, 1);
		switch (opcode) {
		case OPC_Read_Vars:
		case OPC_Write_Vars:
		case OPC_Read_Clock_Vars:
		case OPC_Write_Clock_Vars:
			/* data is expected to be mostly text */
			ND_PRINT((ndo, ", data:\n\t"));
			if (ndo->ndo_vflag > 2)
				fn_print(ndo, cd->data, ndo->ndo_snapend);
			break;
		default:
			/* data is binary format */
			ND_PRINT((ndo, "\n\tTO-BE-DONE:"
				  " data not interpreted"));
		}
	}
	return;

trunc:
	ND_PRINT((ndo, " [|ntp]"));
}

/*
 * Print NTP requests, handling the common VN, LI, and Mode
 */
void
ntp_print(netdissect_options *ndo,
          register const u_char *cp, u_int length)
{
	register const union ntpdata *bp = (const union ntpdata *)cp;
	int mode, version, leapind;

	ND_TCHECK(bp->td.status);

	leapind = (bp->td.status & LEAPMASK) >> LEAPSHIFT;
	version = (bp->td.status & VERSIONMASK) >> VERSIONSHIFT;
	mode = (bp->td.status & MODEMASK) >> MODESHIFT;
	if (ndo->ndo_vflag == 0) {
		ND_PRINT((ndo, "NTP LI=%u, VN=%u, Mode=%u, length=%u",
			  leapind, version, mode, length));
		return;
	}
	ND_PRINT((ndo, "NTP leap indicator=%s, Version=%u, Mode=%s, length=%u",
		  tok2str(ntp_leapind_values, "Unknown", leapind), version,
		  tok2str(ntp_mode_values, "Unknown mode", mode), length));

	if (mode >= MODE_UNSPEC && mode <= MODE_BROADCAST)
		ntp_time_print(ndo, &bp->td, length);
	else if (mode == MODE_CONTROL)
		ntp_control_print(ndo, &bp->cd, length);
	else
		ND_PRINT((ndo, ", mode==%u not implemented!", mode));
	return;

trunc:
	ND_PRINT((ndo, " [|ntp]"));
}

static void
p_sfix(netdissect_options *ndo,
       register const struct s_fixedpt *sfp)
{
	register int i;
	register int f;
	register double ff;

	i = EXTRACT_16BITS(&sfp->int_part);
	f = EXTRACT_16BITS(&sfp->fraction);
	ff = f / 65536.0;		/* shift radix point by 16 bits */
	f = (int)(ff * 1000000.0);	/* Treat fraction as parts per million */
	/* Note: The actual resolution is only about 15 microseconds */
	ND_PRINT((ndo, "%d.%06d", i, f));
}

#define	FMAXINT	(4294967296.0)	/* floating point rep. of MAXINT (32 bit) */

static void
p_ntp_time(netdissect_options *ndo,
           register const struct l_fixedpt *lfp)
{
	register int32_t i;
	register uint32_t uf;
	register uint32_t f;
	register double ff;

	i = EXTRACT_32BITS(&lfp->int_part);
	uf = EXTRACT_32BITS(&lfp->fraction);
	ff = uf;
	if (ff < 0.0)		/* some compilers are buggy */
		ff += FMAXINT;
	ff = ff / FMAXINT;			/* shift radix point by 32 bits */
	/* Note: The actual resolution is almost by a factor of 10 higher,
	 * but for practical reasons the sub-nanosecond resolution can be
	 * ignored. OK, let's round up at least...
	 */
	/* treat fraction as parts per billion */
	f = (uint32_t)(ff * 1000000000.0 + 0.5);
	ND_PRINT((ndo, "%u.%09d", i, f));

#ifdef HAVE_STRFTIME
	/*
	 * print the UTC time in human-readable format.
	 */
	if (i) {
	    time_t seconds = i - JAN_1970;
	    struct tm *tm;
	    char time_buf[128];

	    tm = gmtime(&seconds);
	    /* use ISO 8601 (RFC3339) format */
	    strftime(time_buf, sizeof (time_buf), "%Y-%m-%dT%H:%M:%S", tm);
	    ND_PRINT((ndo, " (%s.%04u)", time_buf, (unsigned)(ff * 10000 + 0.5)));
	}
#endif
}

/* Prints time difference between *lfp and *olfp */
static void
p_ntp_delta(netdissect_options *ndo,
            register const struct l_fixedpt *olfp,
            register const struct l_fixedpt *lfp)
{
	register int32_t i;
	register uint32_t u, uf;
	register uint32_t ou, ouf;
	register uint32_t f;
	register double ff;
	int signbit;

	u = EXTRACT_32BITS(&lfp->int_part);
	ou = EXTRACT_32BITS(&olfp->int_part);
	uf = EXTRACT_32BITS(&lfp->fraction);
	ouf = EXTRACT_32BITS(&olfp->fraction);
	if (ou == 0 && ouf == 0) {
		p_ntp_time(ndo, lfp);
		return;
	}

	i = u - ou;

	if (i > 0) {		/* new is definitely greater than old */
		signbit = 0;
		f = uf - ouf;
		if (ouf > uf)	/* must borrow from high-order bits */
			i -= 1;
	} else if (i < 0) {	/* new is definitely less than old */
		signbit = 1;
		f = ouf - uf;
		if (uf > ouf)	/* must carry into the high-order bits */
			i += 1;
		i = -i;
	} else {		/* int_part is zero */
		if (uf > ouf) {
			signbit = 0;
			f = uf - ouf;
		} else {
			signbit = 1;
			f = ouf - uf;
		}
	}

	ff = f;
	if (ff < 0.0)		/* some compilers are buggy */
		ff += FMAXINT;
	ff = ff / FMAXINT;		/* shift radix point by 32 bits */
	/* treat fraction as parts per billion */
	f = (uint32_t)(ff * 1000000000.0 + 0.5);
	ND_PRINT((ndo, "%s%d.%09d", signbit ? "-" : "+", i, f));
}
