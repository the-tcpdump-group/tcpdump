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

static const char tstr[] = " [|ntp]";

/*
 * Based on ntp.h from the U of MD implementation
 *	This file is based on Version 2 of the NTP spec (RFC1119).
 */

/*
 *  Definitions for the masses
 */
#define	JAN_1970	INT64_T_CONSTANT(2208988800)	/* 1970 - 1900 in seconds */

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
	nd_uint32_t int_part;
	nd_uint32_t fraction;
};

struct s_fixedpt {
	nd_uint16_t int_part;
	nd_uint16_t fraction;
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

/* Length of the NTP data message with the mandatory fields ("the header")
 * and without any optional fields (extension, Key Identifier,
 * Message Digest).
 */
#define NTP_TIMEMSG_MINLEN 48U

struct ntp_time_data {
	nd_uint8_t status;		/* status of local clock and leap info */
	nd_uint8_t stratum;		/* Stratum level */
	nd_int8_t ppoll;		/* poll value */
	nd_int8_t precision;
	struct s_fixedpt root_delay;
	struct s_fixedpt root_dispersion;
	nd_uint32_t refid;
	struct l_fixedpt ref_timestamp;
	struct l_fixedpt org_timestamp;
	struct l_fixedpt rec_timestamp;
	struct l_fixedpt xmt_timestamp;
	nd_uint32_t key_id;
	nd_uint8_t  message_digest[20];
};
/*
 *	Leap Second Codes (high order two bits)
 */
#define	NO_WARNING	0x00	/* no warning */
#define	PLUS_SEC	0x01	/* add a second (61 seconds) */
#define	MINUS_SEC	0x02	/* minus a second (59 seconds) */
#define	ALARM		0x03	/* alarm condition (clock unsynchronized) */

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
static void p_poll(netdissect_options *, register const int);

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
    { NO_WARNING,     "Nominal" },
    { PLUS_SEC,       "+1s" },
    { MINUS_SEC,      "-1s" },
    { ALARM,          "clock unsync." },
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

/* Length of the NTP control message with the mandatory fields ("the header")
 * and without any optional fields (Data, Padding, Authenticator).
 */
#define NTP_CTRLMSG_MINLEN 12U

struct ntp_control_data {
	nd_uint8_t	magic;		/* LI, VN, Mode */
	nd_uint8_t	control;	/* R, E, M, OpCode */
	nd_uint16_t	sequence;	/* Sequence Number */
	nd_uint16_t	status;		/* Status */
	nd_uint16_t	assoc;		/* Association ID */
	nd_uint16_t	offset;		/* Offset */
	nd_uint16_t	count;		/* Count */
	nd_uint8_t	data[564];	/* Data, [Padding, [Authenticator]] */
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

/* draft-ietf-ntp-mode-6-cmds-02 (Figure 2: Status Word Formats)
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |   Error Code  |   Reserved    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *         Error Status Word
 */
/* Error Status for NTP control messages */
typedef	enum {
	CES_Unspec,		/* unspecified (0) */
	CES_AuthFail,		/* authentication failure (1) */
	CES_BadMessage,		/* invalid message length or format (2) */
	CES_BadOpcode,		/* invalid opcode (3) */
	CES_BadAssoc,		/* unknown association identifier (4) */
	CES_BadVar,		/* unknown variable name (5) */
	CES_BadVal,		/* invalid variable value (6) */
	CES_Prohibited		/* administratively prohibited (7) */
} Control_Error_Status;

static const struct tok ntp_CES_values[] = {
	{ CES_Unspec,		"unspecified" },
	{ CES_AuthFail,		"auth. failure" },
	{ CES_BadMessage,	"invalid message" },
	{ CES_BadOpcode,	"invalid opcode" },
	{ CES_BadAssoc,		"unknown assoc. id" },
	{ CES_BadVar,		"unknown variable" },
	{ CES_BadVal,		"invalid value" },
	{ CES_Prohibited,	"prohibited" },
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
	       register const struct ntp_time_data *bp, u_int length)
{
	if (length < NTP_TIMEMSG_MINLEN)
		goto invalid;

	ND_TCHECK(bp->stratum);
	ND_PRINT((ndo, "\n\tStratum %u (%s)",
		bp->stratum,
		tok2str(ntp_stratum_values,
			(bp->stratum >= 2 && bp->stratum <= 15) ?
			"secondary reference" : "reserved", bp->stratum)));

	ND_TCHECK(bp->ppoll);
	ND_PRINT((ndo, ", poll %d", bp->ppoll));
	p_poll(ndo, bp->ppoll);

	ND_TCHECK(bp->precision);
	ND_PRINT((ndo, ", precision %d", bp->precision));

	ND_TCHECK(bp->root_delay);
	ND_PRINT((ndo, "\n\tRoot Delay: "));
	p_sfix(ndo, &bp->root_delay);

	ND_TCHECK(bp->root_dispersion);
	ND_PRINT((ndo, ", Root dispersion: "));
	p_sfix(ndo, &bp->root_dispersion);

	ND_TCHECK(bp->refid);
	ND_PRINT((ndo, ", Reference-ID: "));
	/* Interpretation depends on stratum */
	switch (bp->stratum) {

	case UNSPECIFIED:
		ND_PRINT((ndo, "0x%08x", EXTRACT_BE_U_4(&bp->refid)));
		break;

	case PRIM_REF:
		if (fn_printn(ndo, (const u_char *)&(bp->refid), 4, ndo->ndo_snapend))
			goto trunc;
		break;

	case INFO_QUERY:
		ND_PRINT((ndo, "%s INFO_QUERY", ipaddr_string(ndo, &(bp->refid))));
		/* this doesn't have more content */
		return;

	case INFO_REPLY:
		ND_PRINT((ndo, "%s INFO_REPLY", ipaddr_string(ndo, &(bp->refid))));
		/* this is too complex to be worth printing */
		return;

	default:
		/* In NTPv4 (RFC 5905) refid is an IPv4 address or first 32 bits of
		   MD5 sum of IPv6 address */
		ND_PRINT((ndo, "0x%08x", EXTRACT_BE_U_4(&bp->refid)));
		break;
	}

	ND_TCHECK(bp->ref_timestamp);
	ND_PRINT((ndo, "\n\tReference Timestamp:  "));
	p_ntp_time(ndo, &(bp->ref_timestamp));

	if (ndo->ndo_vflag > 1) {
		ND_TCHECK(bp->org_timestamp);
		ND_PRINT((ndo, "\n\tOriginator Timestamp: "));
		p_ntp_time(ndo, &(bp->org_timestamp));

		ND_TCHECK(bp->rec_timestamp);
		ND_PRINT((ndo, "\n\tReceive Timestamp:    "));
		p_ntp_time(ndo, &(bp->rec_timestamp));

		ND_TCHECK(bp->xmt_timestamp);
		ND_PRINT((ndo, "\n\tTransmit Timestamp:   "));
		p_ntp_time(ndo, &(bp->xmt_timestamp));

		if (ndo->ndo_vflag > 2) {
			ND_PRINT((ndo, "\n\t    Originator - Receive delta:  "));
			p_ntp_delta(ndo, &(bp->org_timestamp),
				    &(bp->rec_timestamp));

			ND_PRINT((ndo, "\n\t    Originator - Transmit delta: "));
			p_ntp_delta(ndo, &(bp->org_timestamp),
				    &(bp->xmt_timestamp));
		}
	}
	if ((sizeof(*bp) - length) == 16) { 	/* Optional: key-id */
		ND_TCHECK(bp->key_id);
		ND_PRINT((ndo, "\n\tKey id: %u", EXTRACT_BE_U_4(bp->key_id)));
	} else if ((sizeof(*bp) - length) == 0) {
		/* Optional: key-id + authentication */
		ND_TCHECK(bp->key_id);
		ND_PRINT((ndo, "\n\tKey id: %u", EXTRACT_BE_U_4(bp->key_id)));
		ND_TCHECK2(bp->message_digest, sizeof (bp->message_digest));
                ND_PRINT((ndo, "\n\tAuthentication: %08x%08x%08x%08x",
        		       EXTRACT_BE_U_4(bp->message_digest),
        		       EXTRACT_BE_U_4(bp->message_digest + 4),
        		       EXTRACT_BE_U_4(bp->message_digest + 8),
        		       EXTRACT_BE_U_4(bp->message_digest + 12)));
	} else if (length == NTP_TIMEMSG_MINLEN + 4 + 20) { 	/* Optional: key-id + 160-bit digest */
		ND_TCHECK(bp->key_id);
		ND_PRINT((ndo, "\n\tKey id: %u", EXTRACT_BE_U_4(&bp->key_id)));
		ND_TCHECK2(bp->message_digest, 20);
		ND_PRINT((ndo, "\n\tAuthentication: %08x%08x%08x%08x%08x",
		               EXTRACT_BE_U_4(bp->message_digest),
		               EXTRACT_BE_U_4(bp->message_digest + 4),
		               EXTRACT_BE_U_4(bp->message_digest + 8),
		               EXTRACT_BE_U_4(bp->message_digest + 12),
		               EXTRACT_BE_U_4(bp->message_digest + 16)));
	} else if (length > NTP_TIMEMSG_MINLEN) {
		ND_PRINT((ndo, "\n\t(%u more bytes after the header)", length - NTP_TIMEMSG_MINLEN));
	}
	return;

invalid:
	ND_PRINT((ndo, " %s", istr));
	ND_TCHECK2(*bp, length);
	return;

trunc:
	ND_PRINT((ndo, " %s", tstr));
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

	if (length < NTP_CTRLMSG_MINLEN)
		goto invalid;

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
	sequence = EXTRACT_BE_U_2(&cd->sequence);
	ND_PRINT((ndo, "\tSequence=%hu", sequence));

	ND_TCHECK(cd->status);
	status = EXTRACT_BE_U_2(&cd->status);
	if (ndo->ndo_vflag > 1) {
		if (E) {
			ND_PRINT((ndo, ", Status=%s (%#hx)",
				  tok2str(ntp_CES_values, "reserved",
					  status >> 8), status));
		} else {
			/* handle these cases! */
			ND_PRINT((ndo, ", Status=%#hx", status));
		}
	} else {
		ND_PRINT((ndo, ", Status=%#hx", status));
	}

	ND_TCHECK(cd->assoc);
	assoc = EXTRACT_BE_U_2(&cd->assoc);
	ND_PRINT((ndo, ", Assoc.=%hu", assoc));

	ND_TCHECK(cd->offset);
	offset = EXTRACT_BE_U_2(&cd->offset);
	ND_PRINT((ndo, ", Offset=%hu", offset));

	ND_TCHECK(cd->count);
	count = EXTRACT_BE_U_2(&cd->count);
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
			if (ndo->ndo_vflag > 2) {
				ND_PRINT((ndo, ", data:\n\t    "));
				fn_print(ndo, cd->data, ndo->ndo_snapend);
			}
			break;
		default:
			/* data is binary format */
			ND_PRINT((ndo, "\n\tTO-BE-DONE:"
				  " data not interpreted"));
		}
	}
	return;

invalid:
	ND_PRINT((ndo, " %s", istr));
	ND_TCHECK2(*cd, length);
 	return;

trunc:
	ND_PRINT((ndo, " %s", tstr));
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
	ND_PRINT((ndo, " %s", tstr));
}

static void
p_sfix(netdissect_options *ndo,
       register const struct s_fixedpt *sfp)
{
	register int i;
	register int f;
	register double ff;

	i = EXTRACT_BE_U_2(&sfp->int_part);
	f = EXTRACT_BE_U_2(&sfp->fraction);
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
	register uint32_t i;
	register uint32_t uf;
	register uint32_t f;
	register double ff;

	i = EXTRACT_BE_U_4(&lfp->int_part);
	uf = EXTRACT_BE_U_4(&lfp->fraction);
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
	    int64_t seconds_64bit = (int64_t)i - JAN_1970;
	    time_t seconds;
	    struct tm *tm;
	    char time_buf[128];

	    seconds = (time_t)seconds_64bit;
	    if (seconds != seconds_64bit) {
		/*
		 * It doesn't fit into a time_t, so we can't hand it
		 * to gmtime.
		 */
		ND_PRINT((ndo, " (unrepresentable)"));
	    } else {
		tm = gmtime(&seconds);
		if (tm == NULL) {
		    /*
		     * gmtime() can't handle it.
		     * (Yes, that might happen with some version of
		     * Microsoft's C library.)
		     */
		    ND_PRINT((ndo, " (unrepresentable)"));
		} else {
		    /* use ISO 8601 (RFC3339) format */
		    strftime(time_buf, sizeof (time_buf), "%Y-%m-%dT%H:%M:%S", tm);
		    ND_PRINT((ndo, " (%s.%04u)", time_buf,
			      (unsigned)(ff * 10000 + 0.5)));
		}
	    }
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

	u = EXTRACT_BE_U_4(&lfp->int_part);
	ou = EXTRACT_BE_U_4(&olfp->int_part);
	uf = EXTRACT_BE_U_4(&lfp->fraction);
	ouf = EXTRACT_BE_U_4(&olfp->fraction);
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

/* Prints polling interval in log2 as seconds or fraction of second */
static void
p_poll(netdissect_options *ndo,
       register const int poll_interval)
{
	if (poll_interval <= -32 || poll_interval >= 32)
		return;

	if (poll_interval >= 0)
		ND_PRINT((ndo, " (%us)", 1U << poll_interval));
	else
		ND_PRINT((ndo, " (1/%us)", 1U << -poll_interval));
}
