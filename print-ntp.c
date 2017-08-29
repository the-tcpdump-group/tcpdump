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
	int ppoll:8;		/* poll value */
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

/* draft-ietf-ntp-mode-6-cmds-02 (Figure 2: Status Word Formats)
 *  0                   1
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | LI| Clock Src | Count | Code  |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        System Status Word
 *
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  Status | SEL | Count | Code  |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *         Peer Status Word
 *
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |   Error Code  |   Reserved    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *         Error Status Word
 *
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |   Reserved    | Count | Code  |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *         Clock Status Word
 */

/* Clock Src for NTP control messages */
typedef	enum {
	ClSrc_Unspec,		/* unspecified or unknown (0) */
	ClSrc_Atomic,		/* calibrated atomic clock (1) */
	ClSrc_LF,		/* LF (band 4) or LF (band 5) radio (2) */
	ClSrc_HF,		/* HF (band 7) radio (3) */
	ClSrc_UHF,		/* UHF (band 9) radio (4) */
	ClSrc_LocalNet,		/* local net e.g., DCN, TSP, DTS) (5) */
	ClSrc_NTP,		/* UDP/NTP (6) */
	ClSrc_TIME,		/* UDP/TIME (7) */
	ClSrc_MANUAL,		/* eyeball-and-wristwatch (8) */
	ClSrc_MODEM,		/* telephone modem (9) */
	ClSrc_Reserved_10	/* reserved (10) */
	/* 11-63 are reserved, also */
} Control_Clock_Src;

static const struct tok ntp_ClSrc_values[] = {
	{ ClSrc_Unspec,		"unspecified or unknown" },
	{ ClSrc_Atomic,		"atomic clock" },
	{ ClSrc_LF,		"VLF or LF radio clock" },
	{ ClSrc_HF,		"HF radio clock" },
	{ ClSrc_UHF,		"UHF radio clock" },
	{ ClSrc_LocalNet,	"local net" },
	{ ClSrc_NTP,		"UDP/NTP" },
	{ ClSrc_TIME,		"UDP/TIME" },
	{ ClSrc_MANUAL,		"eyeball-and-wristwatch" },
	{ ClSrc_MODEM,		"telephone modem" },
	{ 0, NULL }
};

/* System Event Code for NTP control messages */
typedef	enum {
	SEC_Unspec,		/* unspecified (0) */
	SEC_NoDriftFile,	/* frequency correction file not available (1) */
	SEC_FreqStep,	/* frequency correction started (freq. stepped) (2) */
	SEC_SpikeStep,	/* spike detected and ignored, starting stepout timer (3) */
	SEC_FreqTraining,	/* frequency training started (4) */
	SEC_ClockSync,		/* clock synchronized (5) */
	SEC_SysRestart,		/* system restarted (6) */
	SEC_PanicStop,	/* panic stop (required step > panic threshold) (7) */
	SEC_NoSysPeer,		/* no system peer (8) */
	SEC_LeapSecArmed,	/* leap second insertion/deletion armed (9) */
	SEC_LeapSecDisarmed,	/* leap second disarmed (10) */
	SEC_LeapSecDone,	/* leap second inserted or deleted (11) */
	SEC_ClockStep,		/* clock stepped (stepout timer expired) (12) */
	SEC_KernelDiscChanged,	/* kernel loop discipline status changed (13) */
	SEC_LeapSecTabLoaded,	/* leapseconds table loaded from file (14) */
	SEC_LeapSecTabOutdated	/* leapseconds table outdated (15) */
} Control_System_Event_Code;

static const struct tok ntp_SEC_values[] = {
	{ SEC_Unspec,			"unspecified" },
	{ SEC_NoDriftFile,		"no drift file" },
	{ SEC_FreqStep,			"frequency stepped" },
	{ SEC_SpikeStep,		"spike detected" },
	{ SEC_FreqTraining,		"frequency training started" },
	{ SEC_ClockSync,		"clock synchronized" },
	{ SEC_SysRestart,		"system restarted" },
	{ SEC_PanicStop,		"panic stop" },
	{ SEC_NoSysPeer,		"no system peer" },
	{ SEC_LeapSecArmed,		"leap second ins/del armed" },
	{ SEC_LeapSecDisarmed,		"leap second ins/del disarmed" },
	{ SEC_LeapSecDone,		"leap seconds ins/del done" },
	{ SEC_ClockStep,		"clock stepped" },
	{ SEC_KernelDiscChanged,	"kernel status changed" },
	{ SEC_LeapSecTabLoaded,		"leap seconds table loaded" },
	{ SEC_LeapSecTabOutdated,	"leap seconds table outdated" },
	{ 0, NULL }
};

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

/* Peer Status for NTP control messages */
typedef	enum {
	PSS_Configured,		/* configured (peer.config) (0) */
	PSS_AuthEnabled,	/* authentic. enabled (peer.authenable) (1) */
	PSS_AuthOK,		/* aithentication OK (peer.authentic) (2) */
	PSS_Reachable,		/* reachability OK (peer.reach != 0) (3) */
	PSS_BroadcastAssoc	/* broadcast association (4) */
} Control_Peer_Status;

static const struct tok ntp_PSS_values[] = {
	{ PSS_Configured,	"configured" },
	{ PSS_AuthEnabled,	"auth. enabled" },
	{ PSS_AuthOK,		"auth. OK" },
	{ PSS_Reachable,	"reachable" },
	{ PSS_BroadcastAssoc,	"broadcast assoc." },
	{ 0, NULL }
};

/* Peer Selection for NTP control messages */
typedef	enum {
	PSL_Rejected,		/* rejected (0) */
	PSL_DiscardIntersect,	/* discarded by intersection algorithm (1) */
	PSL_DiscardOverflow,	/* discarded by table overflow (2) */
	PSL_DiscardCluster,	/* discarded by cluster algorithm (3) */
	PSL_IncludeCombine,	/* included by combine algorithm (4) */
	PSL_Backup,		/* backup source (5) */
	PSL_SystemPeer,		/* system peer (6) */
	PSL_PPSPeer		/* PPS (pulse per second) peer (7) */
} Control_Peer_Selection;

static const struct tok ntp_PSL_values[] = {
	{ PSL_Rejected,		"rejected" },
	{ PSL_DiscardIntersect,	"discarded (intersect)" },
	{ PSL_DiscardOverflow,	"discarded (overflow)" },
	{ PSL_DiscardCluster,	"discarded (cluster)" },
	{ PSL_IncludeCombine,	"included (combine)" },
	{ PSL_Backup,		"backup source" },
	{ PSL_SystemPeer,	"system peer" },
	{ PSL_PPSPeer,		"PPS peer" },
	{ 0, NULL }
};

/* Peer Event Code for NTP control messages */
typedef	enum {
	PEC_Unspecified,	/* unspecified (0) */
	PEC_Mobilized,		/* association mobilized (1) */
	PEC_Demobilized,	/* association demobilized (2) */
	PEC_PeerUnreachable,	/* peer unreachable (3) */
	PEC_PeerReachable,	/* peer reachable (4) */
	PEC_AssocRestart,	/* association restarted or timed out (5) */
	PEC_NoReply,		/* no reply (6) */
	PEC_KoD_RATE,		/* peer rate limit exceeded (KoD RATE) (7) */
	PEC_KoD_DENY,		/* access denied (KoD DENY) (8) */
	PEC_LeapSec_Armed,	/* leap second ins/del armed by peer vote (9) */
	PEC_System_Peer,	/* became system peer (10) */
	PEC_RefclkEvent,	/* reference clock event (11) */
	PEC_AuthFailed,		/* authentication failed (12) */
	PEC_SpikeSuppressed,	/* popcorn spike suppressed (13) */
	PEC_InterleavedEntered,	/* entering interleaved mode (14) */
	PEC_InterleaveLeft	/* recovering from interleave error (15) */
} Control_Peer_Event_Code;

static const struct tok ntp_PEC_values[] = {
	{ PEC_Unspecified,		"unspecified" },
	{ PEC_Mobilized,		"association mobilized" },
	{ PEC_Demobilized,		"association demobilized" },
	{ PEC_PeerUnreachable,		"peer unreachable" },
	{ PEC_PeerReachable,		"peer reachable" },
	{ PEC_AssocRestart,		"association restarted" },
	{ PEC_NoReply,			"no reply" },
	{ PEC_KoD_RATE,			"peer rate limit exceeded" },
	{ PEC_KoD_DENY,			"access denied" },
	{ PEC_LeapSec_Armed,		"leap second ins/del armed" },
	{ PEC_System_Peer,		"system peer" },
	{ PEC_RefclkEvent,		"reference clock event" },
	{ PEC_AuthFailed,		"authentication failed" },
	{ PEC_SpikeSuppressed,		"popcorn spike suppressed" },
	{ PEC_InterleavedEntered,	"entering interleaved" },
	{ PEC_InterleaveLeft,		"recovering from interleave error" },
	{ 0, NULL }
};

/* Clock Status for NTP control messages */
typedef	enum {
	CCS_Nominal,		/* clock operating within nominals (0) */
	CCS_ReplyTimeout,	/* reply timeout (1) */
	CCS_BadReplyFormat,	/* bad reply format (2) */
	CCS_Fault,		/* hardware or software fault (3) */
	CCS_PropagationFailure,	/* propagation failure (4) */
	CCS_BadDate,		/* bad date format or value (5) */
	CCS_BadTime,		/* bad time format or value (6) */
	CCS_Reserved_7,		/* reserved (7) */
	CCS_Reserved_8,		/* reserved (8) */
	CCS_Reserved_9,		/* reserved (9) */
	CCS_Reserved_10,	/* reserved (10) */
	CCS_Reserved_11,	/* reserved (11) */
	CCS_Reserved_12,	/* reserved (12) */
	CCS_Reserved_13,	/* reserved (13) */
	CCS_Reserved_14,	/* reserved (14) */
	CCS_Reserved_15		/* reserved (15) */
} Control_Clock_Status;

static const struct tok ntp_CCS_values[] = {
	{ CCS_Nominal,			"nominal operation" },
	{ CCS_ReplyTimeout,		"reply timeout" },
	{ CCS_BadReplyFormat,		"bad reply format" },
	{ CCS_Fault,			"hardware or software fault" },
	{ CCS_PropagationFailure,	"propagation failure" },
	{ CCS_BadDate,			"bad date" },
	{ CCS_BadTime,			"bad time" },
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
	u_char version, mode;

	version = (td->status & VERSIONMASK) >> VERSIONSHIFT;
	mode = (td->status & MODEMASK) >> MODESHIFT;

	ND_TCHECK(td->stratum);
	ND_PRINT((ndo, "\n\tStratum %u (%s)",
		td->stratum,
		tok2str(ntp_stratum_values,
			(td->stratum >= 2 && td->stratum <= 15) ?
			"secondary reference" : "reserved", td->stratum)));

	/* Can't ND_TCHECK() ppoll bitfield, so check indirectly via
	 * td->stratum + 2 instead.
	 */
	ND_TCHECK2(td->stratum, 2);
	ND_PRINT((ndo, ", poll %d", td->ppoll));
	if (td->ppoll >= -32 && td->ppoll <= 32) {
		if (td->ppoll >= 0)
			ND_PRINT((ndo, " (%us)", 1U << td->ppoll));
		else
			ND_PRINT((ndo, " (1/%us)", 1U << -td->ppoll));
	} else {
		ND_PRINT((ndo, " [most likely invalid]"));
	}

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
	ND_PRINT((ndo, ", Reference-ID: %#08x", EXTRACT_32BITS(&td->refid)));
	/* Interpretation depends on stratum and NTP version: */
	/* RFC 5905 (NTPv4), section "7.3. Packet Header Variables":
	 * "If using the IPv4 address family, the identifier is the four-octet
	 * IPv4 address.  If using the IPv6 address family, it is the first
	 * four octets of the MD5 hash of the IPv6 address."
	 */
	if (td->stratum < 2) {
		if (td->stratum == 0 && version > 3 && td->refid != 0 &&
		    mode > MODE_UNSPEC && mode < MODE_CONTROL) {
			/* Kiss-of-Death (KoD) code */
			ND_PRINT((ndo, " ("));
			if (fn_printn(ndo, (const u_char *)&(td->refid), 4,
				      ndo->ndo_snapend))
				goto trunc;
			ND_PRINT((ndo, ")"));
		} else if (td->stratum == PRIM_REF) {
			/* Reference Clock Identifier */
			ND_PRINT((ndo, " ("));
			if (fn_printn(ndo, (const u_char *)&(td->refid), 4,
				      ndo->ndo_snapend))
				goto trunc;
			ND_PRINT((ndo, ")"));
		}
	} else if (version < 4) {
		/* up to NTPv3 it's the IPv4 address */
		ND_PRINT((ndo, ", (%s)", ipaddr_string(ndo, &(td->refid))));
	}

	ND_TCHECK(td->ref_timestamp);
	ND_PRINT((ndo, "\n\tReference Timestamp:  "));
	p_ntp_time(ndo, &(td->ref_timestamp));

	if (ndo->ndo_vflag > 1) {
		ND_TCHECK(td->org_timestamp);
		ND_PRINT((ndo, "\n\tOriginator Timestamp: "));
		p_ntp_time(ndo, &(td->org_timestamp));

		ND_TCHECK(td->rec_timestamp);
		ND_PRINT((ndo, "\n\tReceive Timestamp:    "));
		p_ntp_time(ndo, &(td->rec_timestamp));

		ND_TCHECK(td->xmt_timestamp);
		ND_PRINT((ndo, "\n\tTransmit Timestamp:   "));
		p_ntp_time(ndo, &(td->xmt_timestamp));

		if (ndo->ndo_vflag > 2) {
			ND_PRINT((ndo, "\n\t    Originator - Receive delta:  "));
			p_ntp_delta(ndo, &(td->org_timestamp),
				    &(td->rec_timestamp));

			ND_PRINT((ndo, "\n\t    Originator - Transmit delta: "));
			p_ntp_delta(ndo, &(td->org_timestamp),
				    &(td->xmt_timestamp));
		}
	}
	if ((sizeof(*td) - length) == 16) { 	/* Optional: key-id */
		ND_TCHECK(td->key_id);
		ND_PRINT((ndo, "\n\tKey id: %u", EXTRACT_32BITS(&td->key_id)));
	} else if ((sizeof(*td) - length) == 0) {
		/* Optional: key-id + authentication */
		ND_TCHECK(td->key_id);
		ND_PRINT((ndo, "\n\tKey id: %u", EXTRACT_32BITS(&td->key_id)));
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
 * Print NTP control message's Error Status Word
 */
static void
ntp_control_print_ESW(netdissect_options *ndo, uint16_t status,
		      const char *indent)
{
	u_char ecode, reserved;

	ecode = status >> 8;
	reserved = status & 0xff;
	switch (ndo->ndo_vflag){
	case 0:
		break;
	case 1:
		ND_PRINT((ndo, "%sErrStat=%#hx", indent, status));
		break;
	case 2:
		ND_PRINT((ndo, "%sErrStat=%#04hx (Code=%#hx, Reserved=%#hx)",
			  indent, status, ecode, reserved));
		break;
	case 3:
	default:	/* unless a higher verbosity is defined */
		ND_PRINT((ndo, "%sErrStat=%#04hx (Code=%s (%hu), Reserved=%#x)",
			  indent, status, tok2str(ntp_CES_values, "reserved(%u)",
						  ecode), ecode, reserved));
		break;
	}
}

/*
 * Print NTP control message's System Status Word
 */
static void
ntp_control_print_SSW(netdissect_options *ndo, uint16_t status,
		      const char *indent)
{
	u_char LI, clock_src, ecount, code;

	LI = (status >> 14) & 0x03;
	clock_src = (status >> 8) & 0x3f;
	ecount = (status >> 4) & 0x0f;
	code = status & 0x0f;
	
	switch (ndo->ndo_vflag){
	case 0:
		break;
	case 1:
		ND_PRINT((ndo, "%sSysStat=%#04x", indent, status));
		break;
	case 2:
		ND_PRINT((ndo, "%sSysStat=%#04x", indent, status));
		ND_PRINT((ndo, " (LI=%u, ClockSrc=%u, Count=%u, Code=%u)",
			  LI, clock_src, ecount, code));
		break;
	case 3:
	default:	/* unless a higher verbosity is defined */
		/* decode LI, Clock Source, System Event Code */
		ND_PRINT((ndo, "%sSysStat=%#04x", indent, status));
		ND_PRINT((ndo, "%s\tLI=%u (%s)", indent,
			  LI, tok2str(ntp_leapind_values, NULL, LI)));
		ND_PRINT((ndo, "%s\tClockSrc=%u (%s)", indent,
			  clock_src, tok2str(ntp_ClSrc_values, "reserved(%u)",
					     clock_src)));
		ND_PRINT((ndo, "%s\tCount=%u", indent, ecount));
		ND_PRINT((ndo, "%s\tEvent=%u (%s)", indent,
			  code, tok2str(ntp_SEC_values, NULL, code)));
		break;
	}
}

/*
 * Print NTP control message's Peer Status Word
 */
static void
ntp_control_print_PSW(netdissect_options *ndo, uint16_t status,
		      const char *indent)
{
	u_char pstat, sel, ecount, code;

	pstat = (status >> 11) & 0x1f;
	sel = (status >> 8) & 0x07;
	ecount = (status >> 4) & 0x0f;
	code = status & 0x0f;

	switch (ndo->ndo_vflag){
	case 0:
		break;
	case 1:
		ND_PRINT((ndo, "%sPeerStat=%#04x", indent, status));
		break;
	case 2:
		ND_PRINT((ndo, "%sPeerStat=%#04x", indent, status));
		ND_PRINT((ndo, " (Status=%#02x, Sel=%u, Count=%u, Code=%u)",
			  pstat, sel, ecount, code));
		break;
	case 3:
	default:	/* unless a higher verbosity is defined */
		/* decode Peer Status, Peer Selection, Peer Event Code */
		ND_PRINT((ndo, "%sPeerStat=%#04x", indent, status));
		ND_PRINT((ndo, "%s\tStatus=%#02x (%s)", indent,
			  pstat, bittok2str(ntp_PSS_values, NULL, pstat)));
		ND_PRINT((ndo, "%s\tSel=%u (%s)", indent,
			  sel, tok2str(ntp_PSL_values, NULL, sel)));
		ND_PRINT((ndo, "%s\tCount=%u", indent, ecount));
		ND_PRINT((ndo, "%s\tEvent=%u (%s)", indent,
			  code, tok2str(ntp_PEC_values, NULL, code)));
		break;
	}
}

/*
 * Print NTP control message's Clock Status Word
 */
static void
ntp_control_print_CSW(netdissect_options *ndo, uint16_t status,
		      const char *indent)
{
	u_char reserved, ecount, code;

	reserved = (status >> 8) & 0xff;
	ecount = (status >> 4) & 0x0f;
	code = status & 0x0f;

	switch (ndo->ndo_vflag){
	case 0:
		break;
	case 1:
		ND_PRINT((ndo, "%sClkStat=%#04x", indent, status));
		break;
	case 2:
		ND_PRINT((ndo, "%sClkStat=%#04x (Resvd=%u, Count=%u, Code=%u)",
			  indent, status, reserved, ecount, code));
		break;
	case 3:
	default:	/* unless a higher verbosity is defined */
		/* decode Clock Status Code */
		ND_PRINT((ndo, "%sClkStat=%#04x", indent, status));
		ND_PRINT((ndo, "%s\tReserved=%#02x", indent, reserved));
		ND_PRINT((ndo, "%s\tCount=%u", indent, ecount));
		ND_PRINT((ndo, "%s\tCode=%#02x (%s)", indent,
			  code, tok2str(ntp_CCS_values, "reserved(%u)", code)));
		break;
	}
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
	const char *indent;

	indent = "\n\t";
	ND_TCHECK(cd->control);
	R = (cd->control & 0x80) != 0;
	E = (cd->control & 0x40) != 0;
	M = (cd->control & 0x20) != 0;
	opcode = cd->control & 0x1f;
	
	if (ndo->ndo_vflag < 2) {
		ND_PRINT((ndo, "%sREM=%c%c%c, OpCode=%u", indent,
			  R ? 'R' : '_', E ? 'E' : '_', M ? 'M' : '_',
			  (unsigned)opcode));
	} else {
		ND_PRINT((ndo, "%sR=%s, E=%s, M=%s, OpCode=%s", indent,
			  R ? "Response" : "Request", E ? "Error" : "OK",
			  M ? "More" : "Last",
			  tok2str(ntp_control_op_values, NULL, opcode)));
	}

	ND_TCHECK(cd->sequence);
	sequence = EXTRACT_16BITS(&cd->sequence);
	ND_PRINT((ndo, ", Sequence=%hu", sequence));

	ND_TCHECK(cd->status);
	status = EXTRACT_16BITS(&cd->status);
	ND_PRINT((ndo, "%sStatus=%#04x", indent, status));

	ND_TCHECK(cd->assoc);
	assoc = EXTRACT_16BITS(&cd->assoc);
	ND_PRINT((ndo, ", Assoc.=%hu", assoc));

	ND_TCHECK(cd->offset);
	offset = EXTRACT_16BITS(&cd->offset);
	ND_PRINT((ndo, ", Offset=%hu", offset));

	ND_TCHECK(cd->count);
	count = EXTRACT_16BITS(&cd->count);
	ND_PRINT((ndo, ", Count=%hu", count));

	if (E) {
		ntp_control_print_ESW(ndo, status, "\n\t\t");
	} else if (opcode == OPC_Read_Vars || opcode == OPC_Read_Status ||
		   (opcode == OPC_Write_Vars && assoc != 0)) {
		if (assoc == 0) {
			/* See "3.1.  System Status Word" */
			ntp_control_print_SSW(ndo, status, "\n\t\t");
		} else {
			/* See "3.2.  Peer Status Word" */
			ntp_control_print_PSW(ndo, status, "\n\t\t");
		}
	} else if (opcode == OPC_Read_Clock_Vars ||
		   opcode == OPC_Write_Clock_Vars) {
		/* See "3.3.  Clock Status Word" */
		ntp_control_print_CSW(ndo, status, "\n\t\t");
	} else {
		ND_PRINT((ndo, ", Status=%#04hx", status));
	}

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
				ND_PRINT((ndo, "%sdata:%s    ",
					  indent, indent));
				fn_print(ndo, cd->data, ndo->ndo_snapend);
			}
			break;
		default:
			/* data is binary format */
			ND_PRINT((ndo, "%sTO-BE-DONE: data not interpreted",
				  indent));
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
	if (version < 1) {
		ND_PRINT((ndo, "NTP before version 1 or not NTP"));
		return;
	}
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
	else if (version > 1 && mode == MODE_CONTROL)
		ntp_control_print(ndo, &bp->cd, length);
	else
		ND_PRINT((ndo, ", mode==%u unexpected!", mode));
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
