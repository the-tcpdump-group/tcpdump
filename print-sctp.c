/* Copyright (c) 2001 NETLAB, Temple University
 * Copyright (c) 2001 Protocol Engineering Lab, University of Delaware
 *
 * Jerry Heinz <gheinz@astro.temple.edu>
 * John Fiore <jfiore@joda.cis.temple.edu>
 * Armando L. Caro Jr. <acaro@cis.udel.edu>
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

/* \summary: Stream Control Transmission Protocol (SCTP) printer */

#include <config.h>

#include "netdissect-stdinc.h"

#define ND_LONGJMP_FROM_TCHECK
#include "netdissect.h"
#include "addrtoname.h"
#include "extract.h"
#include "ip.h"
#include "ip6.h"

/* Definitions from:
 *
 * SCTP reference Implementation Copyright (C) 1999 Cisco And Motorola
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
 * 3. Neither the name of Cisco nor of Motorola may be used
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
 *
 * This file is part of the SCTP reference Implementation
 *
 *
 * Please send any bug reports or fixes you make to one of the following email
 * addresses:
 *
 * rstewar1@email.mot.com
 * kmorneau@cisco.com
 * qxie1@email.mot.com
 *
 * Any bugs reported given to us we will try to fix... any fixes shared will
 * be incorporated into the next SCTP release.
 */

/* The valid defines for all message
 * types know to SCTP. 0 is reserved
 */
#define SCTP_DATA		0x00
#define SCTP_INITIATION		0x01
#define SCTP_INITIATION_ACK	0x02
#define SCTP_SELECTIVE_ACK	0x03
#define SCTP_HEARTBEAT_REQUEST	0x04
#define SCTP_HEARTBEAT_ACK	0x05
#define SCTP_ABORT_ASSOCIATION	0x06
#define SCTP_SHUTDOWN		0x07
#define SCTP_SHUTDOWN_ACK	0x08
#define SCTP_OPERATION_ERR	0x09
#define SCTP_COOKIE_ECHO	0x0a
#define SCTP_COOKIE_ACK         0x0b
#define SCTP_ECN_ECHO		0x0c
#define SCTP_ECN_CWR		0x0d
#define SCTP_SHUTDOWN_COMPLETE	0x0e
#define SCTP_I_DATA		0x40
#define SCTP_ASCONF_ACK		0x80
#define SCTP_RE_CONFIG		0x82
#define SCTP_PAD_CHUNK		0x84
#define SCTP_FORWARD_CUM_TSN    0xc0
#define SCTP_ASCONF		0xc1
#define SCTP_I_FORWARD_TSN	0xc2

static const struct tok sctp_chunkid_str[] = {
	{ SCTP_DATA,              "DATA"              },
	{ SCTP_INITIATION,        "INIT"              },
	{ SCTP_INITIATION_ACK,    "INIT ACK"          },
	{ SCTP_SELECTIVE_ACK,     "SACK"              },
	{ SCTP_HEARTBEAT_REQUEST, "HB REQ"            },
	{ SCTP_HEARTBEAT_ACK,     "HB ACK"            },
	{ SCTP_ABORT_ASSOCIATION, "ABORT"             },
	{ SCTP_SHUTDOWN,          "SHUTDOWN"          },
	{ SCTP_SHUTDOWN_ACK,      "SHUTDOWN ACK"      },
	{ SCTP_OPERATION_ERR,     "OP ERR"            },
	{ SCTP_COOKIE_ECHO,       "COOKIE ECHO"       },
	{ SCTP_COOKIE_ACK,        "COOKIE ACK"        },
	{ SCTP_ECN_ECHO,          "ECN ECHO"          },
	{ SCTP_ECN_CWR,           "ECN CWR"           },
	{ SCTP_SHUTDOWN_COMPLETE, "SHUTDOWN COMPLETE" },
	{ SCTP_I_DATA,            "I-DATA"            },
	{ SCTP_RE_CONFIG,         "RE-CONFIG"         },
	{ SCTP_PAD_CHUNK,         "PAD"               },
	{ SCTP_FORWARD_CUM_TSN,   "FOR CUM TSN"       },
	{ SCTP_ASCONF,            "ASCONF"            },
	{ SCTP_ASCONF_ACK,        "ASCONF-ACK"        },
	{ SCTP_I_FORWARD_TSN,     "I-FORWARD-FSN"     },
	{ 0, NULL }
};

/* Data Chuck Specific Flags */
#define SCTP_DATA_FRAG_MASK	0x03
#define SCTP_DATA_MIDDLE_FRAG	0x00
#define SCTP_DATA_LAST_FRAG	0x01
#define SCTP_DATA_FIRST_FRAG	0x02
#define SCTP_DATA_NOT_FRAG	0x03
#define SCTP_DATA_UNORDERED	0x04
#define SCTP_DATA_SACK_IMM	0x08

/* I-Forward-TSN Specific Flag */
#define SCTP_I_FORWARD_UNORDERED 0x01

/* RE-CONFIG Parameters */
#define OUT_SSN_RESET		13
#define IN_SSN_RESET		14
#define SSN_TSN_RESET		15
#define RE_CONFIG_RES		16
#define ADD_OUT_STREAM_REQ	17
#define ADD_IN_STREAM_REQ	18

#define SCTP_ADDRMAX 60

/* ASCONF Parameters*/
/* - used in INIT/ACK chunk */
#define SET_PRI_ADDR		0xC004
#define ADAPT_LAYER_INDIC	0xC006
#define SUPPORTED_EXT		0x8008
/* - used in ASCONF param */
#define ADD_IP_ADDR		0xC001
#define DEL_IP_ADDR		0xC002
/* - used in ASCONF response */
#define ERR_CAUSE_INDIC		0xC003
#define SUCCESS_INDIC		0xC005

#define CHAN_HP 6704
#define CHAN_MP 6705
#define CHAN_LP 6706

/* the sctp common header */

struct sctpHeader{
  nd_uint16_t source;
  nd_uint16_t destination;
  nd_uint32_t verificationTag;
  nd_uint32_t adler32;
};

/* various descriptor parsers */

struct sctpChunkDesc{
  nd_uint8_t  chunkID;
  nd_uint8_t  chunkFlg;
  nd_uint16_t chunkLength;
};

struct sctpParamDesc{
  nd_uint16_t paramType;
  nd_uint16_t paramLength;
};


struct sctpRelChunkDesc{
  struct sctpChunkDesc chk;
  nd_uint32_t serialNumber;
};

struct sctpVendorSpecificParam {
  struct sctpParamDesc p;  /* type must be 0xfffe */
  nd_uint32_t vendorId;	   /* vendor ID from RFC 1700 */
  nd_uint16_t vendorSpecificType;
  nd_uint16_t vendorSpecificLen;
};


/* Structures for the control parts */



/* Sctp association init request/ack */

/* this is used for init ack, too */
struct sctpInitiation{
  nd_uint32_t initTag;			/* tag of mine */
  nd_uint32_t rcvWindowCredit;		/* rwnd */
  nd_uint16_t NumPreopenStreams;	/* OS */
  nd_uint16_t MaxInboundStreams;	/* MIS */
  nd_uint32_t initialTSN;
  /* optional param's follow in sctpParamDesc form */
};

struct sctpV4IpAddress{
  struct sctpParamDesc p;	/* type is set to SCTP_IPV4_PARAM_TYPE, len=10 */
  nd_ipv4  ipAddress;
};


struct sctpV6IpAddress{
  struct sctpParamDesc p;	/* type is set to SCTP_IPV6_PARAM_TYPE, len=22 */
  nd_ipv6  ipAddress;
};

struct sctpDNSName{
  struct sctpParamDesc param;
  nd_byte name[1];
};


struct sctpCookiePreserve{
  struct sctpParamDesc p;	/* type is set to SCTP_COOKIE_PRESERVE, len=8 */
  nd_uint32_t extraTime;
};


struct sctpTimeStamp{
  nd_uint32_t ts_sec;
  nd_uint32_t ts_usec;
};


/* this guy is for use when
 * I have a initiate message gloming the
 * things together.

 */
struct sctpUnifiedInit{
  struct sctpChunkDesc uh;
  struct sctpInitiation initm;
};

struct sctpSendableInit{
  struct sctpHeader mh;
  struct sctpUnifiedInit msg;
};


/* Selective Acknowledgement
 * has the following structure with
 * a optional amount of trailing int's
 * on the last part (based on the numberOfDesc
 * field).
 */

struct sctpSelectiveAck{
  nd_uint32_t highestConseqTSN;
  nd_uint32_t updatedRwnd;
  nd_uint16_t numberOfdesc;
  nd_uint16_t numDupTsns;
};

struct sctpSelectiveFrag{
  nd_uint16_t fragmentStart;
  nd_uint16_t fragmentEnd;
};


struct sctpUnifiedSack{
  struct sctpChunkDesc uh;
  struct sctpSelectiveAck sack;
};

/* for the abort and shutdown ACK
 * we must carry the init tag in the common header. Just the
 * common header is all that is needed with a chunk descriptor.
 */
struct sctpUnifiedAbort{
  struct sctpChunkDesc uh;
};

struct sctpUnifiedAbortLight{
  struct sctpHeader mh;
  struct sctpChunkDesc uh;
};

struct sctpUnifiedAbortHeavy{
  struct sctpHeader mh;
  struct sctpChunkDesc uh;
  nd_uint16_t causeCode;
  nd_uint16_t causeLen;
};

/* For the graceful shutdown we must carry
 * the tag (in common header)  and the highest consecutive acking value
 */
struct sctpShutdown {
  nd_uint32_t TSN_Seen;
};

struct sctpUnifiedShutdown{
  struct sctpChunkDesc uh;
  struct sctpShutdown shut;
};

/* in the unified message we add the trailing
 * stream id since it is the only message
 * that is defined as a operation error.
 */
struct sctpOpErrorCause{
  nd_uint16_t cause;
  nd_uint16_t causeLen;
};

struct sctpUnifiedOpError{
  struct sctpChunkDesc uh;
  struct sctpOpErrorCause c;
};

struct sctpUnifiedStreamError{
  struct sctpHeader mh;
  struct sctpChunkDesc uh;
  struct sctpOpErrorCause c;
  nd_uint16_t strmNum;
  nd_uint16_t reserved;
};

struct staleCookieMsg{
  struct sctpHeader mh;
  struct sctpChunkDesc uh;
  struct sctpOpErrorCause c;
  nd_uint32_t moretime;
};

/* the following is used in all sends
 * where nothing is needed except the
 * chunk/type i.e. shutdownAck Abort */

struct sctpUnifiedSingleMsg{
  struct sctpHeader mh;
  struct sctpChunkDesc uh;
};

struct sctpDataPart{
  nd_uint32_t TSN;
  nd_uint16_t streamId;
  nd_uint16_t sequence;
  nd_uint32_t payloadtype;
};

struct sctpIData{
  nd_uint32_t TSN;
  nd_uint16_t streamId;
  nd_uint16_t reserved;
  nd_uint32_t MID;
  nd_uint32_t PPID_FSN;
};

struct sctpIForward{
  nd_uint32_t new_cum_TSN;
};

struct sctpIForwardEntry{
  nd_uint16_t streamId;
  nd_uint16_t flag;
  nd_uint32_t MID;
};

/* RE-CONFIG Parameters */
struct sctpReConfigHdr{
  nd_uint16_t param_type;
  nd_uint16_t param_len;
};

struct outGoingSSNReset{
  nd_uint32_t re_config_req;
  nd_uint32_t re_config_res;
  nd_uint32_t last_assigned_TSN;
};

struct inGoingSSNReset{
  nd_uint32_t re_config_req;
};

struct reConfigRes{
  nd_uint32_t res_seq_num;
  nd_uint32_t result;
};

struct addStreamReq{
  nd_uint32_t res_seq_num;
  nd_uint16_t num_new_stream;
  nd_uint16_t reserved;
};

/* ASCONF parameters */
struct sctpAsconfParam{
  nd_uint16_t type;
  nd_uint16_t length;
  nd_uint32_t CID;
  union {
    struct sctpV4IpAddress ipv4;
    struct sctpV6IpAddress ipv6;
  } addr;
};

struct sctpAsconfParamRes{
  nd_uint16_t type;
  nd_uint16_t length;
  nd_uint32_t CID;
};

struct sctpASCONF{
  nd_uint32_t seq_num;
  union {
    struct sctpV4IpAddress ipv4;
    struct sctpV6IpAddress ipv6;
  } addr;
};

struct sctpASCONF_ACK{
  nd_uint32_t seq_num;
};

struct sctpUnifiedDatagram{
  struct sctpChunkDesc uh;
  struct sctpDataPart dp;
};

struct sctpECN_echo{
  struct sctpChunkDesc uh;
  nd_uint32_t Lowest_TSN;
};


struct sctpCWR{
  struct sctpChunkDesc uh;
  nd_uint32_t TSN_reduced_at;
};

/* RE-CONFIG Parameters */
static const struct tok RE_CONFIG_parameters[] = {
	{ OUT_SSN_RESET,	"OUT SSN RESET"	},
	{ IN_SSN_RESET,		"IN SSN RESET"	},
	{ SSN_TSN_RESET,	"SSN/TSN Reset"	},
	{ RE_CONFIG_RES,	"RESP"		},
	{ ADD_OUT_STREAM_REQ,	"ADD OUT STREAM"},
	{ ADD_IN_STREAM_REQ,	"ADD IN STREAM" },
	{ 0, NULL }
};

static const struct tok results[] = {
	{ 0,	"Success - Nothing to do"		},
	{ 1,	"Success - Performed"			},
	{ 2,	"Denied"				},
	{ 3,	"Error - Wrong SSN"			},
	{ 4,	"Error - Request already in progress"	},
	{ 5,	"Error - Bad Sequence Number"		},
	{ 6,	"In progress"				},
	{ 0, NULL }
};

/* ASCONF tokens */
static const struct tok asconfigParams[] = {
	{ SET_PRI_ADDR,         "SET PRIM ADDR"                 },
	{ ADAPT_LAYER_INDIC,    "Adaptation Layer Indication"   },
	{ SUPPORTED_EXT,        "Supported Extensions"          },
	{ ADD_IP_ADDR,          "ADD ADDR"                      },
	{ DEL_IP_ADDR,          "DEL ADDR"                      },
	{ ERR_CAUSE_INDIC,      "ERR"                           },
	{ SUCCESS_INDIC,        "SUCCESS"                       },
	{ 0, NULL }
};

static const struct tok causeCode[] = {
        { 1,    "Invalid Stream Identifier"                     },
        { 2,    "Missing Mandatory Parameter"                   },
        { 3,    "Stale Cookie Error"                            },
        { 4,    "Out of Resource"                               },
        { 5,    "Unresolvable Address"                          },
        { 6,    "Unrecognized Chunk Type"                       },
        { 7,    "Invalid Mandatory Parameter"                   },
        { 8,    "Unrecognized Parameters"                       },
        { 9,    "No User Data"                                  },
        { 10,   "Cookie Received While Shutting Down"           },
        { 11,   "Restart of an Association with New Addresses"  },
        { 12,   "User Initiated Abort"                          },
        { 13,   "Protocol Violation"                            },
	{ 0,	NULL }
};

static const struct tok ForCES_channels[] = {
	{ CHAN_HP, "ForCES HP" },
	{ CHAN_MP, "ForCES MP" },
	{ CHAN_LP, "ForCES LP" },
	{ 0, NULL }
};

/* data chunk's payload protocol identifiers */

#define SCTP_PPID_IUA 1
#define SCTP_PPID_M2UA 2
#define SCTP_PPID_M3UA 3
#define SCTP_PPID_SUA 4
#define SCTP_PPID_M2PA 5
#define SCTP_PPID_V5UA 6
#define SCTP_PPID_H248 7
#define SCTP_PPID_BICC 8
#define SCTP_PPID_TALI 9
#define SCTP_PPID_DUA 10
#define SCTP_PPID_ASAP 11
#define SCTP_PPID_ENRP 12
#define SCTP_PPID_H323 13
#define SCTP_PPID_QIPC 14
#define SCTP_PPID_SIMCO 15
#define SCTP_PPID_DDPSC 16
#define SCTP_PPID_DDPSSC 17
#define SCTP_PPID_S1AP 18
#define SCTP_PPID_RUA 19
#define SCTP_PPID_HNBAP 20
#define SCTP_PPID_FORCES_HP 21
#define SCTP_PPID_FORCES_MP 22
#define SCTP_PPID_FORCES_LP 23
#define SCTP_PPID_SBC_AP 24
#define SCTP_PPID_NBAP 25
/* 26 */
#define SCTP_PPID_X2AP 27

static const struct tok PayloadProto_idents[] = {
	{ SCTP_PPID_IUA,    "ISDN Q.921" },
	{ SCTP_PPID_M2UA,   "M2UA"   },
	{ SCTP_PPID_M3UA,   "M3UA"   },
	{ SCTP_PPID_SUA,    "SUA"    },
	{ SCTP_PPID_M2PA,   "M2PA"   },
	{ SCTP_PPID_V5UA,   "V5.2"   },
	{ SCTP_PPID_H248,   "H.248"  },
	{ SCTP_PPID_BICC,   "BICC"   },
	{ SCTP_PPID_TALI,   "TALI"   },
	{ SCTP_PPID_DUA,    "DUA"    },
	{ SCTP_PPID_ASAP,   "ASAP"   },
	{ SCTP_PPID_ENRP,   "ENRP"   },
	{ SCTP_PPID_H323,   "H.323"  },
	{ SCTP_PPID_QIPC,   "Q.IPC"  },
	{ SCTP_PPID_SIMCO,  "SIMCO"  },
	{ SCTP_PPID_DDPSC,  "DDPSC"  },
	{ SCTP_PPID_DDPSSC, "DDPSSC" },
	{ SCTP_PPID_S1AP,   "S1AP"   },
	{ SCTP_PPID_RUA,    "RUA"    },
	{ SCTP_PPID_HNBAP,  "HNBAP"  },
	{ SCTP_PPID_FORCES_HP, "ForCES HP" },
	{ SCTP_PPID_FORCES_MP, "ForCES MP" },
	{ SCTP_PPID_FORCES_LP, "ForCES LP" },
	{ SCTP_PPID_SBC_AP, "SBc-AP" },
	{ SCTP_PPID_NBAP,   "NBAP"   },
	/* 26 */
	{ SCTP_PPID_X2AP,   "X2AP"   },
	{ 0, NULL }
};


static int
isForCES_port(u_short Port)
{
	if (Port == CHAN_HP)
		return 1;
	if (Port == CHAN_MP)
		return 1;
	if (Port == CHAN_LP)
		return 1;

	return 0;
}

void
sctp_print(netdissect_options *ndo,
	   const u_char *bp,        /* beginning of sctp packet */
	   const u_char *bp2,       /* beginning of enclosing */
	   u_int sctpPacketLength)  /* sctp packet */
{
  u_int sctpPacketLengthRemaining;
  const struct sctpHeader *sctpPktHdr;
  const struct ip *ip;
  const struct ip6_hdr *ip6;
  uint8_t chunkID;
  u_short sourcePort, destPort;
  u_int chunkCount;
  const struct sctpChunkDesc *chunkDescPtr;
  const char *sep;
  int isforces = 0;

  ndo->ndo_protocol = "sctp";
  ND_ICHECKMSG_ZU("length", sctpPacketLength, <, sizeof(struct sctpHeader));
  sctpPktHdr = (const struct sctpHeader*) bp;
  ND_TCHECK_SIZE(sctpPktHdr);
  sctpPacketLengthRemaining = sctpPacketLength;

  sourcePort = GET_BE_U_2(sctpPktHdr->source);
  destPort = GET_BE_U_2(sctpPktHdr->destination);

  ip = (const struct ip *)bp2;
  if (IP_V(ip) == 6)
    ip6 = (const struct ip6_hdr *)bp2;
  else
    ip6 = NULL;

  if (ip6) {
    ND_PRINT("%s.%u > %s.%u: sctp",
      GET_IP6ADDR_STRING(ip6->ip6_src),
      sourcePort,
      GET_IP6ADDR_STRING(ip6->ip6_dst),
      destPort);
  } else {
    ND_PRINT("%s.%u > %s.%u: sctp",
      GET_IPADDR_STRING(ip->ip_src),
      sourcePort,
      GET_IPADDR_STRING(ip->ip_dst),
      destPort);
  }

  if (isForCES_port(sourcePort)) {
	 ND_PRINT("[%s]", tok2str(ForCES_channels, NULL, sourcePort));
	 isforces = 1;
  }
  if (isForCES_port(destPort)) {
	 ND_PRINT("[%s]", tok2str(ForCES_channels, NULL, destPort));
	 isforces = 1;
  }

  bp += sizeof(struct sctpHeader);
  sctpPacketLengthRemaining -= sizeof(struct sctpHeader);

  if (ndo->ndo_vflag >= 2)
    sep = "\n\t";
  else
    sep = " (";
  /* cycle through all chunks, printing information on each one */
  for (chunkCount = 0, chunkDescPtr = (const struct sctpChunkDesc *)bp;
      sctpPacketLengthRemaining != 0;
      chunkCount++)
    {
      uint16_t chunkLength, chunkLengthRemaining;
      uint16_t align;

      chunkDescPtr = (const struct sctpChunkDesc *)bp;
      if (sctpPacketLengthRemaining < sizeof(*chunkDescPtr)) {
	ND_PRINT("%s%u) [chunk descriptor cut off at end of packet]", sep, chunkCount+1);
	break;
      }
      ND_TCHECK_SIZE(chunkDescPtr);
      chunkLength = GET_BE_U_2(chunkDescPtr->chunkLength);
      if (chunkLength < sizeof(*chunkDescPtr)) {
	ND_PRINT("%s%u) [Bad chunk length %u, < size of chunk descriptor]", sep, chunkCount+1, chunkLength);
	break;
      }
      chunkLengthRemaining = chunkLength;

      align = chunkLength % 4;
      if (align != 0)
	align = 4 - align;

      if (sctpPacketLengthRemaining < align) {
	ND_PRINT("%s%u) [Bad chunk length %u, > remaining data in packet]", sep, chunkCount+1, chunkLength);
	break;
      }

      ND_TCHECK_LEN(bp, chunkLength);

      bp += sizeof(*chunkDescPtr);
      sctpPacketLengthRemaining -= sizeof(*chunkDescPtr);
      chunkLengthRemaining -= sizeof(*chunkDescPtr);

      ND_PRINT("%s%u) ", sep, chunkCount+1);
      chunkID = GET_U_1(chunkDescPtr->chunkID);
      ND_PRINT("[%s] ", tok2str(sctp_chunkid_str, "Unknown chunk type: 0x%x",
	       chunkID));
      switch (chunkID) {
	case SCTP_DATA :
	  {
	    const struct sctpDataPart *dataHdrPtr;
	    uint8_t chunkFlg;
	    uint32_t ppid;
	    uint16_t payload_size;

	    chunkFlg = GET_U_1(chunkDescPtr->chunkFlg);
	    if ((chunkFlg & SCTP_DATA_UNORDERED) == SCTP_DATA_UNORDERED)
	      ND_PRINT("(U)");

	    if ((chunkFlg & SCTP_DATA_FIRST_FRAG) == SCTP_DATA_FIRST_FRAG)
	      ND_PRINT("(B)");

	    if ((chunkFlg & SCTP_DATA_LAST_FRAG) == SCTP_DATA_LAST_FRAG)
	      ND_PRINT("(E)");

	    if( ((chunkFlg & SCTP_DATA_UNORDERED) == SCTP_DATA_UNORDERED) ||
		((chunkFlg & SCTP_DATA_FIRST_FRAG) == SCTP_DATA_FIRST_FRAG) ||
		((chunkFlg & SCTP_DATA_LAST_FRAG) == SCTP_DATA_LAST_FRAG) )
	      ND_PRINT(" ");

	    ND_ICHECKMSG_ZU("chunk length", chunkLengthRemaining, <,
			    sizeof(*dataHdrPtr));
	    dataHdrPtr=(const struct sctpDataPart*)bp;

	    ppid = GET_BE_U_4(dataHdrPtr->payloadtype);
	    ND_PRINT("[TSN: %u] ", GET_BE_U_4(dataHdrPtr->TSN));
	    ND_PRINT("[SID: %u] ", GET_BE_U_2(dataHdrPtr->streamId));
	    ND_PRINT("[SSEQ %u] ", GET_BE_U_2(dataHdrPtr->sequence));
	    ND_PRINT("[PPID %s] ",
		    tok2str(PayloadProto_idents, "0x%x", ppid));

	    if (!isforces) {
		isforces = (ppid == SCTP_PPID_FORCES_HP) ||
		    (ppid == SCTP_PPID_FORCES_MP) ||
		    (ppid == SCTP_PPID_FORCES_LP);
	    }

	    bp += sizeof(*dataHdrPtr);
	    sctpPacketLengthRemaining -= sizeof(*dataHdrPtr);
	    chunkLengthRemaining -= sizeof(*dataHdrPtr);
	    ND_ICHECKMSG_U("chunk length", chunkLengthRemaining, ==, 0);
	    payload_size = chunkLengthRemaining;

	    if (isforces) {
		forces_print(ndo, bp, payload_size);
		/* ndo_protocol reassignment after forces_print() call */
		ndo->ndo_protocol = "sctp";
	    } else if (ndo->ndo_vflag >= 2) {	/* if verbose output is specified */
					/* at the command line */
		switch (ppid) {
		case SCTP_PPID_M3UA :
			m3ua_print(ndo, bp, payload_size);
			/* ndo_protocol reassignment after m3ua_print() call */
			ndo->ndo_protocol = "sctp";
			break;
		default:
			ND_PRINT("[Payload");
			if (!ndo->ndo_suppress_default_print) {
				ND_PRINT(":");
				ND_DEFAULTPRINT(bp, payload_size);
			}
			ND_PRINT("]");
			break;
		}
	    }
	    bp += payload_size;
	    sctpPacketLengthRemaining -= payload_size;
	    chunkLengthRemaining -= payload_size;
	    break;
	  }
	case SCTP_I_DATA :
	  {
	    const struct sctpIData *dataHdrPtr;
	    int Bbit = FALSE;
	    uint8_t chunkFlg;
	    uint32_t ppid_fsn;
	    uint16_t payload_size;

	    chunkFlg = GET_U_1(chunkDescPtr->chunkFlg);
	    if ((chunkFlg & SCTP_DATA_SACK_IMM) == SCTP_DATA_SACK_IMM)
		ND_PRINT("(I)");

	    if ((chunkFlg & SCTP_DATA_UNORDERED) == SCTP_DATA_UNORDERED)
		ND_PRINT("(U)");

	    if ((chunkFlg & SCTP_DATA_FIRST_FRAG) == SCTP_DATA_FIRST_FRAG) {
		ND_PRINT("(B)");
		Bbit = TRUE;
	    }

	    if ((chunkFlg & SCTP_DATA_LAST_FRAG) == SCTP_DATA_LAST_FRAG)
		ND_PRINT("(E)");

	    if (((chunkFlg & SCTP_DATA_UNORDERED) == SCTP_DATA_UNORDERED)   ||
		((chunkFlg & SCTP_DATA_FIRST_FRAG) == SCTP_DATA_FIRST_FRAG) ||
		((chunkFlg & SCTP_DATA_LAST_FRAG) == SCTP_DATA_LAST_FRAG)   ||
		((chunkFlg & SCTP_DATA_SACK_IMM) == SCTP_DATA_SACK_IMM))
		ND_PRINT(" ");

	    ND_ICHECKMSG_ZU("chunk length", chunkLengthRemaining, <, sizeof(*dataHdrPtr));
	    dataHdrPtr = (const struct sctpIData*)bp;

	    ppid_fsn = GET_BE_U_4(dataHdrPtr->PPID_FSN);
	    ND_PRINT("[TSN: %u] ", GET_BE_U_4(dataHdrPtr->TSN));
	    ND_PRINT("[SID: %u] ", GET_BE_U_2(dataHdrPtr->streamId));
	    ND_PRINT("[MID: %u] ", GET_BE_U_4(dataHdrPtr->MID));
	    if (FALSE == Bbit) { /* print FSN if B bit is NOT set */
		ND_PRINT("[FSN: %u] ", ppid_fsn);
	    } else {             /* print PPID if B bit is set */
		ND_PRINT("[PPID %s] ", tok2str(PayloadProto_idents, "0x%x", ppid_fsn));
	    }

	    bp += sizeof(*dataHdrPtr);
	    sctpPacketLengthRemaining -= sizeof(*dataHdrPtr);
	    chunkLengthRemaining -= sizeof(*dataHdrPtr);
	    ND_ICHECKMSG_U("chunk length", chunkLengthRemaining, ==, 0);
	    payload_size = chunkLengthRemaining;

	    if (FALSE == Bbit) {
		if (ndo->ndo_vflag >= 2) {
		    ND_PRINT("[Payload");
			if (!ndo->ndo_suppress_default_print) {
			    ND_PRINT(": ");
			    ND_DEFAULTPRINT(bp, payload_size);
			}
		    ND_PRINT("]");
		}

		bp += payload_size;
		sctpPacketLengthRemaining -= payload_size;
		chunkLengthRemaining -= payload_size;

		/* do not parse ppid and check for CES when B bit is not set */
		break;
	    }

	    if (!isforces) {
		isforces = (ppid_fsn == SCTP_PPID_FORCES_HP) ||
			   (ppid_fsn == SCTP_PPID_FORCES_MP) ||
			   (ppid_fsn == SCTP_PPID_FORCES_LP);
	    }

	    if (isforces) {
		forces_print(ndo, bp, payload_size);
		ndo->ndo_protocol = "sctp";
	    } else if (ndo->ndo_vflag >= 2) {
		switch (ppid_fsn) {
		case SCTP_PPID_M3UA:
		    m3ua_print(ndo, bp, payload_size);
		    ndo->ndo_protocol = "sctp";
		    break;
		default:
		    ND_PRINT("[Payload");
		    if (!ndo->ndo_suppress_default_print) {
			ND_PRINT(":");
			ND_DEFAULTPRINT(bp, payload_size);
		    }
		    ND_PRINT("]");
		    break;
		}
	    }

	    bp += payload_size;
	    sctpPacketLengthRemaining -= payload_size;
	    chunkLengthRemaining -= payload_size;
	    break;
	  }
	case SCTP_I_FORWARD_TSN:
	  {
	    const struct sctpIForward *dataHdrPtr;
	    const struct sctpIForwardEntry *entry;
	    const size_t entry_len = sizeof(struct sctpIForwardEntry);

	    ND_ICHECKMSG_ZU("chunk length", chunkLengthRemaining, <, sizeof(*dataHdrPtr));
	    dataHdrPtr = (const struct sctpIForward*)bp;
	    ND_PRINT("[TSN: %u] ", GET_BE_U_4(dataHdrPtr->new_cum_TSN));

	    bp += sizeof(*dataHdrPtr);
	    sctpPacketLengthRemaining -= sizeof(*dataHdrPtr);
	    chunkLengthRemaining -= sizeof(*dataHdrPtr);

	    if (ndo->ndo_vflag >= 2) {
		while (entry_len <= chunkLengthRemaining) {
		    entry = (const struct sctpIForwardEntry*)bp;

		    ND_PRINT("[SID: %u] ", GET_BE_U_2(entry->streamId));
		    if ((GET_BE_U_2(entry->flag) & SCTP_I_FORWARD_UNORDERED))
			ND_PRINT("(U)");	/* if U bit is set */
		    ND_PRINT("[MID: %u] ", GET_BE_U_4(entry->MID));

		    chunkLengthRemaining -= entry_len;
		    sctpPacketLengthRemaining -= entry_len;
		    bp += entry_len;
		}
	    }

	    bp += chunkLengthRemaining;
	    sctpPacketLengthRemaining -= chunkLengthRemaining;
	    chunkLengthRemaining = 0;
	    break;
	  }
	case SCTP_INITIATION :
	  {
	    const struct sctpInitiation *init;

	    ND_ICHECKMSG_ZU("chunk length", chunkLengthRemaining, <,
			    sizeof(*init));
	    init=(const struct sctpInitiation*)bp;
	    ND_PRINT("[init tag: %u] ", GET_BE_U_4(init->initTag));
	    ND_PRINT("[rwnd: %u] ", GET_BE_U_4(init->rcvWindowCredit));
	    ND_PRINT("[OS: %u] ", GET_BE_U_2(init->NumPreopenStreams));
	    ND_PRINT("[MIS: %u] ", GET_BE_U_2(init->MaxInboundStreams));
	    ND_PRINT("[init TSN: %u] ", GET_BE_U_4(init->initialTSN));
	    bp += sizeof(*init);
	    sctpPacketLengthRemaining -= sizeof(*init);
	    chunkLengthRemaining -= sizeof(*init);

#if 0 /* ALC you can add code for optional params here */
	    if( chunkLengthRemaining != 0 )
	      ND_PRINT(" @@@@@ UNFINISHED @@@@@@%s\n",
		     "Optional params present, but not printed.");
#endif
	    bp += chunkLengthRemaining;
	    sctpPacketLengthRemaining -= chunkLengthRemaining;
	    chunkLengthRemaining = 0;
	    break;
	  }
	case SCTP_INITIATION_ACK :
	  {
	    const struct sctpInitiation *init;

	    ND_ICHECKMSG_ZU("chunk length", chunkLengthRemaining, <,
			    sizeof(*init));
	    init=(const struct sctpInitiation*)bp;
	    ND_PRINT("[init tag: %u] ", GET_BE_U_4(init->initTag));
	    ND_PRINT("[rwnd: %u] ", GET_BE_U_4(init->rcvWindowCredit));
	    ND_PRINT("[OS: %u] ", GET_BE_U_2(init->NumPreopenStreams));
	    ND_PRINT("[MIS: %u] ", GET_BE_U_2(init->MaxInboundStreams));
	    ND_PRINT("[init TSN: %u] ", GET_BE_U_4(init->initialTSN));
	    bp += sizeof(*init);
	    sctpPacketLengthRemaining -= sizeof(*init);
	    chunkLengthRemaining -= sizeof(*init);

#if 0 /* ALC you can add code for optional params here */
	    if( chunkLengthRemaining != 0 )
	      ND_PRINT(" @@@@@ UNFINISHED @@@@@@%s\n",
		     "Optional params present, but not printed.");
#endif
	    bp += chunkLengthRemaining;
	    sctpPacketLengthRemaining -= chunkLengthRemaining;
	    chunkLengthRemaining = 0;
	    break;
	  }
	case SCTP_SELECTIVE_ACK:
	  {
	    const struct sctpSelectiveAck *sack;
	    const struct sctpSelectiveFrag *frag;
	    u_int fragNo, tsnNo;
	    const u_char *dupTSN;

	    ND_ICHECKMSG_ZU("chunk length", chunkLengthRemaining, <,
			    sizeof(*sack));
	    sack=(const struct sctpSelectiveAck*)bp;
	    ND_PRINT("[cum ack %u] ", GET_BE_U_4(sack->highestConseqTSN));
	    ND_PRINT("[a_rwnd %u] ", GET_BE_U_4(sack->updatedRwnd));
	    ND_PRINT("[#gap acks %u] ", GET_BE_U_2(sack->numberOfdesc));
	    ND_PRINT("[#dup tsns %u] ", GET_BE_U_2(sack->numDupTsns));
	    bp += sizeof(*sack);
	    sctpPacketLengthRemaining -= sizeof(*sack);
	    chunkLengthRemaining -= sizeof(*sack);


	    /* print gaps */
	    for (fragNo=0;
		 chunkLengthRemaining != 0 && fragNo < GET_BE_U_2(sack->numberOfdesc);
		 bp += sizeof(*frag), sctpPacketLengthRemaining -= sizeof(*frag), chunkLengthRemaining -= sizeof(*frag), fragNo++) {
	      ND_ICHECKMSG_ZU("chunk length", chunkLengthRemaining, <,
			    sizeof(*frag));
	      frag = (const struct sctpSelectiveFrag *)bp;
	      ND_PRINT("\n\t\t[gap ack block #%u: start = %u, end = %u] ",
		     fragNo+1,
		     GET_BE_U_4(sack->highestConseqTSN) + GET_BE_U_2(frag->fragmentStart),
		     GET_BE_U_4(sack->highestConseqTSN) + GET_BE_U_2(frag->fragmentEnd));
	    }

	    /* print duplicate TSNs */
	    for (tsnNo=0;
		 chunkLengthRemaining != 0 && tsnNo<GET_BE_U_2(sack->numDupTsns);
		 bp += 4, sctpPacketLengthRemaining -= 4, chunkLengthRemaining -= 4, tsnNo++) {
	      ND_ICHECKMSG_U("chunk length", chunkLengthRemaining, <, 4);
	      dupTSN = (const u_char *)bp;
	      ND_PRINT("\n\t\t[dup TSN #%u: %u] ", tsnNo+1,
		       GET_BE_U_4(dupTSN));
	    }
	    break;
	  }
	case SCTP_RE_CONFIG:
	  {
	    const struct sctpReConfigHdr *param;
	    uint16_t param_len, type;
	    uint8_t padding_len;

	    sctpPacketLengthRemaining -= chunkLengthRemaining;

	    /* it's a padding if the remaining length is less than 4 */
	    while (chunkLengthRemaining >= sizeof(uint32_t)) {

		ND_ICHECKMSG_ZU("chunk length", chunkLengthRemaining, <, sizeof(*param));
		param = (const struct sctpReConfigHdr*)bp;
		type = GET_BE_U_2(param->param_type);
		param_len = GET_BE_U_2(param->param_len);
		padding_len = ((param_len+3) &~ 3) - param_len;
		ND_ICHECKMSG_ZU("parameter length", param_len, <, sizeof(*param));

		ND_PRINT("[%s", tok2str(RE_CONFIG_parameters, NULL, type));

		param_len -= sizeof(*param);
		chunkLengthRemaining -= sizeof(*param);
		bp += sizeof(*param);

		ND_ICHECKMSG_U("chunk length", chunkLengthRemaining, <, param_len);

		/* if verbose level < 2, stop and skip */
		if (ndo->ndo_vflag < 2) {
		    ND_PRINT("]");

		    bp += param_len;
		    chunkLengthRemaining -= param_len;
		    /* skipping the parameter padding if there are more
		     * parameters in the remaining length */
		    if (chunkLengthRemaining > sizeof(uint32_t)) {
			bp += padding_len;
			chunkLengthRemaining -= padding_len;
		    }

		    continue;
		}

		switch (type) {
		case OUT_SSN_RESET:
		  {
		    uint16_t stream_num = 0;
		    const struct outGoingSSNReset *content;

		    ND_ICHECKMSG_ZU("parameter length", param_len, <, sizeof(*content));

		    content = (const struct outGoingSSNReset*) bp;
		    ND_PRINT(": REQ SEQ: %u, ", GET_BE_U_4(content->re_config_req));
		    ND_PRINT("RES SEQ: %u, ", GET_BE_U_4(content->re_config_res));
		    ND_PRINT("Last TSN: %u, ", GET_BE_U_4(content->last_assigned_TSN));

		    bp += sizeof(*content);
		    param_len -= sizeof(*content);
		    chunkLengthRemaining -= sizeof(*content);

		    ND_PRINT("SID");
		    while (param_len > 0) {
			ND_ICHECKMSG_ZU("chunk length", chunkLengthRemaining, <, sizeof(stream_num));
			ND_ICHECKMSG_ZU("parameter length", param_len , <, sizeof(stream_num));
			stream_num = GET_BE_U_2(bp);
			ND_PRINT(" %u", stream_num);

			bp += sizeof(stream_num);
			param_len -= sizeof(stream_num);
			chunkLengthRemaining -= sizeof(stream_num);
		    }
		    ND_PRINT("]");

		    break;
		  }
		case IN_SSN_RESET:
		  {
		    uint16_t stream_num = 0;
		    const struct inGoingSSNReset *content;

		    ND_ICHECKMSG_ZU("parameter length", param_len , <, sizeof(*content));

		    content = (const struct inGoingSSNReset*) bp;
		    ND_PRINT(": REQ SEQ: %u, ", GET_BE_U_4(content->re_config_req));

		    bp += sizeof(*content);
		    param_len -= sizeof(*content);
		    chunkLengthRemaining -= sizeof(*content);

		    ND_PRINT("SID");
		    while (param_len > 0) {
			ND_ICHECKMSG_ZU("parameter length", param_len , <, sizeof(stream_num));
			stream_num = GET_BE_U_2(bp);
			ND_PRINT(" %u", stream_num);

			bp += sizeof(stream_num);
			param_len -= sizeof(stream_num);
			chunkLengthRemaining -= sizeof(stream_num);
		    }
		    ND_PRINT("]");

		    break;
		  }
		case SSN_TSN_RESET:
		  {
		    /* reuse inGoingSSNReset struct as their structure are the same*/
		    const struct inGoingSSNReset *content;

		    ND_ICHECKMSG_ZU("parameter length", param_len, <, sizeof(*content));

		    content = (const struct inGoingSSNReset*) bp;
		    ND_PRINT(": REQ SEQ: %u]", GET_BE_U_4(content->re_config_req));

		    bp += sizeof(*content);
		    chunkLengthRemaining -= sizeof(*content);

		    break;
		  }
		case RE_CONFIG_RES:
		  {
		    uint32_t optional = 0;
		    const size_t optional_size = sizeof(optional);
		    const struct reConfigRes *content;

		    ND_ICHECKMSG_ZU("parameter length", param_len, <, sizeof(*content));

		    content = (const struct reConfigRes*) bp;
		    ND_PRINT(": REQ SEQ: %u, ", GET_BE_U_4(content->res_seq_num));
		    ND_PRINT("REQ: %s", tok2str(results, NULL, GET_BE_U_4(content->result)));

		    bp += sizeof(*content);
		    param_len -= sizeof(*content);
		    chunkLengthRemaining -= sizeof(*content);

		    if (0 == param_len) {
			ND_PRINT("]");
			break;
		    }

		    /* either both or none must be present */
		    ND_ICHECKMSG_ZU("parameter length", param_len, <, 2*optional_size);
		    optional = GET_BE_U_4(bp);
		    ND_PRINT(", Sender's TSN: %u", optional);

		    bp += optional_size;
		    param_len -= optional_size;
		    chunkLengthRemaining -= optional_size;

		    optional = GET_BE_U_4(bp);
		    ND_PRINT(", Receiver's Next TSN: %u] ", optional);

		    bp += optional_size;
		    chunkLengthRemaining -= optional_size;

		    break;
		  }
		case ADD_OUT_STREAM_REQ:
		case ADD_IN_STREAM_REQ:
		  {
		    const struct addStreamReq *content;

		    ND_ICHECKMSG_ZU("parameter length", param_len, <, sizeof(*content));

		    content = (const struct addStreamReq*) bp;
		    ND_PRINT(": REQ SEQ: %u, ", GET_BE_U_4(content->res_seq_num));
		    ND_PRINT("No. of new streams: %u] ", GET_BE_U_2(content->num_new_stream));

		    bp += sizeof(*content);
		    chunkLengthRemaining -= sizeof(*content);

		    break;
		  }
		default:
		  {
		    bp += chunkLengthRemaining;
		    chunkLengthRemaining = 0;
		    break;
		  }
		}
		/* skipping the parameter padding if there are more parameters
		 * in the remaining length */
		if (chunkLengthRemaining > sizeof(uint32_t)) {
		    bp += padding_len;
		    chunkLengthRemaining -= padding_len;
		}
	    }
	    bp += chunkLengthRemaining;
	    chunkLengthRemaining = 0;

	    break;
	  }
	case SCTP_ASCONF:
	  {
	    const struct sctpASCONF *content;
	    const struct sctpAsconfParam *param;
	    size_t length;
	    uint16_t param_len;

	    /* Should be at least longer than the length of IPv4 typed parameter*/
	    length = sizeof(nd_uint32_t) + sizeof(struct sctpV4IpAddress);
	    ND_ICHECKMSG_ZU("chunk length", chunkLengthRemaining, <, length);
	    content = (const struct sctpASCONF*) bp;
	    ND_PRINT("[SEQ: %u, ", GET_BE_U_4(content->seq_num));

	    if (GET_BE_U_2(content->addr.ipv4.p.paramType) == 5) {		/* IPv4 */
		ND_ICHECKMSG_ZU("chunk length", chunkLengthRemaining, <, length);
		ND_PRINT("ADDR: %s] ", GET_IPADDR_STRING(content->addr.ipv4.ipAddress));
	    } else if (GET_BE_U_2(content->addr.ipv6.p.paramType) == 6) {	/* IPv6 */
		length = sizeof(nd_uint32_t) + sizeof(struct sctpV6IpAddress);
		ND_ICHECKMSG_ZU("chunk length", chunkLengthRemaining, <, length);
		ND_PRINT("ADDR: %s] ", GET_IP6ADDR_STRING(content->addr.ipv6.ipAddress));
	    } else {
		length = sizeof(nd_uint32_t) + GET_BE_U_2(content->addr.ipv4.p.paramLength);
		ND_ICHECKMSG_ZU("chunk length", chunkLengthRemaining, <, length);
		ND_PRINT("ADDR: bogus address type]");
	    }
	    bp += length;
	    chunkLengthRemaining -= length;
	    sctpPacketLengthRemaining -= length;

	    while (0 != chunkLengthRemaining) {
		ND_ICHECKMSG_ZU("chunk length", chunkLengthRemaining, <, sizeof(uint32_t)); /* ensure param_len can be extracted */
		param = (const struct sctpAsconfParam*) bp;
		param_len = GET_BE_U_2(param->length);
		ND_ICHECKMSG_ZU("parameter length", param_len, <, sizeof(uint16_t));

		ND_ICHECKMSG_U("chunk length", chunkLengthRemaining, <, param_len);
		bp += param_len;
		chunkLengthRemaining -= param_len;
		sctpPacketLengthRemaining -= param_len;

		ND_PRINT("[%s", tok2str(asconfigParams, NULL, GET_BE_U_2(param->type)));

		if (ndo->ndo_vflag >= 2) {
		    ND_PRINT(": C-ID: %u, ", GET_BE_U_4(param->CID));
		    if (GET_BE_U_2(param->addr.ipv4.p.paramType) == 5) {	/* IPv4 */
			length = sizeof(nd_uint32_t) + sizeof(struct sctpV4IpAddress);
			ND_ICHECKMSG_ZU("param length", param_len, <, length);
			ND_PRINT("ADDR: %s] ", GET_IPADDR_STRING(param->addr.ipv4.ipAddress));
		    } else if (GET_BE_U_2(param->addr.ipv4.p.paramType) == 6) {	/* IPv6 */
			length = sizeof(nd_uint32_t) + sizeof(struct sctpV6IpAddress);
			ND_ICHECKMSG_ZU("param length", param_len, <, length);
			ND_PRINT("ADDR: %s] ", GET_IP6ADDR_STRING(param->addr.ipv6.ipAddress));
		    } else {
			ND_PRINT("ADDR: bogus address type]");
		    }
		} else {
		    ND_PRINT("]");
		}
	    }
	    break;
	  }
	case SCTP_ASCONF_ACK:
	  {
	    const struct sctpASCONF_ACK *content;
	    const struct sctpAsconfParamRes *param;
	    uint16_t param_len;

	    ND_ICHECKMSG_ZU("chunk length", chunkLengthRemaining, <, sizeof(*content));
	    content  = (const struct sctpASCONF_ACK*) bp;
	    ND_PRINT("[SEQ: %u] ", GET_BE_U_4(content->seq_num));

	    bp += sizeof(*content);
	    chunkLengthRemaining -= sizeof(*content);
	    sctpPacketLengthRemaining -= sizeof(*content);

	    while (0 != chunkLengthRemaining) {
		ND_ICHECKMSG_ZU("chunk length", chunkLengthRemaining, <, sizeof(struct sctpAsconfParamRes));
		param = (const struct sctpAsconfParamRes*) bp;
		param_len = GET_BE_U_2(param->length);
		ND_ICHECKMSG_ZU("parameter length", param_len, <, sizeof(struct sctpAsconfParamRes));
		ND_ICHECKMSG_U("chunk length", chunkLengthRemaining, <, param_len);

		ND_PRINT("[%s", tok2str(asconfigParams, NULL, GET_BE_U_2(param->type)));
		sctpPacketLengthRemaining -= param_len;

		/* print payload only when vflag >= 2 */
		if (ndo->ndo_vflag < 2) {
		    ND_PRINT("] ");
		    bp += param_len;
		    chunkLengthRemaining -= param_len;
		    continue;
		}

		switch (GET_BE_U_2(param->type)) {
		case ERR_CAUSE_INDIC:
		  {
		    uint16_t cause_len;
		    const struct sctpOpErrorCause *err_cause;

		    ND_PRINT(": C-ID: %u ", GET_BE_U_4(param->CID));
		    bp += sizeof(struct sctpAsconfParamRes);
		    param_len -= sizeof(struct sctpAsconfParamRes);
		    chunkLengthRemaining -= sizeof(struct sctpAsconfParamRes);
		    if (0 == param_len) {
			ND_PRINT("] ");
			break;
		    }

		    /* check against ERROR length */
		    ND_ICHECKMSG_ZU("chunk length", param_len, <, sizeof(uint32_t));
		    bp += sizeof(uint16_t);
		    ND_ICHECKMSG_U("param length", param_len, <, GET_BE_U_2(bp));
		    bp += sizeof(uint16_t);
		    param_len -= sizeof(uint32_t);
		    chunkLengthRemaining -= sizeof(uint32_t);

		    while (0 != param_len) {
			ND_ICHECKMSG_ZU("param length", param_len, <, sizeof(*err_cause));
			err_cause = (const struct sctpOpErrorCause*) bp;
			cause_len = GET_BE_U_2(err_cause->causeLen);
			ND_ICHECKMSG_U("cause length", cause_len, >, param_len);
			ND_ICHECKMSG_ZU("cause length", cause_len, <, sizeof(*err_cause));
			ND_PRINT("%s, ", tok2str(causeCode, NULL, GET_BE_U_2(err_cause->cause)));

			bp += cause_len;
			param_len -= cause_len;
			chunkLengthRemaining -= cause_len;
		    }
		    ND_PRINT("] ");
		    break;
		  }
		case SUCCESS_INDIC:
		  {
		    ND_PRINT(": C-ID: %u ", GET_BE_U_4(param->CID));
		    bp += sizeof(struct sctpAsconfParamRes);
		    param_len -= sizeof(struct sctpAsconfParamRes);
		    chunkLengthRemaining -= sizeof(struct sctpAsconfParamRes);
		    break;
		  }
		default:
		  {
		    ND_PRINT("Unknown parameter] ");
		    bp += param_len;
		    chunkLengthRemaining -= param_len;
		    param_len -= param_len;
		    break;
		  }
		}
	    }
	    break;
	  }
	default :
	  {
	    bp += chunkLengthRemaining;
	    sctpPacketLengthRemaining -= chunkLengthRemaining;
	    chunkLengthRemaining = 0;
	    break;
	  }
	}

      /*
       * Any extra stuff at the end of the chunk?
       * XXX - report this?
       */
      bp += chunkLengthRemaining;
      sctpPacketLengthRemaining -= chunkLengthRemaining;

      if (ndo->ndo_vflag < 2)
	sep = ", (";

      if (align != 0) {
	/*
	 * Fail if the alignment padding isn't in the captured data.
	 * Otherwise, skip it.
	 */
	ND_TCHECK_LEN(bp, align);
	bp += align;
	sctpPacketLengthRemaining -= align;
      }
    }
    return;
invalid:
    nd_print_invalid(ndo);
}
