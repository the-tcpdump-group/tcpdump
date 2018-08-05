/*
 * Copyright (C) 1999 WIDE Project.
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
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * Extensively modified by Hannes Gredler (hannes@gredler.at) for more
 * complete BGP support.
 */

/* \summary: Border Gateway Protocol (BGP) printer */

/* specification: RFC 4271 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "netdissect-stdinc.h"

#include <stdio.h>
#include <string.h>

#include "netdissect.h"
#include "addrtoname.h"
#include "extract.h"
#include "af.h"
#include "l2vpn.h"

struct bgp {
    nd_byte     bgp_marker[16];
    nd_uint16_t bgp_len;
    nd_uint8_t  bgp_type;
};
#define BGP_SIZE        19    /* unaligned */

#define BGP_OPEN                1
#define BGP_UPDATE              2
#define BGP_NOTIFICATION        3
#define BGP_KEEPALIVE           4
#define BGP_ROUTE_REFRESH       5

static const struct tok bgp_msg_values[] = {
    { BGP_OPEN,                 "Open"},
    { BGP_UPDATE,               "Update"},
    { BGP_NOTIFICATION,         "Notification"},
    { BGP_KEEPALIVE,            "Keepalive"},
    { BGP_ROUTE_REFRESH,        "Route Refresh"},
    { 0, NULL}
};

struct bgp_open {
    nd_byte     bgpo_marker[16];
    nd_uint16_t bgpo_len;
    nd_uint8_t  bgpo_type;
    nd_uint8_t  bgpo_version;
    nd_uint16_t bgpo_myas;
    nd_uint16_t bgpo_holdtime;
    nd_uint32_t bgpo_id;
    nd_uint8_t  bgpo_optlen;
    /* options should follow */
};
#define BGP_OPEN_SIZE        29    /* unaligned */

struct bgp_opt {
    nd_uint8_t bgpopt_type;
    nd_uint8_t bgpopt_len;
    /* variable length */
};
#define BGP_OPT_SIZE           2    /* some compilers may pad to 4 bytes */
#define BGP_CAP_HEADER_SIZE    2    /* some compilers may pad to 4 bytes */

struct bgp_notification {
    nd_byte     bgpn_marker[16];
    nd_uint16_t bgpn_len;
    nd_uint8_t  bgpn_type;
    nd_uint8_t  bgpn_major;
    nd_uint8_t  bgpn_minor;
};
#define BGP_NOTIFICATION_SIZE        21    /* unaligned */

struct bgp_route_refresh {
    nd_byte     bgp_marker[16];
    nd_uint16_t len;
    nd_uint8_t  type;   /* No padding after this; afi is, in fact, not aligned */
    nd_uint16_t afi;
    nd_uint8_t  res;
    nd_uint8_t  safi;
};
#define BGP_ROUTE_REFRESH_SIZE          23

#define bgp_attr_lenlen(flags, p) \
    (((flags) & 0x10) ? 2U : 1U)
#define bgp_attr_len(flags, p) \
    (((flags) & 0x10) ? EXTRACT_BE_U_2(p) : EXTRACT_U_1(p))

#define BGPTYPE_ORIGIN                   1
#define BGPTYPE_AS_PATH                  2
#define BGPTYPE_NEXT_HOP                 3
#define BGPTYPE_MULTI_EXIT_DISC          4
#define BGPTYPE_LOCAL_PREF               5
#define BGPTYPE_ATOMIC_AGGREGATE         6
#define BGPTYPE_AGGREGATOR               7
#define BGPTYPE_COMMUNITIES              8    /* RFC1997 */
#define BGPTYPE_ORIGINATOR_ID            9    /* RFC4456 */
#define BGPTYPE_CLUSTER_LIST            10    /* RFC4456 */
#define BGPTYPE_DPA                     11    /* deprecated, draft-ietf-idr-bgp-dpa */
#define BGPTYPE_ADVERTISERS             12    /* deprecated RFC1863 */
#define BGPTYPE_RCID_PATH               13    /* deprecated RFC1863 */
#define BGPTYPE_MP_REACH_NLRI           14    /* RFC4760 */
#define BGPTYPE_MP_UNREACH_NLRI         15    /* RFC4760 */
#define BGPTYPE_EXTD_COMMUNITIES        16      /* RFC4360 */
#define BGPTYPE_AS4_PATH                17      /* RFC6793 */
#define BGPTYPE_AGGREGATOR4             18      /* RFC6793 */
#define BGPTYPE_PMSI_TUNNEL             22      /* RFC6514 */
#define BGPTYPE_TUNNEL_ENCAP            23      /* RFC5512 */
#define BGPTYPE_TRAFFIC_ENG             24      /* RFC5543 */
#define BGPTYPE_IPV6_EXTD_COMMUNITIES   25      /* RFC5701 */
#define BGPTYPE_AIGP                    26      /* RFC7311 */
#define BGPTYPE_PE_DISTINGUISHER_LABEL  27      /* RFC6514 */
#define BGPTYPE_ENTROPY_LABEL           28      /* RFC6790 */
#define BGPTYPE_LARGE_COMMUNITY         32      /* draft-ietf-idr-large-community-05 */
#define BGPTYPE_ATTR_SET               128      /* RFC6368 */

#define BGP_MP_NLRI_MINSIZE              3       /* End of RIB Marker detection */

static const struct tok bgp_attr_values[] = {
    { BGPTYPE_ORIGIN,           "Origin"},
    { BGPTYPE_AS_PATH,          "AS Path"},
    { BGPTYPE_AS4_PATH,         "AS4 Path"},
    { BGPTYPE_NEXT_HOP,         "Next Hop"},
    { BGPTYPE_MULTI_EXIT_DISC,  "Multi Exit Discriminator"},
    { BGPTYPE_LOCAL_PREF,       "Local Preference"},
    { BGPTYPE_ATOMIC_AGGREGATE, "Atomic Aggregate"},
    { BGPTYPE_AGGREGATOR,       "Aggregator"},
    { BGPTYPE_AGGREGATOR4,      "Aggregator4"},
    { BGPTYPE_COMMUNITIES,      "Community"},
    { BGPTYPE_ORIGINATOR_ID,    "Originator ID"},
    { BGPTYPE_CLUSTER_LIST,     "Cluster List"},
    { BGPTYPE_DPA,              "DPA"},
    { BGPTYPE_ADVERTISERS,      "Advertisers"},
    { BGPTYPE_RCID_PATH,        "RCID Path / Cluster ID"},
    { BGPTYPE_MP_REACH_NLRI,    "Multi-Protocol Reach NLRI"},
    { BGPTYPE_MP_UNREACH_NLRI,  "Multi-Protocol Unreach NLRI"},
    { BGPTYPE_EXTD_COMMUNITIES, "Extended Community"},
    { BGPTYPE_PMSI_TUNNEL,      "PMSI Tunnel"},
    { BGPTYPE_TUNNEL_ENCAP,     "Tunnel Encapsulation"},
    { BGPTYPE_TRAFFIC_ENG,      "Traffic Engineering"},
    { BGPTYPE_IPV6_EXTD_COMMUNITIES, "IPv6 Extended Community"},
    { BGPTYPE_AIGP,             "Accumulated IGP Metric"},
    { BGPTYPE_PE_DISTINGUISHER_LABEL, "PE Distinguisher Label"},
    { BGPTYPE_ENTROPY_LABEL,    "Entropy Label"},
    { BGPTYPE_LARGE_COMMUNITY,  "Large Community"},
    { BGPTYPE_ATTR_SET,         "Attribute Set"},
    { 255,                      "Reserved for development"},
    { 0, NULL}
};

#define BGP_AS_SET             1
#define BGP_AS_SEQUENCE        2
#define BGP_CONFED_AS_SEQUENCE 3 /* draft-ietf-idr-rfc3065bis-01 */
#define BGP_CONFED_AS_SET      4 /* draft-ietf-idr-rfc3065bis-01  */

#define BGP_AS_SEG_TYPE_MIN    BGP_AS_SET
#define BGP_AS_SEG_TYPE_MAX    BGP_CONFED_AS_SET

static const struct tok bgp_as_path_segment_open_values[] = {
    { BGP_AS_SEQUENCE,         ""},
    { BGP_AS_SET,              "{ "},
    { BGP_CONFED_AS_SEQUENCE,  "( "},
    { BGP_CONFED_AS_SET,       "({ "},
    { 0, NULL}
};

static const struct tok bgp_as_path_segment_close_values[] = {
    { BGP_AS_SEQUENCE,         ""},
    { BGP_AS_SET,              "}"},
    { BGP_CONFED_AS_SEQUENCE,  ")"},
    { BGP_CONFED_AS_SET,       "})"},
    { 0, NULL}
};

#define BGP_OPT_AUTH                    1
#define BGP_OPT_CAP                     2

static const struct tok bgp_opt_values[] = {
    { BGP_OPT_AUTH,             "Authentication Information"},
    { BGP_OPT_CAP,              "Capabilities Advertisement"},
    { 0, NULL}
};

#define BGP_CAPCODE_MP                  1 /* RFC2858 */
#define BGP_CAPCODE_RR                  2 /* RFC2918 */
#define BGP_CAPCODE_ORF                 3 /* RFC5291 */
#define BGP_CAPCODE_MR                  4 /* RFC3107 */
#define BGP_CAPCODE_EXT_NH              5 /* RFC5549 */
#define BGP_CAPCODE_RESTART            64 /* RFC4724  */
#define BGP_CAPCODE_AS_NEW             65 /* RFC6793 */
#define BGP_CAPCODE_DYN_CAP            67 /* draft-ietf-idr-dynamic-cap */
#define BGP_CAPCODE_MULTISESS          68 /* draft-ietf-idr-bgp-multisession */
#define BGP_CAPCODE_ADD_PATH           69 /* RFC7911 */
#define BGP_CAPCODE_ENH_RR             70 /* draft-keyur-bgp-enhanced-route-refresh */
#define BGP_CAPCODE_RR_CISCO          128

static const struct tok bgp_capcode_values[] = {
    { BGP_CAPCODE_MP,           "Multiprotocol Extensions"},
    { BGP_CAPCODE_RR,           "Route Refresh"},
    { BGP_CAPCODE_ORF,          "Cooperative Route Filtering"},
    { BGP_CAPCODE_MR,           "Multiple Routes to a Destination"},
    { BGP_CAPCODE_EXT_NH,       "Extended Next Hop Encoding"},
    { BGP_CAPCODE_RESTART,      "Graceful Restart"},
    { BGP_CAPCODE_AS_NEW,       "32-Bit AS Number"},
    { BGP_CAPCODE_DYN_CAP,      "Dynamic Capability"},
    { BGP_CAPCODE_MULTISESS,    "Multisession BGP"},
    { BGP_CAPCODE_ADD_PATH,     "Multiple Paths"},
    { BGP_CAPCODE_ENH_RR,       "Enhanced Route Refresh"},
    { BGP_CAPCODE_RR_CISCO,     "Route Refresh (Cisco)"},
    { 0, NULL}
};

#define BGP_NOTIFY_MAJOR_MSG            1
#define BGP_NOTIFY_MAJOR_OPEN           2
#define BGP_NOTIFY_MAJOR_UPDATE         3
#define BGP_NOTIFY_MAJOR_HOLDTIME       4
#define BGP_NOTIFY_MAJOR_FSM            5
#define BGP_NOTIFY_MAJOR_CEASE          6
#define BGP_NOTIFY_MAJOR_CAP            7

static const struct tok bgp_notify_major_values[] = {
    { BGP_NOTIFY_MAJOR_MSG,     "Message Header Error"},
    { BGP_NOTIFY_MAJOR_OPEN,    "OPEN Message Error"},
    { BGP_NOTIFY_MAJOR_UPDATE,  "UPDATE Message Error"},
    { BGP_NOTIFY_MAJOR_HOLDTIME,"Hold Timer Expired"},
    { BGP_NOTIFY_MAJOR_FSM,     "Finite State Machine Error"},
    { BGP_NOTIFY_MAJOR_CEASE,   "Cease"},
    { BGP_NOTIFY_MAJOR_CAP,     "Capability Message Error"},
    { 0, NULL}
};

/* draft-ietf-idr-cease-subcode-02 */
#define BGP_NOTIFY_MINOR_CEASE_MAXPRFX  1
/* draft-ietf-idr-shutdown-07 */
#define BGP_NOTIFY_MINOR_CEASE_SHUT     2
#define BGP_NOTIFY_MINOR_CEASE_RESET    4
#define BGP_NOTIFY_MINOR_CEASE_ADMIN_SHUTDOWN_LEN   128
static const struct tok bgp_notify_minor_cease_values[] = {
    { BGP_NOTIFY_MINOR_CEASE_MAXPRFX, "Maximum Number of Prefixes Reached"},
    { BGP_NOTIFY_MINOR_CEASE_SHUT,    "Administrative Shutdown"},
    { 3,                        "Peer Unconfigured"},
    { BGP_NOTIFY_MINOR_CEASE_RESET,   "Administrative Reset"},
    { 5,                        "Connection Rejected"},
    { 6,                        "Other Configuration Change"},
    { 7,                        "Connection Collision Resolution"},
    { 0, NULL}
};

static const struct tok bgp_notify_minor_msg_values[] = {
    { 1,                        "Connection Not Synchronized"},
    { 2,                        "Bad Message Length"},
    { 3,                        "Bad Message Type"},
    { 0, NULL}
};

static const struct tok bgp_notify_minor_open_values[] = {
    { 1,                        "Unsupported Version Number"},
    { 2,                        "Bad Peer AS"},
    { 3,                        "Bad BGP Identifier"},
    { 4,                        "Unsupported Optional Parameter"},
    { 5,                        "Authentication Failure"},
    { 6,                        "Unacceptable Hold Time"},
    { 7,                        "Capability Message Error"},
    { 0, NULL}
};

static const struct tok bgp_notify_minor_update_values[] = {
    { 1,                        "Malformed Attribute List"},
    { 2,                        "Unrecognized Well-known Attribute"},
    { 3,                        "Missing Well-known Attribute"},
    { 4,                        "Attribute Flags Error"},
    { 5,                        "Attribute Length Error"},
    { 6,                        "Invalid ORIGIN Attribute"},
    { 7,                        "AS Routing Loop"},
    { 8,                        "Invalid NEXT_HOP Attribute"},
    { 9,                        "Optional Attribute Error"},
    { 10,                       "Invalid Network Field"},
    { 11,                       "Malformed AS_PATH"},
    { 0, NULL}
};

static const struct tok bgp_notify_minor_fsm_values[] = {
    { 0,                        "Unspecified Error"},
    { 1,                        "In OpenSent State"},
    { 2,                        "In OpenConfirm State"},
    { 3,                        "In Established State"},
    { 0, NULL }
};

static const struct tok bgp_notify_minor_cap_values[] = {
    { 1,                        "Invalid Action Value" },
    { 2,                        "Invalid Capability Length" },
    { 3,                        "Malformed Capability Value" },
    { 4,                        "Unsupported Capability Code" },
    { 0, NULL }
};

static const struct tok bgp_origin_values[] = {
    { 0,                        "IGP"},
    { 1,                        "EGP"},
    { 2,                        "Incomplete"},
    { 0, NULL}
};

#define BGP_PMSI_TUNNEL_RSVP_P2MP 1
#define BGP_PMSI_TUNNEL_LDP_P2MP  2
#define BGP_PMSI_TUNNEL_PIM_SSM   3
#define BGP_PMSI_TUNNEL_PIM_SM    4
#define BGP_PMSI_TUNNEL_PIM_BIDIR 5
#define BGP_PMSI_TUNNEL_INGRESS   6
#define BGP_PMSI_TUNNEL_LDP_MP2MP 7

static const struct tok bgp_pmsi_tunnel_values[] = {
    { BGP_PMSI_TUNNEL_RSVP_P2MP, "RSVP-TE P2MP LSP"},
    { BGP_PMSI_TUNNEL_LDP_P2MP, "LDP P2MP LSP"},
    { BGP_PMSI_TUNNEL_PIM_SSM, "PIM-SSM Tree"},
    { BGP_PMSI_TUNNEL_PIM_SM, "PIM-SM Tree"},
    { BGP_PMSI_TUNNEL_PIM_BIDIR, "PIM-Bidir Tree"},
    { BGP_PMSI_TUNNEL_INGRESS, "Ingress Replication"},
    { BGP_PMSI_TUNNEL_LDP_MP2MP, "LDP MP2MP LSP"},
    { 0, NULL}
};

static const struct tok bgp_pmsi_flag_values[] = {
    { 0x01, "Leaf Information required"},
    { 0, NULL}
};

#define BGP_AIGP_TLV 1

static const struct tok bgp_aigp_values[] = {
    { BGP_AIGP_TLV, "AIGP"},
    { 0, NULL}
};

/* Subsequent address family identifier, RFC2283 section 7 */
#define SAFNUM_RES                      0
#define SAFNUM_UNICAST                  1
#define SAFNUM_MULTICAST                2
#define SAFNUM_UNIMULTICAST             3       /* deprecated now */
/* labeled BGP RFC3107 */
#define SAFNUM_LABUNICAST               4
/* RFC6514 */
#define SAFNUM_MULTICAST_VPN            5
/* draft-nalawade-kapoor-tunnel-safi */
#define SAFNUM_TUNNEL                   64
/* RFC4761 */
#define SAFNUM_VPLS                     65
/* RFC6037 */
#define SAFNUM_MDT                      66
/* RFC4364 */
#define SAFNUM_VPNUNICAST               128
/* RFC6513 */
#define SAFNUM_VPNMULTICAST             129
#define SAFNUM_VPNUNIMULTICAST          130     /* deprecated now */
/* RFC4684 */
#define SAFNUM_RT_ROUTING_INFO          132

#define BGP_VPN_RD_LEN                  8

static const struct tok bgp_safi_values[] = {
    { SAFNUM_RES,               "Reserved"},
    { SAFNUM_UNICAST,           "Unicast"},
    { SAFNUM_MULTICAST,         "Multicast"},
    { SAFNUM_UNIMULTICAST,      "Unicast+Multicast"},
    { SAFNUM_LABUNICAST,        "labeled Unicast"},
    { SAFNUM_TUNNEL,            "Tunnel"},
    { SAFNUM_VPLS,              "VPLS"},
    { SAFNUM_MDT,               "MDT"},
    { SAFNUM_VPNUNICAST,        "labeled VPN Unicast"},
    { SAFNUM_VPNMULTICAST,      "labeled VPN Multicast"},
    { SAFNUM_VPNUNIMULTICAST,   "labeled VPN Unicast+Multicast"},
    { SAFNUM_RT_ROUTING_INFO,   "Route Target Routing Information"},
    { SAFNUM_MULTICAST_VPN,     "Multicast VPN"},
    { 0, NULL }
};

/* well-known community */
#define BGP_COMMUNITY_NO_EXPORT              0xffffff01
#define BGP_COMMUNITY_NO_ADVERT              0xffffff02
#define BGP_COMMUNITY_NO_EXPORT_SUBCONFED    0xffffff03

/* Extended community type - draft-ietf-idr-bgp-ext-communities-05 */
#define BGP_EXT_COM_RT_0        0x0002  /* Route Target,Format AS(2bytes):AN(4bytes) */
#define BGP_EXT_COM_RT_1        0x0102  /* Route Target,Format IP address:AN(2bytes) */
#define BGP_EXT_COM_RT_2        0x0202  /* Route Target,Format AN(4bytes):local(2bytes) */
#define BGP_EXT_COM_RO_0        0x0003  /* Route Origin,Format AS(2bytes):AN(4bytes) */
#define BGP_EXT_COM_RO_1        0x0103  /* Route Origin,Format IP address:AN(2bytes) */
#define BGP_EXT_COM_RO_2        0x0203  /* Route Origin,Format AN(4bytes):local(2bytes) */
#define BGP_EXT_COM_LINKBAND    0x4004  /* Link Bandwidth,Format AS(2B):Bandwidth(4B) */
                                        /* rfc2547 bgp-mpls-vpns */
#define BGP_EXT_COM_VPN_ORIGIN  0x0005  /* OSPF Domain ID / VPN of Origin  - draft-rosen-vpns-ospf-bgp-mpls */
#define BGP_EXT_COM_VPN_ORIGIN2 0x0105  /* duplicate - keep for backwards compatibility */
#define BGP_EXT_COM_VPN_ORIGIN3 0x0205  /* duplicate - keep for backwards compatibility */
#define BGP_EXT_COM_VPN_ORIGIN4 0x8005  /* duplicate - keep for backwards compatibility */

#define BGP_EXT_COM_OSPF_RTYPE  0x0306  /* OSPF Route Type,Format Area(4B):RouteType(1B):Options(1B) */
#define BGP_EXT_COM_OSPF_RTYPE2 0x8000  /* duplicate - keep for backwards compatibility */

#define BGP_EXT_COM_OSPF_RID    0x0107  /* OSPF Router ID,Format RouterID(4B):Unused(2B) */
#define BGP_EXT_COM_OSPF_RID2   0x8001  /* duplicate - keep for backwards compatibility */

#define BGP_EXT_COM_L2INFO      0x800a  /* draft-kompella-ppvpn-l2vpn */

#define BGP_EXT_COM_SOURCE_AS   0x0009  /* RFC-ietf-l3vpn-2547bis-mcast-bgp-08.txt */
#define BGP_EXT_COM_VRF_RT_IMP  0x010b  /* RFC-ietf-l3vpn-2547bis-mcast-bgp-08.txt */
#define BGP_EXT_COM_L2VPN_RT_0  0x000a  /* L2VPN Identifier,Format AS(2bytes):AN(4bytes) */
#define BGP_EXT_COM_L2VPN_RT_1  0xF10a  /* L2VPN Identifier,Format IP address:AN(2bytes) */

/* http://www.cisco.com/en/US/tech/tk436/tk428/technologies_tech_note09186a00801eb09a.shtml  */
#define BGP_EXT_COM_EIGRP_GEN                    0x8800
#define BGP_EXT_COM_EIGRP_METRIC_AS_DELAY        0x8801
#define BGP_EXT_COM_EIGRP_METRIC_REL_NH_BW       0x8802
#define BGP_EXT_COM_EIGRP_METRIC_LOAD_MTU        0x8803
#define BGP_EXT_COM_EIGRP_EXT_REMAS_REMID        0x8804
#define BGP_EXT_COM_EIGRP_EXT_REMPROTO_REMMETRIC 0x8805

static const struct tok bgp_extd_comm_flag_values[] = {
    { 0x8000,                  "vendor-specific"},
    { 0x4000,                  "non-transitive"},
    { 0, NULL},
};

static const struct tok bgp_extd_comm_subtype_values[] = {
    { BGP_EXT_COM_RT_0,        "target"},
    { BGP_EXT_COM_RT_1,        "target"},
    { BGP_EXT_COM_RT_2,        "target"},
    { BGP_EXT_COM_RO_0,        "origin"},
    { BGP_EXT_COM_RO_1,        "origin"},
    { BGP_EXT_COM_RO_2,        "origin"},
    { BGP_EXT_COM_LINKBAND,    "link-BW"},
    { BGP_EXT_COM_VPN_ORIGIN,  "ospf-domain"},
    { BGP_EXT_COM_VPN_ORIGIN2, "ospf-domain"},
    { BGP_EXT_COM_VPN_ORIGIN3, "ospf-domain"},
    { BGP_EXT_COM_VPN_ORIGIN4, "ospf-domain"},
    { BGP_EXT_COM_OSPF_RTYPE,  "ospf-route-type"},
    { BGP_EXT_COM_OSPF_RTYPE2, "ospf-route-type"},
    { BGP_EXT_COM_OSPF_RID,    "ospf-router-id"},
    { BGP_EXT_COM_OSPF_RID2,   "ospf-router-id"},
    { BGP_EXT_COM_L2INFO,      "layer2-info"},
    { BGP_EXT_COM_EIGRP_GEN , "eigrp-general-route (flag, tag)" },
    { BGP_EXT_COM_EIGRP_METRIC_AS_DELAY , "eigrp-route-metric (AS, delay)" },
    { BGP_EXT_COM_EIGRP_METRIC_REL_NH_BW , "eigrp-route-metric (reliability, nexthop, bandwidth)" },
    { BGP_EXT_COM_EIGRP_METRIC_LOAD_MTU , "eigrp-route-metric (load, MTU)" },
    { BGP_EXT_COM_EIGRP_EXT_REMAS_REMID , "eigrp-external-route (remote-AS, remote-ID)" },
    { BGP_EXT_COM_EIGRP_EXT_REMPROTO_REMMETRIC , "eigrp-external-route (remote-proto, remote-metric)" },
    { BGP_EXT_COM_SOURCE_AS, "source-AS" },
    { BGP_EXT_COM_VRF_RT_IMP, "vrf-route-import"},
    { BGP_EXT_COM_L2VPN_RT_0, "l2vpn-id"},
    { BGP_EXT_COM_L2VPN_RT_1, "l2vpn-id"},
    { 0, NULL},
};

/* OSPF codes for  BGP_EXT_COM_OSPF_RTYPE draft-rosen-vpns-ospf-bgp-mpls  */
#define BGP_OSPF_RTYPE_RTR      1 /* OSPF Router LSA */
#define BGP_OSPF_RTYPE_NET      2 /* OSPF Network LSA */
#define BGP_OSPF_RTYPE_SUM      3 /* OSPF Summary LSA */
#define BGP_OSPF_RTYPE_EXT      5 /* OSPF External LSA, note that ASBR doesn't apply to MPLS-VPN */
#define BGP_OSPF_RTYPE_NSSA     7 /* OSPF NSSA External*/
#define BGP_OSPF_RTYPE_SHAM     129 /* OSPF-MPLS-VPN Sham link */
#define BGP_OSPF_RTYPE_METRIC_TYPE 0x1 /* LSB of RTYPE Options Field */

static const struct tok bgp_extd_comm_ospf_rtype_values[] = {
  { BGP_OSPF_RTYPE_RTR, "Router" },
  { BGP_OSPF_RTYPE_NET, "Network" },
  { BGP_OSPF_RTYPE_SUM, "Summary" },
  { BGP_OSPF_RTYPE_EXT, "External" },
  { BGP_OSPF_RTYPE_NSSA,"NSSA External" },
  { BGP_OSPF_RTYPE_SHAM,"MPLS-VPN Sham" },
  { 0, NULL },
};

/* ADD-PATH Send/Receive field values */
static const struct tok bgp_add_path_recvsend[] = {
    { 1, "Receive" },
    { 2, "Send" },
    { 3, "Both" },
    { 0, NULL },
};

static char astostr[20];

/*
 * as_printf
 *
 * Convert an AS number into a string and return string pointer.
 *
 * Depending on bflag is set or not, AS number is converted into ASDOT notation
 * or plain number notation.
 *
 */
static char *
as_printf(netdissect_options *ndo,
          char *str, size_t size, u_int asnum)
{
    if (!ndo->ndo_bflag || asnum <= 0xFFFF) {
        nd_snprintf(str, size, "%u", asnum);
    } else {
        nd_snprintf(str, size, "%u.%u", asnum >> 16, asnum & 0xFFFF);
    }
    return str;
}

#define ITEMCHECK(minlen) if (itemlen < minlen) goto badtlv;

int
decode_prefix4(netdissect_options *ndo,
               const u_char *pptr, u_int itemlen, char *buf, u_int buflen)
{
    struct in_addr addr;
    u_int plen, plenbytes;

    ND_TCHECK_1(pptr);
    ITEMCHECK(1);
    plen = EXTRACT_U_1(pptr);
    if (32 < plen)
        return -1;
    itemlen -= 1;

    memset(&addr, 0, sizeof(addr));
    plenbytes = (plen + 7) / 8;
    ND_TCHECK_LEN(pptr + 1, plenbytes);
    ITEMCHECK(plenbytes);
    memcpy(&addr, pptr + 1, plenbytes);
    if (plen % 8) {
        ((u_char *)&addr)[plenbytes - 1] &= ((0xff00 >> (plen % 8)) & 0xff);
    }
    nd_snprintf(buf, buflen, "%s/%u", ipaddr_string(ndo, (const u_char *)&addr), plen);
    return 1 + plenbytes;

trunc:
    return -2;

badtlv:
    return -3;
}

static int
decode_labeled_prefix4(netdissect_options *ndo,
                       const u_char *pptr, u_int itemlen, char *buf, u_int buflen)
{
    struct in_addr addr;
    u_int plen, plenbytes;

    /* prefix length and label = 4 bytes */
    ND_TCHECK_4(pptr);
    ITEMCHECK(4);
    plen = EXTRACT_U_1(pptr);   /* get prefix length */

    /* this is one of the weirdnesses of rfc3107
       the label length (actually the label + COS bits)
       is added to the prefix length;
       we also do only read out just one label -
       there is no real application for advertisement of
       stacked labels in a single BGP message
    */

    if (24 > plen)
        return -1;

    plen-=24; /* adjust prefixlen - labellength */

    if (32 < plen)
        return -1;
    itemlen -= 4;

    memset(&addr, 0, sizeof(addr));
    plenbytes = (plen + 7) / 8;
    ND_TCHECK_LEN(pptr + 4, plenbytes);
    ITEMCHECK(plenbytes);
    memcpy(&addr, pptr + 4, plenbytes);
    if (plen % 8) {
        ((u_char *)&addr)[plenbytes - 1] &= ((0xff00 >> (plen % 8)) & 0xff);
    }
    /* the label may get offsetted by 4 bits so lets shift it right */
    nd_snprintf(buf, buflen, "%s/%u, label:%u %s",
             ipaddr_string(ndo, (const u_char *)&addr),
             plen,
             EXTRACT_BE_U_3(pptr + 1)>>4,
             ((EXTRACT_U_1(pptr + 3) & 1) == 0) ? "(BOGUS: Bottom of Stack NOT set!)" : "(bottom)" );

    return 4 + plenbytes;

trunc:
    return -2;

badtlv:
    return -3;
}

/*
 * bgp_vpn_ip_print
 *
 * print an ipv4 or ipv6 address into a buffer dependend on address length.
 */
static char *
bgp_vpn_ip_print(netdissect_options *ndo,
                 const u_char *pptr, u_int addr_length)
{

    /* worst case string is s fully formatted v6 address */
    static char addr[sizeof("1234:5678:89ab:cdef:1234:5678:89ab:cdef")];
    char *pos = addr;

    switch(addr_length) {
    case (sizeof(nd_ipv4) << 3): /* 32 */
        ND_TCHECK_LEN(pptr, sizeof(nd_ipv4));
        nd_snprintf(pos, sizeof(addr), "%s", ipaddr_string(ndo, pptr));
        break;
    case (sizeof(nd_ipv6) << 3): /* 128 */
        ND_TCHECK_LEN(pptr, sizeof(nd_ipv6));
        nd_snprintf(pos, sizeof(addr), "%s", ip6addr_string(ndo, pptr));
        break;
    default:
        nd_snprintf(pos, sizeof(addr), "bogus address length %u", addr_length);
        break;
    }
    pos += strlen(pos);

trunc:
    *(pos) = '\0';
    return (addr);
}

/*
 * bgp_vpn_sg_print
 *
 * print an multicast s,g entry into a buffer.
 * the s,g entry is encoded like this.
 *
 * +-----------------------------------+
 * | Multicast Source Length (1 octet) |
 * +-----------------------------------+
 * |   Multicast Source (Variable)     |
 * +-----------------------------------+
 * |  Multicast Group Length (1 octet) |
 * +-----------------------------------+
 * |  Multicast Group   (Variable)     |
 * +-----------------------------------+
 *
 * return the number of bytes read from the wire.
 */
static u_int
bgp_vpn_sg_print(netdissect_options *ndo,
                 const u_char *pptr, char *buf, u_int buflen)
{
    uint8_t addr_length;
    u_int total_length, offset;

    total_length = 0;

    /* Source address length, encoded in bits */
    ND_TCHECK_1(pptr);
    addr_length = EXTRACT_U_1(pptr);
    pptr++;

    /* Source address */
    ND_TCHECK_LEN(pptr, (addr_length >> 3));
    total_length += (addr_length >> 3) + 1;
    offset = strlen(buf);
    if (addr_length) {
        nd_snprintf(buf + offset, buflen - offset, ", Source %s",
             bgp_vpn_ip_print(ndo, pptr, addr_length));
        pptr += (addr_length >> 3);
    }

    /* Group address length, encoded in bits */
    ND_TCHECK_1(pptr);
    addr_length = EXTRACT_U_1(pptr);
    pptr++;

    /* Group address */
    ND_TCHECK_LEN(pptr, (addr_length >> 3));
    total_length += (addr_length >> 3) + 1;
    offset = strlen(buf);
    if (addr_length) {
        nd_snprintf(buf + offset, buflen - offset, ", Group %s",
             bgp_vpn_ip_print(ndo, pptr, addr_length));
        pptr += (addr_length >> 3);
    }

trunc:
    return (total_length);
}

/* RDs and RTs share the same semantics
 * we use bgp_vpn_rd_print for
 * printing route targets inside a NLRI */
const char *
bgp_vpn_rd_print(netdissect_options *ndo,
                 const u_char *pptr)
{
    /* allocate space for the largest possible string */
    static char rd[sizeof("xxxxxxxxxx:xxxxx (xxx.xxx.xxx.xxx:xxxxx)")];
    char *pos = rd;

    /* ok lets load the RD format */
    switch (EXTRACT_BE_U_2(pptr)) {

        /* 2-byte-AS:number fmt*/
    case 0:
        nd_snprintf(pos, sizeof(rd) - (pos - rd), "%u:%u (= %u.%u.%u.%u)",
                 EXTRACT_BE_U_2(pptr + 2),
                 EXTRACT_BE_U_4(pptr + 4),
                 EXTRACT_U_1(pptr + 4), EXTRACT_U_1(pptr + 5),
                 EXTRACT_U_1(pptr + 6), EXTRACT_U_1(pptr + 7));
        break;
        /* IP-address:AS fmt*/

    case 1:
        nd_snprintf(pos, sizeof(rd) - (pos - rd), "%u.%u.%u.%u:%u",
                 EXTRACT_U_1(pptr + 2), EXTRACT_U_1(pptr + 3),
                 EXTRACT_U_1(pptr + 4), EXTRACT_U_1(pptr + 5),
                 EXTRACT_BE_U_2(pptr + 6));
        break;

        /* 4-byte-AS:number fmt*/
    case 2:
        nd_snprintf(pos, sizeof(rd) - (pos - rd), "%s:%u (%u.%u.%u.%u:%u)",
                 as_printf(ndo, astostr, sizeof(astostr), EXTRACT_BE_U_4(pptr + 2)),
                 EXTRACT_BE_U_2(pptr + 6), EXTRACT_U_1(pptr + 2),
                 EXTRACT_U_1(pptr + 3), EXTRACT_U_1(pptr + 4),
                 EXTRACT_U_1(pptr + 5), EXTRACT_BE_U_2(pptr + 6));
        break;
    default:
        nd_snprintf(pos, sizeof(rd) - (pos - rd), "unknown RD format");
        break;
    }
    pos += strlen(pos);
    *(pos) = '\0';
    return (rd);
}

static int
decode_rt_routing_info(netdissect_options *ndo,
                       const u_char *pptr, char *buf, u_int buflen)
{
    uint8_t route_target[8];
    u_int plen;
    char asbuf[sizeof(astostr)]; /* bgp_vpn_rd_print() overwrites astostr */

    /* NLRI "prefix length" from RFC 2858 Section 4. */
    ND_TCHECK_1(pptr);
    plen = EXTRACT_U_1(pptr);   /* get prefix length */

    /* NLRI "prefix" (ibid), valid lengths are { 0, 32, 33, ..., 96 } bits.
     * RFC 4684 Section 4 defines the layout of "origin AS" and "route
     * target" fields inside the "prefix" depending on its length.
     */
    if (0 == plen) {
        /* Without "origin AS", without "route target". */
        nd_snprintf(buf, buflen, "default route target");
        return 1;
    }

    if (32 > plen)
        return -1;

    /* With at least "origin AS", possibly with "route target". */
    ND_TCHECK_4(pptr + 1);
    as_printf(ndo, asbuf, sizeof(asbuf), EXTRACT_BE_U_4(pptr + 1));

    plen -= 32; /* adjust prefix length */

    if (64 < plen)
        return -1;

    /* From now on (plen + 7) / 8 evaluates to { 0, 1, 2, ..., 8 }
     * and gives the number of octets in the variable-length "route
     * target" field inside this NLRI "prefix". Look for it.
     */
    memset(&route_target, 0, sizeof(route_target));
    ND_TCHECK_LEN(pptr + 5, (plen + 7) / 8);
    memcpy(&route_target, pptr + 5, (plen + 7) / 8);
    /* Which specification says to do this? */
    if (plen % 8) {
        ((u_char *)&route_target)[(plen + 7) / 8 - 1] &=
            ((0xff00 >> (plen % 8)) & 0xff);
    }
    nd_snprintf(buf, buflen, "origin AS: %s, route target %s",
             asbuf,
             bgp_vpn_rd_print(ndo, (u_char *)&route_target));

    return 5 + (plen + 7) / 8;

trunc:
    return -2;
}

static int
decode_labeled_vpn_prefix4(netdissect_options *ndo,
                           const u_char *pptr, char *buf, u_int buflen)
{
    struct in_addr addr;
    u_int plen;

    ND_TCHECK_1(pptr);
    plen = EXTRACT_U_1(pptr);   /* get prefix length */

    if ((24+64) > plen)
        return -1;

    plen -= (24+64); /* adjust prefixlen - labellength - RD len*/

    if (32 < plen)
        return -1;

    memset(&addr, 0, sizeof(addr));
    ND_TCHECK_LEN(pptr + 12, (plen + 7) / 8);
    memcpy(&addr, pptr + 12, (plen + 7) / 8);
    if (plen % 8) {
        ((u_char *)&addr)[(plen + 7) / 8 - 1] &=
            ((0xff00 >> (plen % 8)) & 0xff);
    }
    /* the label may get offsetted by 4 bits so lets shift it right */
    nd_snprintf(buf, buflen, "RD: %s, %s/%u, label:%u %s",
             bgp_vpn_rd_print(ndo, pptr+4),
             ipaddr_string(ndo, (const u_char *)&addr),
             plen,
             EXTRACT_BE_U_3(pptr + 1)>>4,
             ((EXTRACT_U_1(pptr + 3) & 1) == 0) ? "(BOGUS: Bottom of Stack NOT set!)" : "(bottom)" );

    return 12 + (plen + 7) / 8;

trunc:
    return -2;
}

/*
 * +-------------------------------+
 * |                               |
 * |  RD:IPv4-address (12 octets)  |
 * |                               |
 * +-------------------------------+
 * |  MDT Group-address (4 octets) |
 * +-------------------------------+
 */

#define MDT_VPN_NLRI_LEN 16

static int
decode_mdt_vpn_nlri(netdissect_options *ndo,
                    const u_char *pptr, char *buf, u_int buflen)
{
    const u_char *rd;
    const u_char *vpn_ip;

    ND_TCHECK_1(pptr);

    /* if the NLRI is not predefined length, quit.*/
    if (EXTRACT_U_1(pptr) != MDT_VPN_NLRI_LEN * 8)
        return -1;
    pptr++;

    /* RD */
    ND_TCHECK_8(pptr);
    rd = pptr;
    pptr += 8;

    /* IPv4 address */
    ND_TCHECK_LEN(pptr, sizeof(nd_ipv4));
    vpn_ip = pptr;
    pptr += sizeof(nd_ipv4);

    /* MDT Group Address */
    ND_TCHECK_LEN(pptr, sizeof(nd_ipv4));

    nd_snprintf(buf, buflen, "RD: %s, VPN IP Address: %s, MC Group Address: %s",
             bgp_vpn_rd_print(ndo, rd), ipaddr_string(ndo, vpn_ip), ipaddr_string(ndo, pptr));

    return MDT_VPN_NLRI_LEN + 1;

 trunc:
    return -2;
}

#define BGP_MULTICAST_VPN_ROUTE_TYPE_INTRA_AS_I_PMSI   1
#define BGP_MULTICAST_VPN_ROUTE_TYPE_INTER_AS_I_PMSI   2
#define BGP_MULTICAST_VPN_ROUTE_TYPE_S_PMSI            3
#define BGP_MULTICAST_VPN_ROUTE_TYPE_INTRA_AS_SEG_LEAF 4
#define BGP_MULTICAST_VPN_ROUTE_TYPE_SOURCE_ACTIVE     5
#define BGP_MULTICAST_VPN_ROUTE_TYPE_SHARED_TREE_JOIN  6
#define BGP_MULTICAST_VPN_ROUTE_TYPE_SOURCE_TREE_JOIN  7

static const struct tok bgp_multicast_vpn_route_type_values[] = {
    { BGP_MULTICAST_VPN_ROUTE_TYPE_INTRA_AS_I_PMSI, "Intra-AS I-PMSI"},
    { BGP_MULTICAST_VPN_ROUTE_TYPE_INTER_AS_I_PMSI, "Inter-AS I-PMSI"},
    { BGP_MULTICAST_VPN_ROUTE_TYPE_S_PMSI, "S-PMSI"},
    { BGP_MULTICAST_VPN_ROUTE_TYPE_INTRA_AS_SEG_LEAF, "Intra-AS Segment-Leaf"},
    { BGP_MULTICAST_VPN_ROUTE_TYPE_SOURCE_ACTIVE, "Source-Active"},
    { BGP_MULTICAST_VPN_ROUTE_TYPE_SHARED_TREE_JOIN, "Shared Tree Join"},
    { BGP_MULTICAST_VPN_ROUTE_TYPE_SOURCE_TREE_JOIN, "Source Tree Join"},
    { 0, NULL}
};

static int
decode_multicast_vpn(netdissect_options *ndo,
                     const u_char *pptr, char *buf, size_t buflen)
{
    uint8_t route_type, route_length, addr_length;
    u_int sg_length;
    u_int offset;

    ND_TCHECK_2(pptr);
    route_type = EXTRACT_U_1(pptr);
    pptr++;
    route_length = EXTRACT_U_1(pptr);
    pptr++;

    nd_snprintf(buf, buflen, "Route-Type: %s (%u), length: %u",
         tok2str(bgp_multicast_vpn_route_type_values,
                 "Unknown", route_type),
         route_type, route_length);

    switch(route_type) {
    case BGP_MULTICAST_VPN_ROUTE_TYPE_INTRA_AS_I_PMSI:
        ND_TCHECK_LEN(pptr, BGP_VPN_RD_LEN);
        offset = strlen(buf);
        nd_snprintf(buf + offset, buflen - offset, ", RD: %s, Originator %s",
                 bgp_vpn_rd_print(ndo, pptr),
                 bgp_vpn_ip_print(ndo, pptr + BGP_VPN_RD_LEN,
                                  (route_length - BGP_VPN_RD_LEN) << 3));
        break;
    case BGP_MULTICAST_VPN_ROUTE_TYPE_INTER_AS_I_PMSI:
        ND_TCHECK_LEN(pptr, BGP_VPN_RD_LEN + 4);
        offset = strlen(buf);
        nd_snprintf(buf + offset, buflen - offset, ", RD: %s, Source-AS %s",
        bgp_vpn_rd_print(ndo, pptr),
        as_printf(ndo, astostr, sizeof(astostr),
        EXTRACT_BE_U_4(pptr + BGP_VPN_RD_LEN)));
        break;

    case BGP_MULTICAST_VPN_ROUTE_TYPE_S_PMSI:
        ND_TCHECK_LEN(pptr, BGP_VPN_RD_LEN);
        offset = strlen(buf);
        nd_snprintf(buf + offset, buflen - offset, ", RD: %s",
                 bgp_vpn_rd_print(ndo, pptr));
        pptr += BGP_VPN_RD_LEN;

        sg_length = bgp_vpn_sg_print(ndo, pptr, buf, buflen);
        addr_length =  route_length - sg_length;

        ND_TCHECK_LEN(pptr, addr_length);
        offset = strlen(buf);
        nd_snprintf(buf + offset, buflen - offset, ", Originator %s",
                 bgp_vpn_ip_print(ndo, pptr, addr_length << 3));
        break;

    case BGP_MULTICAST_VPN_ROUTE_TYPE_SOURCE_ACTIVE:
        ND_TCHECK_LEN(pptr, BGP_VPN_RD_LEN);
        offset = strlen(buf);
        nd_snprintf(buf + offset, buflen - offset, ", RD: %s",
                 bgp_vpn_rd_print(ndo, pptr));
        pptr += BGP_VPN_RD_LEN;

        bgp_vpn_sg_print(ndo, pptr, buf, buflen);
        break;

    case BGP_MULTICAST_VPN_ROUTE_TYPE_SHARED_TREE_JOIN: /* fall through */
    case BGP_MULTICAST_VPN_ROUTE_TYPE_SOURCE_TREE_JOIN:
        ND_TCHECK_LEN(pptr, BGP_VPN_RD_LEN + 4);
        offset = strlen(buf);
        nd_snprintf(buf + offset, buflen - offset, ", RD: %s, Source-AS %s",
                 bgp_vpn_rd_print(ndo, pptr),
                 as_printf(ndo, astostr, sizeof(astostr),
                 EXTRACT_BE_U_4(pptr + BGP_VPN_RD_LEN)));
        pptr += BGP_VPN_RD_LEN + 4;

        bgp_vpn_sg_print(ndo, pptr, buf, buflen);
        break;

        /*
         * no per route-type printing yet.
         */
    case BGP_MULTICAST_VPN_ROUTE_TYPE_INTRA_AS_SEG_LEAF:
    default:
        break;
    }

    return route_length + 2;

trunc:
    return -2;
}

/*
 * As I remember, some versions of systems have an snprintf() that
 * returns -1 if the buffer would have overflowed.  If the return
 * value is negative, set buflen to 0, to indicate that we've filled
 * the buffer up.
 *
 * If the return value is greater than buflen, that means that
 * the buffer would have overflowed; again, set buflen to 0 in
 * that case.
 */
#define UPDATE_BUF_BUFLEN(buf, buflen, stringlen) \
    if (stringlen<0) \
        buflen=0; \
    else if ((u_int)stringlen>buflen) \
        buflen=0; \
    else { \
        buflen-=stringlen; \
        buf+=stringlen; \
    }

static int
decode_labeled_vpn_l2(netdissect_options *ndo,
                      const u_char *pptr, char *buf, u_int buflen)
{
    u_int plen, tlen, tlv_type, tlv_len, ttlv_len;
    int stringlen;

    ND_TCHECK_2(pptr);
    plen = EXTRACT_BE_U_2(pptr);
    tlen = plen;
    pptr += 2;
    /* Old and new L2VPN NLRI share AFI/SAFI
     *   -> Assume a 12 Byte-length NLRI is auto-discovery-only
     *      and > 17 as old format. Complain for the middle case
     */
    if (plen == 12) {
        /* assume AD-only with RD, BGPNH */
        ND_TCHECK_LEN(pptr, 12);
        buf[0] = '\0';
        stringlen = nd_snprintf(buf, buflen, "RD: %s, BGPNH: %s",
                             bgp_vpn_rd_print(ndo, pptr),
                             ipaddr_string(ndo, pptr+8));
        UPDATE_BUF_BUFLEN(buf, buflen, stringlen);
        pptr += 12;
        tlen -= 12;
        return plen + 2;
    } else if (plen > 17) {
        /* assume old format */
        /* RD, ID, LBLKOFF, LBLBASE */

        ND_TCHECK_LEN(pptr, 15);
        buf[0] = '\0';
        stringlen = nd_snprintf(buf, buflen, "RD: %s, CE-ID: %u, Label-Block Offset: %u, Label Base %u",
                             bgp_vpn_rd_print(ndo, pptr),
                             EXTRACT_BE_U_2(pptr + 8),
                             EXTRACT_BE_U_2(pptr + 10),
                             EXTRACT_BE_U_3(pptr + 12)>>4); /* the label is offsetted by 4 bits so lets shift it right */
        UPDATE_BUF_BUFLEN(buf, buflen, stringlen);
        pptr += 15;
        tlen -= 15;

        /* ok now the variable part - lets read out TLVs*/
        while (tlen != 0) {
            if (tlen < 3) {
                if (buflen != 0) {
                    stringlen=nd_snprintf(buf,buflen, "\n\t\tran past the end");
                    UPDATE_BUF_BUFLEN(buf, buflen, stringlen);
                }
                return plen + 2;
            }
            ND_TCHECK_3(pptr);
            tlv_type = EXTRACT_U_1(pptr);
            pptr++;
            tlv_len = EXTRACT_BE_U_2(pptr);  /* length, in *bits* */
            ttlv_len = (tlv_len + 7)/8;      /* length, in *bytes* */
            pptr += 2;

            switch(tlv_type) {
            case 1:
                if (buflen != 0) {
                    stringlen=nd_snprintf(buf,buflen, "\n\t\tcircuit status vector (%u) length: %u: 0x",
                                       tlv_type,
                                       tlv_len);
                    UPDATE_BUF_BUFLEN(buf, buflen, stringlen);
                }
                while (ttlv_len != 0) {
                    if (tlen < 1) {
                        if (buflen != 0) {
                            stringlen=nd_snprintf(buf,buflen, " (ran past the end)");
                            UPDATE_BUF_BUFLEN(buf, buflen, stringlen);
                        }
                        return plen + 2;
                    }
                    ND_TCHECK_1(pptr);
                    if (buflen != 0) {
                        stringlen=nd_snprintf(buf,buflen, "%02x",
                                           EXTRACT_U_1(pptr));
                        pptr++;
                        UPDATE_BUF_BUFLEN(buf, buflen, stringlen);
                    }
                    ttlv_len--;
                    tlen--;
                }
                break;
            default:
                if (buflen != 0) {
                    stringlen=nd_snprintf(buf,buflen, "\n\t\tunknown TLV #%u, length: %u",
                                       tlv_type,
                                       tlv_len);
                    UPDATE_BUF_BUFLEN(buf, buflen, stringlen);
                }
                if (tlen < ttlv_len) {
                    if (buflen != 0) {
                        stringlen=nd_snprintf(buf,buflen, " (ran past the end)");
                        UPDATE_BUF_BUFLEN(buf, buflen, stringlen);
                    }
                    return plen + 2;
                }
                tlen -= ttlv_len;
                break;
            }
        }
        return plen + 2;
    } else {
        /* complain bitterly ? */
        /* fall through */
        goto trunc;
    }

trunc:
    return -2;
}

int
decode_prefix6(netdissect_options *ndo,
               const u_char *pd, u_int itemlen, char *buf, u_int buflen)
{
    struct in6_addr addr;
    u_int plen, plenbytes;

    ND_TCHECK_1(pd);
    ITEMCHECK(1);
    plen = EXTRACT_U_1(pd);
    if (128 < plen)
        return -1;
    itemlen -= 1;

    memset(&addr, 0, sizeof(addr));
    plenbytes = (plen + 7) / 8;
    ND_TCHECK_LEN(pd + 1, plenbytes);
    ITEMCHECK(plenbytes);
    memcpy(&addr, pd + 1, plenbytes);
    if (plen % 8) {
        addr.s6_addr[plenbytes - 1] &=
            ((0xff00 >> (plen % 8)) & 0xff);
    }
    nd_snprintf(buf, buflen, "%s/%u", ip6addr_string(ndo, (const u_char *)&addr), plen);
    return 1 + plenbytes;

trunc:
    return -2;

badtlv:
    return -3;
}

static int
decode_labeled_prefix6(netdissect_options *ndo,
               const u_char *pptr, u_int itemlen, char *buf, u_int buflen)
{
    struct in6_addr addr;
    u_int plen, plenbytes;

    /* prefix length and label = 4 bytes */
    ND_TCHECK_4(pptr);
    ITEMCHECK(4);
    plen = EXTRACT_U_1(pptr); /* get prefix length */

    if (24 > plen)
        return -1;

    plen -= 24; /* adjust prefixlen - labellength */

    if (128 < plen)
        return -1;
    itemlen -= 4;

    memset(&addr, 0, sizeof(addr));
    plenbytes = (plen + 7) / 8;
    ND_TCHECK_LEN(pptr + 4, plenbytes);
    memcpy(&addr, pptr + 4, plenbytes);
    if (plen % 8) {
        addr.s6_addr[plenbytes - 1] &=
            ((0xff00 >> (plen % 8)) & 0xff);
    }
    /* the label may get offsetted by 4 bits so lets shift it right */
    nd_snprintf(buf, buflen, "%s/%u, label:%u %s",
             ip6addr_string(ndo, (const u_char *)&addr),
             plen,
             EXTRACT_BE_U_3(pptr + 1)>>4,
             ((EXTRACT_U_1(pptr + 3) & 1) == 0) ? "(BOGUS: Bottom of Stack NOT set!)" : "(bottom)" );

    return 4 + plenbytes;

trunc:
    return -2;

badtlv:
    return -3;
}

static int
decode_labeled_vpn_prefix6(netdissect_options *ndo,
                           const u_char *pptr, char *buf, u_int buflen)
{
    struct in6_addr addr;
    u_int plen;

    ND_TCHECK_1(pptr);
    plen = EXTRACT_U_1(pptr);   /* get prefix length */

    if ((24+64) > plen)
        return -1;

    plen -= (24+64); /* adjust prefixlen - labellength - RD len*/

    if (128 < plen)
        return -1;

    memset(&addr, 0, sizeof(addr));
    ND_TCHECK_LEN(pptr + 12, (plen + 7) / 8);
    memcpy(&addr, pptr + 12, (plen + 7) / 8);
    if (plen % 8) {
        addr.s6_addr[(plen + 7) / 8 - 1] &=
            ((0xff00 >> (plen % 8)) & 0xff);
    }
    /* the label may get offsetted by 4 bits so lets shift it right */
    nd_snprintf(buf, buflen, "RD: %s, %s/%u, label:%u %s",
             bgp_vpn_rd_print(ndo, pptr+4),
             ip6addr_string(ndo, (const u_char *)&addr),
             plen,
             EXTRACT_BE_U_3(pptr + 1)>>4,
             ((EXTRACT_U_1(pptr + 3) & 1) == 0) ? "(BOGUS: Bottom of Stack NOT set!)" : "(bottom)" );

    return 12 + (plen + 7) / 8;

trunc:
    return -2;
}

static int
decode_clnp_prefix(netdissect_options *ndo,
                   const u_char *pptr, char *buf, u_int buflen)
{
    uint8_t addr[19];
    u_int plen;

    ND_TCHECK_1(pptr);
    plen = EXTRACT_U_1(pptr); /* get prefix length */

    if (152 < plen)
        return -1;

    memset(&addr, 0, sizeof(addr));
    ND_TCHECK_LEN(pptr + 4, (plen + 7) / 8);
    memcpy(&addr, pptr + 4, (plen + 7) / 8);
    if (plen % 8) {
        addr[(plen + 7) / 8 - 1] &=
            ((0xff00 >> (plen % 8)) & 0xff);
    }
    nd_snprintf(buf, buflen, "%s/%u",
             isonsap_string(ndo, addr,(plen + 7) / 8),
             plen);

    return 1 + (plen + 7) / 8;

trunc:
    return -2;
}

static int
decode_labeled_vpn_clnp_prefix(netdissect_options *ndo,
                               const u_char *pptr, char *buf, u_int buflen)
{
    uint8_t addr[19];
    u_int plen;

    ND_TCHECK_1(pptr);
    plen = EXTRACT_U_1(pptr);   /* get prefix length */

    if ((24+64) > plen)
        return -1;

    plen -= (24+64); /* adjust prefixlen - labellength - RD len*/

    if (152 < plen)
        return -1;

    memset(&addr, 0, sizeof(addr));
    ND_TCHECK_LEN(pptr + 12, (plen + 7) / 8);
    memcpy(&addr, pptr + 12, (plen + 7) / 8);
    if (plen % 8) {
        addr[(plen + 7) / 8 - 1] &= ((0xff00 >> (plen % 8)) & 0xff);
    }
    /* the label may get offsetted by 4 bits so lets shift it right */
    nd_snprintf(buf, buflen, "RD: %s, %s/%u, label:%u %s",
             bgp_vpn_rd_print(ndo, pptr+4),
             isonsap_string(ndo, addr,(plen + 7) / 8),
             plen,
             EXTRACT_BE_U_3(pptr + 1)>>4,
             ((EXTRACT_U_1(pptr + 3) & 1) == 0) ? "(BOGUS: Bottom of Stack NOT set!)" : "(bottom)" );

    return 12 + (plen + 7) / 8;

trunc:
    return -2;
}

/*
 * bgp_attr_get_as_size
 *
 * Try to find the size of the ASs encoded in an as-path. It is not obvious, as
 * both Old speakers that do not support 4 byte AS, and the new speakers that do
 * support, exchange AS-Path with the same path-attribute type value 0x02.
 */
static u_int
bgp_attr_get_as_size(netdissect_options *ndo,
                     uint8_t bgpa_type, const u_char *pptr, u_int len)
{
    const u_char *tptr = pptr;

    /*
     * If the path attribute is the optional AS4 path type, then we already
     * know, that ASs must be encoded in 4 byte format.
     */
    if (bgpa_type == BGPTYPE_AS4_PATH) {
        return 4;
    }

    /*
     * Let us assume that ASs are of 2 bytes in size, and check if the AS-Path
     * TLV is good. If not, ask the caller to try with AS encoded as 4 bytes
     * each.
     */
    while (tptr < pptr + len) {
        ND_TCHECK_1(tptr);

        /*
         * If we do not find a valid segment type, our guess might be wrong.
         */
        if (EXTRACT_U_1(tptr) < BGP_AS_SEG_TYPE_MIN || EXTRACT_U_1(tptr) > BGP_AS_SEG_TYPE_MAX) {
            goto trunc;
        }
        ND_TCHECK_1(tptr + 1);
        tptr += 2 + EXTRACT_U_1(tptr + 1) * 2;
    }

    /*
     * If we correctly reached end of the AS path attribute data content,
     * then most likely ASs were indeed encoded as 2 bytes.
     */
    if (tptr == pptr + len) {
        return 2;
    }

trunc:

    /*
     * We can come here, either we did not have enough data, or if we
     * try to decode 4 byte ASs in 2 byte format. Either way, return 4,
     * so that calller can try to decode each AS as of 4 bytes. If indeed
     * there was not enough data, it will crib and end the parse anyways.
     */
    return 4;
}

/*
 * The only way to know that a BGP UPDATE message is using add path is
 * by checking if the capability is in the OPEN message which we may have missed.
 * So this function checks if it is possible that the update could contain add path
 * and if so it checks that standard BGP doesn't make sense.
 */
static int
check_add_path(netdissect_options *ndo, const u_char *pptr, u_int length,
               u_int max_prefix_length)
{
    u_int offset, prefix_length;

    if (length < 5) {
        return 0;
    }

    /*
     * Scan through the NLRI information under the assumpetion that
     * it doesn't have path IDs.
     */
    for (offset = 0; offset < length;) {
        offset += 4;
        if (!ND_TTEST_1(pptr + offset)) {
            /* We ran out of captured data; quit scanning. */
            break;
        }
        prefix_length = EXTRACT_U_1(pptr + offset);
        /*
         * Add 4 to cover the path id
         * and check the prefix length isn't greater than 32/128.
         */
        if (prefix_length > max_prefix_length) {
            return 0;
        }
        /* Add 1 for the prefix_length byte and prefix_length to cover the address */
        offset += 1 + ((prefix_length + 7) / 8);
    }
    /* check we haven't gone past the end of the section */
    if (offset > length) {
        return 0;
    }

    /* check it's not standard BGP */
    for (offset = 0; offset < length; ) {
        if (!ND_TTEST_1(pptr + offset)) {
            /* We ran out of captured data; quit scanning. */
            break;
        }
        prefix_length = EXTRACT_U_1(pptr + offset);
        /*
         * If the prefix_length is zero (0.0.0.0/0)
         * and since it's not the only address (length >= 5)
         * then it is add-path
         */
        if (prefix_length < 1 || prefix_length > max_prefix_length) {
            return 1;
        }
        offset += 1 + ((prefix_length + 7) / 8);
    }
    if (offset > length) {
        return 1;
    }

    /* assume not add-path by default */
    return 0;
}

static int
bgp_attr_print(netdissect_options *ndo,
               u_int atype, const u_char *pptr, u_int len)
{
    u_int i;
    uint16_t af;
    uint8_t safi, snpa, nhlen;
    union { /* copy buffer for bandwidth values */
        float f;
        uint32_t i;
    } bw;
    int advance;
    u_int tlen;
    const u_char *tptr;
    char buf[MAXHOSTNAMELEN + 100];
    u_int as_size;
    int add_path4, add_path6;
    u_int path_id = 0;

    tptr = pptr;
    tlen = len;

    switch (atype) {
    case BGPTYPE_ORIGIN:
        if (len != 1)
            ND_PRINT("invalid len");
        else {
            ND_TCHECK_1(tptr);
            ND_PRINT("%s", tok2str(bgp_origin_values,
                      "Unknown Origin Typecode",
                      EXTRACT_U_1(tptr)));
        }
        break;

    /*
     * Process AS4 byte path and AS2 byte path attributes here.
     */
    case BGPTYPE_AS4_PATH:
    case BGPTYPE_AS_PATH:
        if (len % 2) {
            ND_PRINT("invalid len");
            break;
        }
        if (!len) {
            ND_PRINT("empty");
            break;
        }

        /*
         * BGP updates exchanged between New speakers that support 4
         * byte AS, ASs are always encoded in 4 bytes. There is no
         * definitive way to find this, just by the packet's
         * contents. So, check for packet's TLV's sanity assuming
         * 2 bytes first, and it does not pass, assume that ASs are
         * encoded in 4 bytes format and move on.
         */
        as_size = bgp_attr_get_as_size(ndo, atype, pptr, len);

        while (tptr < pptr + len) {
            ND_TCHECK_1(tptr);
            ND_PRINT("%s", tok2str(bgp_as_path_segment_open_values,
                      "?", EXTRACT_U_1(tptr)));
            ND_TCHECK_1(tptr + 1);
            for (i = 0; i < EXTRACT_U_1(tptr + 1) * as_size; i += as_size) {
                ND_TCHECK_LEN(tptr + 2 + i, as_size);
                ND_PRINT("%s ",
                          as_printf(ndo, astostr, sizeof(astostr),
                          as_size == 2 ?
                              EXTRACT_BE_U_2(tptr + i + 2) :
                              EXTRACT_BE_U_4(tptr + i + 2)));
            }
            ND_TCHECK_1(tptr);
            ND_PRINT("%s", tok2str(bgp_as_path_segment_close_values,
                      "?", EXTRACT_U_1(tptr)));
            ND_TCHECK_1(tptr + 1);
            tptr += 2 + EXTRACT_U_1(tptr + 1) * as_size;
        }
        break;
    case BGPTYPE_NEXT_HOP:
        if (len != 4)
            ND_PRINT("invalid len");
        else {
            ND_TCHECK_4(tptr);
            ND_PRINT("%s", ipaddr_string(ndo, tptr));
        }
        break;
    case BGPTYPE_MULTI_EXIT_DISC:
    case BGPTYPE_LOCAL_PREF:
        if (len != 4)
            ND_PRINT("invalid len");
        else {
            ND_TCHECK_4(tptr);
            ND_PRINT("%u", EXTRACT_BE_U_4(tptr));
        }
        break;
    case BGPTYPE_ATOMIC_AGGREGATE:
        if (len != 0)
            ND_PRINT("invalid len");
        break;
    case BGPTYPE_AGGREGATOR:

        /*
         * Depending on the AS encoded is of 2 bytes or of 4 bytes,
         * the length of this PA can be either 6 bytes or 8 bytes.
         */
        if (len != 6 && len != 8) {
            ND_PRINT("invalid len");
            break;
        }
        ND_TCHECK_LEN(tptr, len);
        if (len == 6) {
            ND_PRINT(" AS #%s, origin %s",
                      as_printf(ndo, astostr, sizeof(astostr), EXTRACT_BE_U_2(tptr)),
                      ipaddr_string(ndo, tptr + 2));
        } else {
            ND_PRINT(" AS #%s, origin %s",
                      as_printf(ndo, astostr, sizeof(astostr),
                      EXTRACT_BE_U_4(tptr)), ipaddr_string(ndo, tptr + 4));
        }
        break;
    case BGPTYPE_AGGREGATOR4:
        if (len != 8) {
            ND_PRINT("invalid len");
            break;
        }
        ND_TCHECK_8(tptr);
        ND_PRINT(" AS #%s, origin %s",
                  as_printf(ndo, astostr, sizeof(astostr), EXTRACT_BE_U_4(tptr)),
                  ipaddr_string(ndo, tptr + 4));
        break;
    case BGPTYPE_COMMUNITIES:
        if (len % 4) {
            ND_PRINT("invalid len");
            break;
        }
        while (tlen != 0) {
            uint32_t comm;
            ND_TCHECK_4(tptr);
            if (tlen < 4)
                goto trunc;
            comm = EXTRACT_BE_U_4(tptr);
            switch (comm) {
            case BGP_COMMUNITY_NO_EXPORT:
                ND_PRINT(" NO_EXPORT");
                break;
            case BGP_COMMUNITY_NO_ADVERT:
                ND_PRINT(" NO_ADVERTISE");
                break;
            case BGP_COMMUNITY_NO_EXPORT_SUBCONFED:
                ND_PRINT(" NO_EXPORT_SUBCONFED");
                break;
            default:
                ND_PRINT("%u:%u%s",
                         (comm >> 16) & 0xffff,
                         comm & 0xffff,
                         (tlen>4) ? ", " : "");
                break;
            }
            tlen -=4;
            tptr +=4;
        }
        break;
    case BGPTYPE_ORIGINATOR_ID:
        if (len != 4) {
            ND_PRINT("invalid len");
            break;
        }
        ND_TCHECK_4(tptr);
        ND_PRINT("%s",ipaddr_string(ndo, tptr));
        break;
    case BGPTYPE_CLUSTER_LIST:
        if (len % 4) {
            ND_PRINT("invalid len");
            break;
        }
        while (tlen != 0) {
            ND_TCHECK_4(tptr);
            if (tlen < 4)
                goto trunc;
            ND_PRINT("%s%s",
                      ipaddr_string(ndo, tptr),
                      (tlen>4) ? ", " : "");
            tlen -=4;
            tptr +=4;
        }
        break;
    case BGPTYPE_MP_REACH_NLRI:
        ND_TCHECK_3(tptr);
        if (tlen < 3)
            goto trunc;
        af = EXTRACT_BE_U_2(tptr);
        safi = EXTRACT_U_1(tptr + 2);

        ND_PRINT("\n\t    AFI: %s (%u), %sSAFI: %s (%u)",
                  tok2str(af_values, "Unknown AFI", af),
                  af,
                  (safi>128) ? "vendor specific " : "", /* 128 is meanwhile wellknown */
                  tok2str(bgp_safi_values, "Unknown SAFI", safi),
                  safi);

        switch(af<<8 | safi) {
        case (AFNUM_INET<<8 | SAFNUM_UNICAST):
        case (AFNUM_INET<<8 | SAFNUM_MULTICAST):
        case (AFNUM_INET<<8 | SAFNUM_UNIMULTICAST):
        case (AFNUM_INET<<8 | SAFNUM_LABUNICAST):
        case (AFNUM_INET<<8 | SAFNUM_RT_ROUTING_INFO):
        case (AFNUM_INET<<8 | SAFNUM_VPNUNICAST):
        case (AFNUM_INET<<8 | SAFNUM_VPNMULTICAST):
        case (AFNUM_INET<<8 | SAFNUM_VPNUNIMULTICAST):
        case (AFNUM_INET<<8 | SAFNUM_MULTICAST_VPN):
        case (AFNUM_INET<<8 | SAFNUM_MDT):
        case (AFNUM_INET6<<8 | SAFNUM_UNICAST):
        case (AFNUM_INET6<<8 | SAFNUM_MULTICAST):
        case (AFNUM_INET6<<8 | SAFNUM_UNIMULTICAST):
        case (AFNUM_INET6<<8 | SAFNUM_LABUNICAST):
        case (AFNUM_INET6<<8 | SAFNUM_VPNUNICAST):
        case (AFNUM_INET6<<8 | SAFNUM_VPNMULTICAST):
        case (AFNUM_INET6<<8 | SAFNUM_VPNUNIMULTICAST):
        case (AFNUM_NSAP<<8 | SAFNUM_UNICAST):
        case (AFNUM_NSAP<<8 | SAFNUM_MULTICAST):
        case (AFNUM_NSAP<<8 | SAFNUM_UNIMULTICAST):
        case (AFNUM_NSAP<<8 | SAFNUM_VPNUNICAST):
        case (AFNUM_NSAP<<8 | SAFNUM_VPNMULTICAST):
        case (AFNUM_NSAP<<8 | SAFNUM_VPNUNIMULTICAST):
        case (AFNUM_L2VPN<<8 | SAFNUM_VPNUNICAST):
        case (AFNUM_L2VPN<<8 | SAFNUM_VPNMULTICAST):
        case (AFNUM_L2VPN<<8 | SAFNUM_VPNUNIMULTICAST):
        case (AFNUM_VPLS<<8 | SAFNUM_VPLS):
            break;
        default:
            ND_TCHECK_LEN(tptr, tlen);
            ND_PRINT("\n\t    no AFI %u / SAFI %u decoder", af, safi);
            if (ndo->ndo_vflag <= 1)
                print_unknown_data(ndo, tptr, "\n\t    ", tlen);
            goto done;
            break;
        }

        tptr +=3;

        ND_TCHECK_1(tptr);
        nhlen = EXTRACT_U_1(tptr);
        tlen = nhlen;
        tptr++;

        if (tlen) {
            u_int nnh = 0;
            ND_PRINT("\n\t    nexthop: ");
            while (tlen != 0) {
                if (nnh++ > 0) {
                    ND_PRINT(", " );
                }
                switch(af<<8 | safi) {
                case (AFNUM_INET<<8 | SAFNUM_UNICAST):
                case (AFNUM_INET<<8 | SAFNUM_MULTICAST):
                case (AFNUM_INET<<8 | SAFNUM_UNIMULTICAST):
                case (AFNUM_INET<<8 | SAFNUM_LABUNICAST):
                case (AFNUM_INET<<8 | SAFNUM_RT_ROUTING_INFO):
                case (AFNUM_INET<<8 | SAFNUM_MULTICAST_VPN):
                case (AFNUM_INET<<8 | SAFNUM_MDT):
                    if (tlen < sizeof(nd_ipv4)) {
                        ND_PRINT("invalid len");
                        tlen = 0;
                    } else {
                        ND_TCHECK_LEN(tptr, sizeof(nd_ipv4));
                        ND_PRINT("%s",ipaddr_string(ndo, tptr));
                        tlen -= sizeof(nd_ipv4);
                        tptr += sizeof(nd_ipv4);
                    }
                    break;
                case (AFNUM_INET<<8 | SAFNUM_VPNUNICAST):
                case (AFNUM_INET<<8 | SAFNUM_VPNMULTICAST):
                case (AFNUM_INET<<8 | SAFNUM_VPNUNIMULTICAST):
                    if (tlen < sizeof(nd_ipv4)+BGP_VPN_RD_LEN) {
                        ND_PRINT("invalid len");
                        tlen = 0;
                    } else {
                        ND_TCHECK_LEN(tptr,
                                      sizeof(nd_ipv4) + BGP_VPN_RD_LEN);
                        ND_PRINT("RD: %s, %s",
                                  bgp_vpn_rd_print(ndo, tptr),
                                  ipaddr_string(ndo, tptr+BGP_VPN_RD_LEN));
                        tlen -= (sizeof(nd_ipv4)+BGP_VPN_RD_LEN);
                        tptr += (sizeof(nd_ipv4)+BGP_VPN_RD_LEN);
                    }
                    break;
                case (AFNUM_INET6<<8 | SAFNUM_UNICAST):
                case (AFNUM_INET6<<8 | SAFNUM_MULTICAST):
                case (AFNUM_INET6<<8 | SAFNUM_UNIMULTICAST):
                case (AFNUM_INET6<<8 | SAFNUM_LABUNICAST):
                    if (tlen < sizeof(nd_ipv6)) {
                        ND_PRINT("invalid len");
                        tlen = 0;
                    } else {
                        ND_TCHECK_LEN(tptr, sizeof(nd_ipv6));
                        ND_PRINT("%s", ip6addr_string(ndo, tptr));
                        tlen -= sizeof(nd_ipv6);
                        tptr += sizeof(nd_ipv6);
                    }
                    break;
                case (AFNUM_INET6<<8 | SAFNUM_VPNUNICAST):
                case (AFNUM_INET6<<8 | SAFNUM_VPNMULTICAST):
                case (AFNUM_INET6<<8 | SAFNUM_VPNUNIMULTICAST):
                    if (tlen < sizeof(nd_ipv6)+BGP_VPN_RD_LEN) {
                        ND_PRINT("invalid len");
                        tlen = 0;
                    } else {
                        ND_TCHECK_LEN(tptr,
                                      sizeof(nd_ipv6) + BGP_VPN_RD_LEN);
                        ND_PRINT("RD: %s, %s",
                                  bgp_vpn_rd_print(ndo, tptr),
                                  ip6addr_string(ndo, tptr+BGP_VPN_RD_LEN));
                        tlen -= (sizeof(nd_ipv6)+BGP_VPN_RD_LEN);
                        tptr += (sizeof(nd_ipv6)+BGP_VPN_RD_LEN);
                    }
                    break;
                case (AFNUM_VPLS<<8 | SAFNUM_VPLS):
                case (AFNUM_L2VPN<<8 | SAFNUM_VPNUNICAST):
                case (AFNUM_L2VPN<<8 | SAFNUM_VPNMULTICAST):
                case (AFNUM_L2VPN<<8 | SAFNUM_VPNUNIMULTICAST):
                    if (tlen < sizeof(nd_ipv4)) {
                        ND_PRINT("invalid len");
                        tlen = 0;
                    } else {
                        ND_TCHECK_LEN(tptr, sizeof(nd_ipv4));
                        ND_PRINT("%s", ipaddr_string(ndo, tptr));
                        tlen -= (sizeof(nd_ipv4));
                        tptr += (sizeof(nd_ipv4));
                    }
                    break;
                case (AFNUM_NSAP<<8 | SAFNUM_UNICAST):
                case (AFNUM_NSAP<<8 | SAFNUM_MULTICAST):
                case (AFNUM_NSAP<<8 | SAFNUM_UNIMULTICAST):
                    ND_TCHECK_LEN(tptr, tlen);
                    ND_PRINT("%s", isonsap_string(ndo, tptr, tlen));
                    tptr += tlen;
                    tlen = 0;
                    break;

                case (AFNUM_NSAP<<8 | SAFNUM_VPNUNICAST):
                case (AFNUM_NSAP<<8 | SAFNUM_VPNMULTICAST):
                case (AFNUM_NSAP<<8 | SAFNUM_VPNUNIMULTICAST):
                    if (tlen < BGP_VPN_RD_LEN+1) {
                        ND_PRINT("invalid len");
                        tlen = 0;
                    } else {
                        ND_TCHECK_LEN(tptr, tlen);
                        ND_PRINT("RD: %s, %s",
                                  bgp_vpn_rd_print(ndo, tptr),
                                  isonsap_string(ndo, tptr+BGP_VPN_RD_LEN,tlen-BGP_VPN_RD_LEN));
                        /* rfc986 mapped IPv4 address ? */
                        if (EXTRACT_BE_U_4(tptr + BGP_VPN_RD_LEN) ==  0x47000601)
                            ND_PRINT(" = %s", ipaddr_string(ndo, tptr+BGP_VPN_RD_LEN+4));
                        /* rfc1888 mapped IPv6 address ? */
                        else if (EXTRACT_BE_U_3(tptr + BGP_VPN_RD_LEN) ==  0x350000)
                            ND_PRINT(" = %s", ip6addr_string(ndo, tptr+BGP_VPN_RD_LEN+3));
                        tptr += tlen;
                        tlen = 0;
                    }
                    break;
                default:
                    ND_TCHECK_LEN(tptr, tlen);
                    ND_PRINT("no AFI %u/SAFI %u decoder", af, safi);
                    if (ndo->ndo_vflag <= 1)
                        print_unknown_data(ndo, tptr, "\n\t    ", tlen);
                    tptr += tlen;
                    tlen = 0;
                    goto done;
                    break;
                }
            }
        }
        ND_PRINT(", nh-length: %u", nhlen);
        tptr += tlen;

        ND_TCHECK_1(tptr);
        snpa = EXTRACT_U_1(tptr);
        tptr++;

        if (snpa) {
            ND_PRINT("\n\t    %u SNPA", snpa);
            for (/*nothing*/; snpa != 0; snpa--) {
                ND_TCHECK_1(tptr);
                ND_PRINT("\n\t      %u bytes", EXTRACT_U_1(tptr));
                tptr += EXTRACT_U_1(tptr) + 1;
            }
        } else {
            ND_PRINT(", no SNPA");
        }

        add_path4 = check_add_path(ndo, tptr, (len-(tptr - pptr)), 32);
        add_path6 = check_add_path(ndo, tptr, (len-(tptr - pptr)), 128);

        while (tptr < pptr + len) {
            switch (af<<8 | safi) {
            case (AFNUM_INET<<8 | SAFNUM_UNICAST):
            case (AFNUM_INET<<8 | SAFNUM_MULTICAST):
            case (AFNUM_INET<<8 | SAFNUM_UNIMULTICAST):
                if (add_path4) {
                    path_id = EXTRACT_BE_U_4(tptr);
                    tptr += 4;
                }
                advance = decode_prefix4(ndo, tptr, len, buf, sizeof(buf));
                if (advance == -1)
                    ND_PRINT("\n\t    (illegal prefix length)");
                else if (advance == -2)
                    goto trunc;
                else if (advance == -3)
                    break; /* bytes left, but not enough */
                else
                    ND_PRINT("\n\t      %s", buf);
                if (add_path4) {
                    ND_PRINT("   Path Id: %u", path_id);
                }
                break;
            case (AFNUM_INET<<8 | SAFNUM_LABUNICAST):
                advance = decode_labeled_prefix4(ndo, tptr, len, buf, sizeof(buf));
                if (advance == -1)
                    ND_PRINT("\n\t    (illegal prefix length)");
                else if (advance == -2)
                    goto trunc;
                else if (advance == -3)
                    break; /* bytes left, but not enough */
                else
                    ND_PRINT("\n\t      %s", buf);
                break;
            case (AFNUM_INET<<8 | SAFNUM_VPNUNICAST):
            case (AFNUM_INET<<8 | SAFNUM_VPNMULTICAST):
            case (AFNUM_INET<<8 | SAFNUM_VPNUNIMULTICAST):
                advance = decode_labeled_vpn_prefix4(ndo, tptr, buf, sizeof(buf));
                if (advance == -1)
                    ND_PRINT("\n\t    (illegal prefix length)");
                else if (advance == -2)
                    goto trunc;
                else
                    ND_PRINT("\n\t      %s", buf);
                break;
            case (AFNUM_INET<<8 | SAFNUM_RT_ROUTING_INFO):
                advance = decode_rt_routing_info(ndo, tptr, buf, sizeof(buf));
                if (advance == -1)
                    ND_PRINT("\n\t    (illegal prefix length)");
                else if (advance == -2)
                    goto trunc;
                else
                    ND_PRINT("\n\t      %s", buf);
                break;
            case (AFNUM_INET<<8 | SAFNUM_MULTICAST_VPN): /* fall through */
            case (AFNUM_INET6<<8 | SAFNUM_MULTICAST_VPN):
                advance = decode_multicast_vpn(ndo, tptr, buf, sizeof(buf));
                if (advance == -1)
                    ND_PRINT("\n\t    (illegal prefix length)");
                else if (advance == -2)
                    goto trunc;
                else
                    ND_PRINT("\n\t      %s", buf);
                break;

            case (AFNUM_INET<<8 | SAFNUM_MDT):
                advance = decode_mdt_vpn_nlri(ndo, tptr, buf, sizeof(buf));
                if (advance == -1)
                    ND_PRINT("\n\t    (illegal prefix length)");
                else if (advance == -2)
                    goto trunc;
                else
                    ND_PRINT("\n\t      %s", buf);
                break;
            case (AFNUM_INET6<<8 | SAFNUM_UNICAST):
            case (AFNUM_INET6<<8 | SAFNUM_MULTICAST):
            case (AFNUM_INET6<<8 | SAFNUM_UNIMULTICAST):
                if (add_path6) {
                    path_id = EXTRACT_BE_U_4(tptr);
                    tptr += 4;
                }
                advance = decode_prefix6(ndo, tptr, len, buf, sizeof(buf));
                if (advance == -1)
                    ND_PRINT("\n\t    (illegal prefix length)");
                else if (advance == -2)
                    goto trunc;
                else if (advance == -3)
                    break; /* bytes left, but not enough */
                else
                    ND_PRINT("\n\t      %s", buf);
                if (add_path6) {
                    ND_PRINT("   Path Id: %u", path_id);
                }
                break;
            case (AFNUM_INET6<<8 | SAFNUM_LABUNICAST):
                advance = decode_labeled_prefix6(ndo, tptr, len, buf, sizeof(buf));
                if (advance == -1)
                    ND_PRINT("\n\t    (illegal prefix length)");
                else if (advance == -2)
                    goto trunc;
                else if (advance == -3)
                    break; /* bytes left, but not enough */
                else
                    ND_PRINT("\n\t      %s", buf);
                break;
            case (AFNUM_INET6<<8 | SAFNUM_VPNUNICAST):
            case (AFNUM_INET6<<8 | SAFNUM_VPNMULTICAST):
            case (AFNUM_INET6<<8 | SAFNUM_VPNUNIMULTICAST):
                advance = decode_labeled_vpn_prefix6(ndo, tptr, buf, sizeof(buf));
                if (advance == -1)
                    ND_PRINT("\n\t    (illegal prefix length)");
                else if (advance == -2)
                    goto trunc;
                else
                    ND_PRINT("\n\t      %s", buf);
                break;
            case (AFNUM_VPLS<<8 | SAFNUM_VPLS):
            case (AFNUM_L2VPN<<8 | SAFNUM_VPNUNICAST):
            case (AFNUM_L2VPN<<8 | SAFNUM_VPNMULTICAST):
            case (AFNUM_L2VPN<<8 | SAFNUM_VPNUNIMULTICAST):
                advance = decode_labeled_vpn_l2(ndo, tptr, buf, sizeof(buf));
                if (advance == -1)
                    ND_PRINT("\n\t    (illegal length)");
                else if (advance == -2)
                    goto trunc;
                else
                    ND_PRINT("\n\t      %s", buf);
                break;
            case (AFNUM_NSAP<<8 | SAFNUM_UNICAST):
            case (AFNUM_NSAP<<8 | SAFNUM_MULTICAST):
            case (AFNUM_NSAP<<8 | SAFNUM_UNIMULTICAST):
                advance = decode_clnp_prefix(ndo, tptr, buf, sizeof(buf));
                if (advance == -1)
                    ND_PRINT("\n\t    (illegal prefix length)");
                else if (advance == -2)
                    goto trunc;
                else
                    ND_PRINT("\n\t      %s", buf);
                break;
            case (AFNUM_NSAP<<8 | SAFNUM_VPNUNICAST):
            case (AFNUM_NSAP<<8 | SAFNUM_VPNMULTICAST):
            case (AFNUM_NSAP<<8 | SAFNUM_VPNUNIMULTICAST):
                advance = decode_labeled_vpn_clnp_prefix(ndo, tptr, buf, sizeof(buf));
                if (advance == -1)
                    ND_PRINT("\n\t    (illegal prefix length)");
                else if (advance == -2)
                    goto trunc;
                else
                    ND_PRINT("\n\t      %s", buf);
                break;
            default:
                ND_TCHECK_LEN(tptr, tlen);
                ND_PRINT("\n\t    no AFI %u / SAFI %u decoder", af, safi);
                if (ndo->ndo_vflag <= 1)
                    print_unknown_data(ndo, tptr, "\n\t    ", tlen);
                advance = 0;
                tptr = pptr + len;
                break;
            }
            if (advance < 0)
                break;
            tptr += advance;
        }
    done:
        break;

    case BGPTYPE_MP_UNREACH_NLRI:
        ND_TCHECK_LEN(tptr, BGP_MP_NLRI_MINSIZE);
        af = EXTRACT_BE_U_2(tptr);
        safi = EXTRACT_U_1(tptr + 2);

        ND_PRINT("\n\t    AFI: %s (%u), %sSAFI: %s (%u)",
                  tok2str(af_values, "Unknown AFI", af),
                  af,
                  (safi>128) ? "vendor specific " : "", /* 128 is meanwhile wellknown */
                  tok2str(bgp_safi_values, "Unknown SAFI", safi),
                  safi);

        if (len == BGP_MP_NLRI_MINSIZE)
            ND_PRINT("\n\t      End-of-Rib Marker (empty NLRI)");

        tptr += 3;

        add_path4 = check_add_path(ndo, tptr, (len-(tptr - pptr)), 32);
        add_path6 = check_add_path(ndo, tptr, (len-(tptr - pptr)), 128);

        while (tptr < pptr + len) {
            switch (af<<8 | safi) {
            case (AFNUM_INET<<8 | SAFNUM_UNICAST):
            case (AFNUM_INET<<8 | SAFNUM_MULTICAST):
            case (AFNUM_INET<<8 | SAFNUM_UNIMULTICAST):
                if (add_path4) {
                    path_id = EXTRACT_BE_U_4(tptr);
                    tptr += 4;
                }
                advance = decode_prefix4(ndo, tptr, len, buf, sizeof(buf));
                if (advance == -1)
                    ND_PRINT("\n\t    (illegal prefix length)");
                else if (advance == -2)
                    goto trunc;
                else if (advance == -3)
                    break; /* bytes left, but not enough */
                else
                    ND_PRINT("\n\t      %s", buf);
                if (add_path4) {
                    ND_PRINT("   Path Id: %u", path_id);
                }
                break;
            case (AFNUM_INET<<8 | SAFNUM_LABUNICAST):
                advance = decode_labeled_prefix4(ndo, tptr, len, buf, sizeof(buf));
                if (advance == -1)
                    ND_PRINT("\n\t    (illegal prefix length)");
                else if (advance == -2)
                    goto trunc;
                else if (advance == -3)
                    break; /* bytes left, but not enough */
                else
                    ND_PRINT("\n\t      %s", buf);
                break;
            case (AFNUM_INET<<8 | SAFNUM_VPNUNICAST):
            case (AFNUM_INET<<8 | SAFNUM_VPNMULTICAST):
            case (AFNUM_INET<<8 | SAFNUM_VPNUNIMULTICAST):
                advance = decode_labeled_vpn_prefix4(ndo, tptr, buf, sizeof(buf));
                if (advance == -1)
                    ND_PRINT("\n\t    (illegal prefix length)");
                else if (advance == -2)
                    goto trunc;
                else
                    ND_PRINT("\n\t      %s", buf);
                break;
            case (AFNUM_INET6<<8 | SAFNUM_UNICAST):
            case (AFNUM_INET6<<8 | SAFNUM_MULTICAST):
            case (AFNUM_INET6<<8 | SAFNUM_UNIMULTICAST):
                if (add_path6) {
                    path_id = EXTRACT_BE_U_4(tptr);
                    tptr += 4;
                }
                advance = decode_prefix6(ndo, tptr, len, buf, sizeof(buf));
                if (advance == -1)
                    ND_PRINT("\n\t    (illegal prefix length)");
                else if (advance == -2)
                    goto trunc;
                else if (advance == -3)
                    break; /* bytes left, but not enough */
                else
                    ND_PRINT("\n\t      %s", buf);
                if (add_path6) {
                    ND_PRINT("   Path Id: %u", path_id);
                }
                break;
            case (AFNUM_INET6<<8 | SAFNUM_LABUNICAST):
                advance = decode_labeled_prefix6(ndo, tptr, len, buf, sizeof(buf));
                if (advance == -1)
                    ND_PRINT("\n\t    (illegal prefix length)");
                else if (advance == -2)
                    goto trunc;
                else if (advance == -3)
                    break; /* bytes left, but not enough */
                else
                    ND_PRINT("\n\t      %s", buf);
                break;
            case (AFNUM_INET6<<8 | SAFNUM_VPNUNICAST):
            case (AFNUM_INET6<<8 | SAFNUM_VPNMULTICAST):
            case (AFNUM_INET6<<8 | SAFNUM_VPNUNIMULTICAST):
                advance = decode_labeled_vpn_prefix6(ndo, tptr, buf, sizeof(buf));
                if (advance == -1)
                    ND_PRINT("\n\t    (illegal prefix length)");
                else if (advance == -2)
                    goto trunc;
                else
                    ND_PRINT("\n\t      %s", buf);
                break;
            case (AFNUM_VPLS<<8 | SAFNUM_VPLS):
            case (AFNUM_L2VPN<<8 | SAFNUM_VPNUNICAST):
            case (AFNUM_L2VPN<<8 | SAFNUM_VPNMULTICAST):
            case (AFNUM_L2VPN<<8 | SAFNUM_VPNUNIMULTICAST):
                advance = decode_labeled_vpn_l2(ndo, tptr, buf, sizeof(buf));
                if (advance == -1)
                    ND_PRINT("\n\t    (illegal length)");
                else if (advance == -2)
                    goto trunc;
                else
                    ND_PRINT("\n\t      %s", buf);
                break;
            case (AFNUM_NSAP<<8 | SAFNUM_UNICAST):
            case (AFNUM_NSAP<<8 | SAFNUM_MULTICAST):
            case (AFNUM_NSAP<<8 | SAFNUM_UNIMULTICAST):
                advance = decode_clnp_prefix(ndo, tptr, buf, sizeof(buf));
                if (advance == -1)
                    ND_PRINT("\n\t    (illegal prefix length)");
                else if (advance == -2)
                    goto trunc;
                else
                    ND_PRINT("\n\t      %s", buf);
                break;
            case (AFNUM_NSAP<<8 | SAFNUM_VPNUNICAST):
            case (AFNUM_NSAP<<8 | SAFNUM_VPNMULTICAST):
            case (AFNUM_NSAP<<8 | SAFNUM_VPNUNIMULTICAST):
                advance = decode_labeled_vpn_clnp_prefix(ndo, tptr, buf, sizeof(buf));
                if (advance == -1)
                    ND_PRINT("\n\t    (illegal prefix length)");
                else if (advance == -2)
                    goto trunc;
                else
                    ND_PRINT("\n\t      %s", buf);
                break;
            case (AFNUM_INET<<8 | SAFNUM_MDT):
                advance = decode_mdt_vpn_nlri(ndo, tptr, buf, sizeof(buf));
                if (advance == -1)
                    ND_PRINT("\n\t    (illegal prefix length)");
                else if (advance == -2)
                    goto trunc;
                else
                    ND_PRINT("\n\t      %s", buf);
                break;
            case (AFNUM_INET<<8 | SAFNUM_MULTICAST_VPN): /* fall through */
            case (AFNUM_INET6<<8 | SAFNUM_MULTICAST_VPN):
                advance = decode_multicast_vpn(ndo, tptr, buf, sizeof(buf));
                if (advance == -1)
                    ND_PRINT("\n\t    (illegal prefix length)");
                else if (advance == -2)
                    goto trunc;
                else
                    ND_PRINT("\n\t      %s", buf);
                break;
            default:
                ND_TCHECK_LEN(tptr - 3, tlen);
                ND_PRINT("no AFI %u / SAFI %u decoder", af, safi);
                if (ndo->ndo_vflag <= 1)
                    print_unknown_data(ndo, tptr-3, "\n\t    ", tlen);
                advance = 0;
                tptr = pptr + len;
                break;
            }
            if (advance < 0)
                break;
            tptr += advance;
        }
        break;
    case BGPTYPE_EXTD_COMMUNITIES:
        if (len % 8) {
            ND_PRINT("invalid len");
            break;
        }
        while (tlen != 0) {
            uint16_t extd_comm;

            ND_TCHECK_2(tptr);
            if (tlen < 2)
                goto trunc;
            extd_comm=EXTRACT_BE_U_2(tptr);

            ND_PRINT("\n\t    %s (0x%04x), Flags [%s]",
                      tok2str(bgp_extd_comm_subtype_values,
                              "unknown extd community typecode",
                              extd_comm),
                      extd_comm,
                      bittok2str(bgp_extd_comm_flag_values, "none", extd_comm));

            ND_TCHECK_6(tptr + 2);
            if (tlen < 8)
                goto trunc;
            switch(extd_comm) {
            case BGP_EXT_COM_RT_0:
            case BGP_EXT_COM_RO_0:
            case BGP_EXT_COM_L2VPN_RT_0:
                ND_PRINT(": %u:%u (= %s)",
                          EXTRACT_BE_U_2(tptr + 2),
                          EXTRACT_BE_U_4(tptr + 4),
                          ipaddr_string(ndo, tptr+4));
                break;
            case BGP_EXT_COM_RT_1:
            case BGP_EXT_COM_RO_1:
            case BGP_EXT_COM_L2VPN_RT_1:
            case BGP_EXT_COM_VRF_RT_IMP:
                ND_PRINT(": %s:%u",
                          ipaddr_string(ndo, tptr+2),
                          EXTRACT_BE_U_2(tptr + 6));
                break;
            case BGP_EXT_COM_RT_2:
            case BGP_EXT_COM_RO_2:
                ND_PRINT(": %s:%u",
                          as_printf(ndo, astostr, sizeof(astostr),
                          EXTRACT_BE_U_4(tptr + 2)), EXTRACT_BE_U_2(tptr + 6));
                break;
            case BGP_EXT_COM_LINKBAND:
                bw.i = EXTRACT_BE_U_4(tptr + 2);
                ND_PRINT(": bandwidth: %.3f Mbps",
                          bw.f*8/1000000);
                break;
            case BGP_EXT_COM_VPN_ORIGIN:
            case BGP_EXT_COM_VPN_ORIGIN2:
            case BGP_EXT_COM_VPN_ORIGIN3:
            case BGP_EXT_COM_VPN_ORIGIN4:
            case BGP_EXT_COM_OSPF_RID:
            case BGP_EXT_COM_OSPF_RID2:
                ND_PRINT("%s", ipaddr_string(ndo, tptr+2));
                break;
            case BGP_EXT_COM_OSPF_RTYPE:
            case BGP_EXT_COM_OSPF_RTYPE2:
                ND_PRINT(": area:%s, router-type:%s, metric-type:%s%s",
                          ipaddr_string(ndo, tptr+2),
                          tok2str(bgp_extd_comm_ospf_rtype_values,
                                  "unknown (0x%02x)",
                                  EXTRACT_U_1((tptr + 6))),
                          (EXTRACT_U_1(tptr + 7) &  BGP_OSPF_RTYPE_METRIC_TYPE) ? "E2" : "",
                          ((EXTRACT_U_1(tptr + 6) == BGP_OSPF_RTYPE_EXT) || (EXTRACT_U_1(tptr + 6) == BGP_OSPF_RTYPE_NSSA)) ? "E1" : "");
                break;
            case BGP_EXT_COM_L2INFO:
                ND_PRINT(": %s Control Flags [0x%02x]:MTU %u",
                          tok2str(l2vpn_encaps_values,
                                  "unknown encaps",
                                  EXTRACT_U_1((tptr + 2))),
                          EXTRACT_U_1((tptr + 3)),
                          EXTRACT_BE_U_2(tptr + 4));
                break;
            case BGP_EXT_COM_SOURCE_AS:
                ND_PRINT(": AS %u", EXTRACT_BE_U_2(tptr + 2));
                break;
            default:
                ND_TCHECK_8(tptr);
                print_unknown_data(ndo, tptr, "\n\t      ", 8);
                break;
            }
            tlen -= 8;
            tptr += 8;
        }
        break;

    case BGPTYPE_PMSI_TUNNEL:
    {
        uint8_t tunnel_type, flags;

        ND_TCHECK_5(tptr);
        if (tlen < 5)
            goto trunc;
        flags = EXTRACT_U_1(tptr);
        tunnel_type = EXTRACT_U_1(tptr + 1);
        tlen = len;

        ND_PRINT("\n\t    Tunnel-type %s (%u), Flags [%s], MPLS Label %u",
                  tok2str(bgp_pmsi_tunnel_values, "Unknown", tunnel_type),
                  tunnel_type,
                  bittok2str(bgp_pmsi_flag_values, "none", flags),
                  EXTRACT_BE_U_3(tptr + 2)>>4);

        tptr +=5;
        tlen -= 5;

        switch (tunnel_type) {
        case BGP_PMSI_TUNNEL_PIM_SM: /* fall through */
        case BGP_PMSI_TUNNEL_PIM_BIDIR:
            ND_TCHECK_8(tptr);
            ND_PRINT("\n\t      Sender %s, P-Group %s",
                      ipaddr_string(ndo, tptr),
                      ipaddr_string(ndo, tptr+4));
            break;

        case BGP_PMSI_TUNNEL_PIM_SSM:
            ND_TCHECK_8(tptr);
            ND_PRINT("\n\t      Root-Node %s, P-Group %s",
                      ipaddr_string(ndo, tptr),
                      ipaddr_string(ndo, tptr+4));
            break;
        case BGP_PMSI_TUNNEL_INGRESS:
            ND_TCHECK_4(tptr);
            ND_PRINT("\n\t      Tunnel-Endpoint %s",
                      ipaddr_string(ndo, tptr));
            break;
        case BGP_PMSI_TUNNEL_LDP_P2MP: /* fall through */
        case BGP_PMSI_TUNNEL_LDP_MP2MP:
            ND_TCHECK_8(tptr);
            ND_PRINT("\n\t      Root-Node %s, LSP-ID 0x%08x",
                      ipaddr_string(ndo, tptr),
                      EXTRACT_BE_U_4(tptr + 4));
            break;
        case BGP_PMSI_TUNNEL_RSVP_P2MP:
            ND_TCHECK_8(tptr);
            ND_PRINT("\n\t      Extended-Tunnel-ID %s, P2MP-ID 0x%08x",
                      ipaddr_string(ndo, tptr),
                      EXTRACT_BE_U_4(tptr + 4));
            break;
        default:
            if (ndo->ndo_vflag <= 1) {
                print_unknown_data(ndo, tptr, "\n\t      ", tlen);
            }
        }
        break;
    }
    case BGPTYPE_AIGP:
    {
        uint8_t type;
        uint16_t length;

        tlen = len;

        while (tlen >= 3) {

            ND_TCHECK_3(tptr);

            type = EXTRACT_U_1(tptr);
            length = EXTRACT_BE_U_2(tptr + 1);
            tptr += 3;
            tlen -= 3;

            ND_PRINT("\n\t    %s TLV (%u), length %u",
                      tok2str(bgp_aigp_values, "Unknown", type),
                      type, length);

            if (length < 3)
                goto trunc;
            length -= 3;

            /*
             * Check if we can read the TLV data.
             */
            ND_TCHECK_LEN(tptr + 3, length);
            if (tlen < length)
                goto trunc;

            switch (type) {

            case BGP_AIGP_TLV:
                if (length < 8)
                    goto trunc;
                ND_PRINT(", metric %" PRIu64,
                          EXTRACT_BE_U_8(tptr));
                break;

            default:
                if (ndo->ndo_vflag <= 1) {
                    print_unknown_data(ndo, tptr,"\n\t      ", length);
                }
            }

            tptr += length;
            tlen -= length;
        }
        break;
    }
    case BGPTYPE_ATTR_SET:
        ND_TCHECK_4(tptr);
        if (len < 4)
            goto trunc;
        ND_PRINT("\n\t    Origin AS: %s",
                  as_printf(ndo, astostr, sizeof(astostr), EXTRACT_BE_U_4(tptr)));
        tptr += 4;
        len -= 4;

        while (len) {
            u_int aflags, alenlen, alen;

            ND_TCHECK_2(tptr);
            if (len < 2) {
                ND_PRINT(" [path attr too short]");
                tptr += len;
                break;
            }
            aflags = EXTRACT_U_1(tptr);
            atype = EXTRACT_U_1(tptr + 1);
            tptr += 2;
            len -= 2;
            alenlen = bgp_attr_lenlen(aflags, tptr);
            ND_TCHECK_LEN(tptr, alenlen);
            if (len < alenlen) {
                ND_PRINT(" [path attr too short]");
                tptr += len;
                break;
            }
            alen = bgp_attr_len(aflags, tptr);
            tptr += alenlen;
            len -= alenlen;

            ND_PRINT("\n\t      %s (%u), length: %u",
                      tok2str(bgp_attr_values,
                              "Unknown Attribute", atype),
                      atype,
                      alen);

            if (aflags) {
                ND_PRINT(", Flags [%s%s%s%s",
                          aflags & 0x80 ? "O" : "",
                          aflags & 0x40 ? "T" : "",
                          aflags & 0x20 ? "P" : "",
                          aflags & 0x10 ? "E" : "");
                if (aflags & 0xf)
                    ND_PRINT("+%x", aflags & 0xf);
                ND_PRINT("]");
            }
            ND_PRINT(": ");
            if (len < alen) {
                ND_PRINT(" [path attr too short]");
                tptr += len;
                break;
            }
            /* FIXME check for recursion */
            if (!bgp_attr_print(ndo, atype, tptr, alen))
                return 0;
            tptr += alen;
            len -= alen;
        }
        break;

    case BGPTYPE_LARGE_COMMUNITY:
        if (len == 0 || len % 12) {
            ND_PRINT("invalid len");
            break;
        }
        ND_PRINT("\n\t    ");
        while (len != 0) {
            ND_TCHECK_LEN(tptr, 12);
            ND_PRINT("%u:%u:%u%s",
                      EXTRACT_BE_U_4(tptr),
                      EXTRACT_BE_U_4(tptr + 4),
                      EXTRACT_BE_U_4(tptr + 8),
                      (len > 12) ? ", " : "");
            tptr += 12;
            /*
             * len will always be a multiple of 12, as per the above,
             * so this will never underflow.
             */
            len -= 12;
        }
        break;
    default:
        ND_TCHECK_LEN(pptr, len);
        ND_PRINT("\n\t    no Attribute %u decoder", atype); /* we have no decoder for the attribute */
        if (ndo->ndo_vflag <= 1)
            print_unknown_data(ndo, pptr, "\n\t    ", len);
        break;
    }
    if (ndo->ndo_vflag > 1 && len) { /* omit zero length attributes*/
        ND_TCHECK_LEN(pptr, len);
        print_unknown_data(ndo, pptr, "\n\t    ", len);
    }
    return 1;

trunc:
    return 0;
}

static void
bgp_capabilities_print(netdissect_options *ndo,
                       const u_char *opt, u_int caps_len)
{
    u_int cap_type, cap_len, tcap_len, cap_offset;
    u_int i = 0;

    while (i < caps_len) {
        ND_TCHECK_LEN(opt + i, BGP_CAP_HEADER_SIZE);
        cap_type=EXTRACT_U_1(opt + i);
        cap_len=EXTRACT_U_1(opt + i + 1);
        ND_PRINT("\n\t      %s (%u), length: %u",
                  tok2str(bgp_capcode_values, "Unknown", cap_type),
                  cap_type,
                  cap_len);
        ND_TCHECK_LEN(opt + 2 + i, cap_len);
        switch (cap_type) {
        case BGP_CAPCODE_MP:
            /* AFI (16 bits), Reserved (8 bits), SAFI (8 bits) */
            if (cap_len < 4) {
                ND_PRINT(" (too short, < 4)");
                return;
            }
            ND_PRINT("\n\t\tAFI %s (%u), SAFI %s (%u)",
               tok2str(af_values, "Unknown", EXTRACT_BE_U_2(opt + i + 2)),
               EXTRACT_BE_U_2(opt + i + 2),
               tok2str(bgp_safi_values, "Unknown", EXTRACT_U_1(opt + i + 5)),
               EXTRACT_U_1(opt + i + 5));
            break;
        case BGP_CAPCODE_RESTART:
            /* Restart Flags (4 bits), Restart Time in seconds (12 bits) */
            if (cap_len < 2) {
                ND_PRINT(" (too short, < 2)");
                return;
            }
            tcap_len=cap_len;
            ND_PRINT("\n\t\tRestart Flags: [%s], Restart Time %us",
                      ((EXTRACT_U_1(opt + i + 2))&0x80) ? "R" : "none",
                      EXTRACT_BE_U_2(opt + i + 2)&0xfff);
            tcap_len-=2;
            cap_offset=4;
            while(tcap_len>=4) {
                ND_PRINT("\n\t\t  AFI %s (%u), SAFI %s (%u), Forwarding state preserved: %s",
                          tok2str(af_values,"Unknown",
                                  EXTRACT_BE_U_2(opt + i + cap_offset)),
                          EXTRACT_BE_U_2(opt + i + cap_offset),
                          tok2str(bgp_safi_values,"Unknown",
                                  EXTRACT_U_1(opt + i + cap_offset + 2)),
                          EXTRACT_U_1(opt + (i + cap_offset + 2)),
                          ((EXTRACT_U_1(opt + (i + cap_offset + 3)))&0x80) ? "yes" : "no" );
                tcap_len -= 4;
                cap_offset += 4;
            }
            break;
        case BGP_CAPCODE_RR:
        case BGP_CAPCODE_RR_CISCO:
            break;
        case BGP_CAPCODE_AS_NEW:
            /*
             * Extract the 4 byte AS number encoded.
             */
            if (cap_len < 4) {
                ND_PRINT(" (too short, < 4)");
                return;
            }
            ND_PRINT("\n\t\t 4 Byte AS %s",
                      as_printf(ndo, astostr, sizeof(astostr),
                      EXTRACT_BE_U_4(opt + i + 2)));
            break;
        case BGP_CAPCODE_ADD_PATH:
            if (cap_len == 0) {
                ND_PRINT(" (bogus)"); /* length */
                break;
            }
            tcap_len=cap_len;
            cap_offset=2;
            while (tcap_len != 0) {
                if (tcap_len < 4) {
                    ND_PRINT("\n\t\t(invalid)");
                    break;
                }
                ND_PRINT("\n\t\tAFI %s (%u), SAFI %s (%u), Send/Receive: %s",
                          tok2str(af_values,"Unknown",EXTRACT_BE_U_2(opt + i + cap_offset)),
                          EXTRACT_BE_U_2(opt + i + cap_offset),
                          tok2str(bgp_safi_values,"Unknown",EXTRACT_U_1(opt + i + cap_offset + 2)),
                          EXTRACT_U_1(opt + (i + cap_offset + 2)),
                          tok2str(bgp_add_path_recvsend,"Bogus (0x%02x)",EXTRACT_U_1(opt + i + cap_offset + 3))
                );
                tcap_len -= 4;
                cap_offset += 4;
            }
            break;
        default:
            ND_PRINT("\n\t\tno decoder for Capability %u",
                      cap_type);
            if (ndo->ndo_vflag <= 1)
                print_unknown_data(ndo, opt + i + 2, "\n\t\t",
                                   cap_len);
            break;
        }
        if (ndo->ndo_vflag > 1 && cap_len != 0) {
            print_unknown_data(ndo, opt + i + 2, "\n\t\t", cap_len);
        }
        i += BGP_CAP_HEADER_SIZE + cap_len;
    }
    return;

trunc:
    nd_print_trunc(ndo);
}

static void
bgp_open_print(netdissect_options *ndo,
               const u_char *dat, u_int length)
{
    const struct bgp_open *bgp_open_header;
    u_int optslen;
    const struct bgp_opt *bgpopt;
    const u_char *opt;
    u_int i;

    ND_TCHECK_LEN(dat, BGP_OPEN_SIZE);
    if (length < BGP_OPEN_SIZE)
        goto trunc;

    bgp_open_header = (const struct bgp_open *)dat;

    ND_PRINT("\n\t  Version %u, ",
        EXTRACT_U_1(bgp_open_header->bgpo_version));
    ND_PRINT("my AS %s, ",
        as_printf(ndo, astostr, sizeof(astostr), EXTRACT_BE_U_2(bgp_open_header->bgpo_myas)));
    ND_PRINT("Holdtime %us, ",
        EXTRACT_BE_U_2(bgp_open_header->bgpo_holdtime));
    ND_PRINT("ID %s", ipaddr_string(ndo, bgp_open_header->bgpo_id));
    optslen = EXTRACT_U_1(bgp_open_header->bgpo_optlen);
    ND_PRINT("\n\t  Optional parameters, length: %u", optslen);

    opt = dat + BGP_OPEN_SIZE;
    length -= BGP_OPEN_SIZE;

    i = 0;
    while (i < optslen) {
        uint8_t opt_type, opt_len;

        ND_TCHECK_LEN(opt + i, BGP_OPT_SIZE);
        if (length < BGP_OPT_SIZE + i)
            goto trunc;
        bgpopt = (const struct bgp_opt *)(opt + i);
        opt_type = EXTRACT_U_1(bgpopt->bgpopt_type);
        opt_len = EXTRACT_U_1(bgpopt->bgpopt_len);
        if (BGP_OPT_SIZE + i + opt_len > optslen) {
            ND_PRINT("\n\t     Option %u, length: %u, goes past the end of the options",
                      opt_type, opt_len);
            break;
        }

        ND_PRINT("\n\t    Option %s (%u), length: %u",
                  tok2str(bgp_opt_values,"Unknown",opt_type),
                  opt_type,
                  opt_len);

        /* now let's decode the options we know*/
        switch(opt_type) {

        case BGP_OPT_CAP:
            bgp_capabilities_print(ndo, opt + BGP_OPT_SIZE + i,
                                   opt_len);
            break;

        case BGP_OPT_AUTH:
        default:
               ND_PRINT("\n\t      no decoder for option %u",
               opt_type);
               break;
        }
        i += BGP_OPT_SIZE + opt_len;
    }
    return;
trunc:
    nd_print_trunc(ndo);
}

static void
bgp_update_print(netdissect_options *ndo,
                 const u_char *dat, u_int length)
{
    const u_char *p;
    u_int withdrawn_routes_len;
    char buf[MAXHOSTNAMELEN + 100];
    int wpfx;
    u_int len;
    int i;
    int add_path;
    u_int path_id = 0;

    ND_TCHECK_LEN(dat, BGP_SIZE);
    if (length < BGP_SIZE)
        goto trunc;
    p = dat + BGP_SIZE;
    length -= BGP_SIZE;

    /* Unfeasible routes */
    ND_TCHECK_2(p);
    if (length < 2)
        goto trunc;
    withdrawn_routes_len = EXTRACT_BE_U_2(p);
    p += 2;
    length -= 2;
    if (withdrawn_routes_len > 1) {
        /*
         * Without keeping state from the original NLRI message,
         * it's not possible to tell if this a v4 or v6 route,
         * so only try to decode it if we're not v6 enabled.
         */
        ND_TCHECK_LEN(p, withdrawn_routes_len);
        if (length < withdrawn_routes_len)
            goto trunc;
        ND_PRINT("\n\t  Withdrawn routes:");
        add_path = check_add_path(ndo, p, withdrawn_routes_len, 32);
        while (withdrawn_routes_len != 0) {
            if (add_path) {
            	if (withdrawn_routes_len < 4) {
            	    p += withdrawn_routes_len;
            	    length -= withdrawn_routes_len;
            	    break;
            	}
                path_id = EXTRACT_BE_U_4(p);
                p += 4;
                length -= 4;
                withdrawn_routes_len -= 4;
            }
            wpfx = decode_prefix4(ndo, p, withdrawn_routes_len, buf, sizeof(buf));
            if (wpfx == -1) {
                ND_PRINT("\n\t    (illegal prefix length)");
                break;
            } else if (wpfx == -2)
                goto trunc;
            else if (wpfx == -3)
                goto trunc; /* bytes left, but not enough */
            else {
                ND_PRINT("\n\t    %s", buf);
                if (add_path) {
                    ND_PRINT("   Path Id: %u", path_id);
                }
                p += wpfx;
                length -= wpfx;
                withdrawn_routes_len -= wpfx;
            }
        }
    } else {
        ND_TCHECK_LEN(p, withdrawn_routes_len);
        if (length < withdrawn_routes_len)
            goto trunc;
        p += withdrawn_routes_len;
        length -= withdrawn_routes_len;
    }

    ND_TCHECK_2(p);
    if (length < 2)
        goto trunc;
    len = EXTRACT_BE_U_2(p);
    p += 2;
    length -= 2;

    if (withdrawn_routes_len == 0 && len == 0 && length == 0) {
        /* No withdrawn routes, no path attributes, no NLRI */
        ND_PRINT("\n\t  End-of-Rib Marker (empty NLRI)");
        return;
    }

    if (len) {
        /* do something more useful!*/
        while (len) {
            u_int aflags, atype, alenlen, alen;

            ND_TCHECK_2(p);
            if (length < 2)
                goto trunc;
            if (len < 2) {
                ND_PRINT("\n\t  [path attrs too short]");
                p += len;
                length -= len;
                break;
            }
            aflags = EXTRACT_U_1(p);
            atype = EXTRACT_U_1(p + 1);
            p += 2;
            len -= 2;
            length -= 2;
            alenlen = bgp_attr_lenlen(aflags, p);
            ND_TCHECK_LEN(p, alenlen);
            if (length < alenlen)
                goto trunc;
            if (len < alenlen) {
                ND_PRINT("\n\t  [path attrs too short]");
                p += len;
                length -= len;
                break;
            }
            alen = bgp_attr_len(aflags, p);
            p += alenlen;
            len -= alenlen;
            length -= alenlen;

            ND_PRINT("\n\t  %s (%u), length: %u",
                      tok2str(bgp_attr_values, "Unknown Attribute", atype),
                      atype,
                      alen);

            if (aflags) {
                ND_PRINT(", Flags [%s%s%s%s",
                          aflags & 0x80 ? "O" : "",
                          aflags & 0x40 ? "T" : "",
                          aflags & 0x20 ? "P" : "",
                          aflags & 0x10 ? "E" : "");
                if (aflags & 0xf)
                    ND_PRINT("+%x", aflags & 0xf);
                ND_PRINT("]: ");
            }
            if (len < alen) {
                ND_PRINT(" [path attrs too short]");
                p += len;
                length -= len;
                break;
            }
            if (length < alen)
                goto trunc;
            if (!bgp_attr_print(ndo, atype, p, alen))
                goto trunc;
            p += alen;
            len -= alen;
            length -= alen;
        }
    }

    if (length) {
        add_path = check_add_path(ndo, p, length, 32);
        ND_PRINT("\n\t  Updated routes:");
        while (length != 0) {
            if (add_path) {
                ND_TCHECK_4(p);
                if (length < 4)
                    goto trunc;
                path_id = EXTRACT_BE_U_4(p);
                p += 4;
                length -= 4;
            }
            i = decode_prefix4(ndo, p, length, buf, sizeof(buf));
            if (i == -1) {
                ND_PRINT("\n\t    (illegal prefix length)");
                break;
            } else if (i == -2)
                goto trunc;
            else if (i == -3)
                goto trunc; /* bytes left, but not enough */
            else {
                ND_PRINT("\n\t    %s", buf);
                if (add_path) {
                    ND_PRINT("   Path Id: %u", path_id);
                }
                p += i;
                length -= i;
            }
        }
    }
    return;
trunc:
    nd_print_trunc(ndo);
}

static void
bgp_notification_print(netdissect_options *ndo,
                       const u_char *dat, u_int length)
{
    const struct bgp_notification *bgp_notification_header;
    const u_char *tptr;
    uint8_t bgpn_major, bgpn_minor;
    uint8_t shutdown_comm_length;
    uint8_t remainder_offset;

    ND_TCHECK_LEN(dat, BGP_NOTIFICATION_SIZE);
    if (length<BGP_NOTIFICATION_SIZE)
        return;

    bgp_notification_header = (const struct bgp_notification *)dat;
    bgpn_major = EXTRACT_U_1(bgp_notification_header->bgpn_major);
    bgpn_minor = EXTRACT_U_1(bgp_notification_header->bgpn_minor);

    ND_PRINT(", %s (%u)",
              tok2str(bgp_notify_major_values, "Unknown Error",
                      bgpn_major),
              bgpn_major);

    switch (bgpn_major) {

    case BGP_NOTIFY_MAJOR_MSG:
        ND_PRINT(", subcode %s (%u)",
                  tok2str(bgp_notify_minor_msg_values, "Unknown",
                          bgpn_minor),
                  bgpn_minor);
        break;
    case BGP_NOTIFY_MAJOR_OPEN:
        ND_PRINT(", subcode %s (%u)",
                  tok2str(bgp_notify_minor_open_values, "Unknown",
                          bgpn_minor),
                  bgpn_minor);
        break;
    case BGP_NOTIFY_MAJOR_UPDATE:
        ND_PRINT(", subcode %s (%u)",
                  tok2str(bgp_notify_minor_update_values, "Unknown",
                          bgpn_minor),
                  bgpn_minor);
        break;
    case BGP_NOTIFY_MAJOR_FSM:
        ND_PRINT(" subcode %s (%u)",
                  tok2str(bgp_notify_minor_fsm_values, "Unknown",
                          bgpn_minor),
                  bgpn_minor);
        break;
    case BGP_NOTIFY_MAJOR_CAP:
        ND_PRINT(" subcode %s (%u)",
                  tok2str(bgp_notify_minor_cap_values, "Unknown",
                          bgpn_minor),
                  bgpn_minor);
        break;
    case BGP_NOTIFY_MAJOR_CEASE:
        ND_PRINT(", subcode %s (%u)",
                  tok2str(bgp_notify_minor_cease_values, "Unknown",
                          bgpn_minor),
                  bgpn_minor);

        /* draft-ietf-idr-cease-subcode-02 mentions optionally 7 bytes
         * for the maxprefix subtype, which may contain AFI, SAFI and MAXPREFIXES
         */
        if(bgpn_minor == BGP_NOTIFY_MINOR_CEASE_MAXPRFX && length >= BGP_NOTIFICATION_SIZE + 7) {
            tptr = dat + BGP_NOTIFICATION_SIZE;
            ND_TCHECK_7(tptr);
            ND_PRINT(", AFI %s (%u), SAFI %s (%u), Max Prefixes: %u",
                      tok2str(af_values, "Unknown", EXTRACT_BE_U_2(tptr)),
                      EXTRACT_BE_U_2(tptr),
                      tok2str(bgp_safi_values, "Unknown", EXTRACT_U_1((tptr + 2))),
                      EXTRACT_U_1((tptr + 2)),
                      EXTRACT_BE_U_4(tptr + 3));
        }
        /*
         * draft-ietf-idr-shutdown describes a method to send a communication
         * intended for human consumption regarding the Administrative Shutdown
         */
        if ((bgpn_minor == BGP_NOTIFY_MINOR_CEASE_SHUT ||
             bgpn_minor == BGP_NOTIFY_MINOR_CEASE_RESET) &&
             length >= BGP_NOTIFICATION_SIZE + 1) {
            tptr = dat + BGP_NOTIFICATION_SIZE;
            ND_TCHECK_1(tptr);
            shutdown_comm_length = EXTRACT_U_1(tptr);
            remainder_offset = 0;
            /* garbage, hexdump it all */
            if (shutdown_comm_length > BGP_NOTIFY_MINOR_CEASE_ADMIN_SHUTDOWN_LEN ||
                shutdown_comm_length > length - (BGP_NOTIFICATION_SIZE + 1)) {
                ND_PRINT(", invalid Shutdown Communication length");
            }
            else if (shutdown_comm_length == 0) {
                ND_PRINT(", empty Shutdown Communication");
                remainder_offset += 1;
            }
            /* a proper shutdown communication */
            else {
                ND_TCHECK_LEN(tptr + 1, shutdown_comm_length);
                ND_PRINT(", Shutdown Communication (length: %u): \"", shutdown_comm_length);
                (void)nd_printn(ndo, tptr+1, shutdown_comm_length, NULL);
                ND_PRINT("\"");
                remainder_offset += shutdown_comm_length + 1;
            }
            /* if there is trailing data, hexdump it */
            if(length - (remainder_offset + BGP_NOTIFICATION_SIZE) > 0) {
                ND_PRINT(", Data: (length: %u)", length - (remainder_offset + BGP_NOTIFICATION_SIZE));
                hex_print(ndo, "\n\t\t", tptr + remainder_offset, length - (remainder_offset + BGP_NOTIFICATION_SIZE));
            }
        }
        break;
    default:
        break;
    }

    return;
trunc:
    nd_print_trunc(ndo);
}

static void
bgp_route_refresh_print(netdissect_options *ndo,
                        const u_char *pptr, u_int len)
{
    const struct bgp_route_refresh *bgp_route_refresh_header;

    ND_TCHECK_LEN(pptr, BGP_ROUTE_REFRESH_SIZE);

    /* some little sanity checking */
    if (len<BGP_ROUTE_REFRESH_SIZE)
        return;

    bgp_route_refresh_header = (const struct bgp_route_refresh *)pptr;

    ND_PRINT("\n\t  AFI %s (%u), SAFI %s (%u)",
              tok2str(af_values,"Unknown",
                      EXTRACT_BE_U_2(bgp_route_refresh_header->afi)),
              EXTRACT_BE_U_2(bgp_route_refresh_header->afi),
              tok2str(bgp_safi_values,"Unknown",
                      EXTRACT_U_1(bgp_route_refresh_header->safi)),
              EXTRACT_U_1(bgp_route_refresh_header->safi));

    if (ndo->ndo_vflag > 1) {
        ND_TCHECK_LEN(pptr, len);
        print_unknown_data(ndo, pptr, "\n\t  ", len);
    }

    return;
trunc:
    nd_print_trunc(ndo);
}

static int
bgp_pdu_print(netdissect_options *ndo,
              const u_char *dat, u_int length)
{
    const struct bgp *bgp_header;
    uint8_t bgp_type;

    ND_TCHECK_LEN(dat, BGP_SIZE);
    bgp_header = (const struct bgp *)dat;
    bgp_type = EXTRACT_U_1(bgp_header->bgp_type);

    ND_PRINT("\n\t%s Message (%u), length: %u",
              tok2str(bgp_msg_values, "Unknown", bgp_type),
              bgp_type,
              length);

    switch (bgp_type) {
    case BGP_OPEN:
        bgp_open_print(ndo, dat, length);
        break;
    case BGP_UPDATE:
        bgp_update_print(ndo, dat, length);
        break;
    case BGP_NOTIFICATION:
        bgp_notification_print(ndo, dat, length);
        break;
    case BGP_KEEPALIVE:
        break;
    case BGP_ROUTE_REFRESH:
        bgp_route_refresh_print(ndo, dat, length);
        break;
    default:
        /* we have no decoder for the BGP message */
        ND_TCHECK_LEN(dat, length);
        ND_PRINT("\n\t  no Message %u decoder", bgp_type);
        print_unknown_data(ndo, dat, "\n\t  ", length);
        break;
    }
    return 1;
trunc:
    nd_print_trunc(ndo);
    return 0;
}

void
bgp_print(netdissect_options *ndo,
          const u_char *dat, u_int length _U_)
{
    const u_char *p;
    const u_char *ep = ndo->ndo_snapend;
    const u_char *start;
    const u_char marker[] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    };
    const struct bgp *bgp_header;
    uint16_t hlen;

    ndo->ndo_protocol = "bgp";
    ND_PRINT(": BGP");

    if (ndo->ndo_vflag < 1) /* lets be less chatty */
        return;

    p = dat;
    start = p;
    while (p < ep) {
        if (!ND_TTEST_1(p))
            break;
        if (EXTRACT_U_1(p) != 0xff) {
            p++;
            continue;
        }

        if (!ND_TTEST_LEN(p, sizeof(marker)))
            break;
        if (memcmp(p, marker, sizeof(marker)) != 0) {
            p++;
            continue;
        }

        /* found BGP header */
        ND_TCHECK_LEN(p, BGP_SIZE);
        bgp_header = (const struct bgp *)p;

        if (start != p)
            nd_print_trunc(ndo);

        hlen = EXTRACT_BE_U_2(bgp_header->bgp_len);
        if (hlen < BGP_SIZE) {
            ND_PRINT("\n[|BGP Bogus header length %u < %u]", hlen,
                      BGP_SIZE);
            break;
        }

        if (ND_TTEST_LEN(p, hlen)) {
            if (!bgp_pdu_print(ndo, p, hlen))
                return;
            p += hlen;
            start = p;
        } else {
            ND_PRINT("\n[|BGP %s]",
                      tok2str(bgp_msg_values,
                              "Unknown Message Type",
                              EXTRACT_U_1(bgp_header->bgp_type)));
            break;
        }
    }

    return;

trunc:
    nd_print_trunc(ndo);
}
