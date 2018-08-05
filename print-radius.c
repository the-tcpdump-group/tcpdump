/*
 * Copyright (C) 2000 Alfredo Andres Omella.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in
 *      the documentation and/or other materials provided with the
 *      distribution.
 *   3. The names of the authors may not be used to endorse or promote
 *      products derived from this software without specific prior
 *      written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

/* \summary: Radius protocol printer */

/*
 * Radius printer routines as specified on:
 *
 * RFC 2865:
 *      "Remote Authentication Dial In User Service (RADIUS)"
 *
 * RFC 2866:
 *      "RADIUS Accounting"
 *
 * RFC 2867:
 *      "RADIUS Accounting Modifications for Tunnel Protocol Support"
 *
 * RFC 2868:
 *      "RADIUS Attributes for Tunnel Protocol Support"
 *
 * RFC 2869:
 *      "RADIUS Extensions"
 *
 * RFC 3162:
 *      "RADIUS and IPv6"
 *
 * RFC 3580:
 *      "IEEE 802.1X Remote Authentication Dial In User Service (RADIUS)"
 *      "Usage Guidelines"
 *
 * RFC 4072:
 *      "Diameter Extensible Authentication Protocol (EAP) Application"
 *
 * RFC 4675:
 *      "RADIUS Attributes for Virtual LAN and Priority Support"
 *
 * RFC 4818:
 *      "RADIUS Delegated-IPv6-Prefix Attribute"
 *
 * RFC 4849:
 *      "RADIUS Filter Rule Attribute"
 *
 * RFC 5090:
 *      "RADIUS Extension for Digest Authentication"
 *
 * RFC 5176:
 *      "Dynamic Authorization Extensions to RADIUS"
 *
 * RFC 5447:
 *      "Diameter Mobile IPv6"
 *
 * RFC 5580:
 *      "Carrying Location Objects in RADIUS and Diameter"
 *
 * RFC 6572:
 *      "RADIUS Support for Proxy Mobile IPv6"
 *
 * RFC 7155:
 *      "Diameter Network Access Server Application"
 *
 * Alfredo Andres Omella (aandres@s21sec.com) v0.1 2000/09/15
 *
 * TODO: Among other things to print ok MacIntosh and Vendor values
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "netdissect-stdinc.h"

#include <string.h>

#include "netdissect.h"
#include "addrtoname.h"
#include "extract.h"
#include "oui.h"


#define TAM_SIZE(x) (sizeof(x)/sizeof(x[0]) )

#define PRINT_HEX(bytes_len, ptr_data)                               \
           while(bytes_len)                                          \
           {                                                         \
              ND_PRINT("%02X", *ptr_data );                   \
              ptr_data++;                                            \
              bytes_len--;                                           \
           }


/* Radius packet codes */
#define RADCMD_ACCESS_REQ   1 /* Access-Request      */
#define RADCMD_ACCESS_ACC   2 /* Access-Accept       */
#define RADCMD_ACCESS_REJ   3 /* Access-Reject       */
#define RADCMD_ACCOUN_REQ   4 /* Accounting-Request  */
#define RADCMD_ACCOUN_RES   5 /* Accounting-Response */
#define RADCMD_ACCESS_CHA  11 /* Access-Challenge    */
#define RADCMD_STATUS_SER  12 /* Status-Server       */
#define RADCMD_STATUS_CLI  13 /* Status-Client       */
#define RADCMD_DISCON_REQ  40 /* Disconnect-Request  */
#define RADCMD_DISCON_ACK  41 /* Disconnect-ACK      */
#define RADCMD_DISCON_NAK  42 /* Disconnect-NAK      */
#define RADCMD_COA_REQ     43 /* CoA-Request         */
#define RADCMD_COA_ACK     44 /* CoA-ACK             */
#define RADCMD_COA_NAK     45 /* CoA-NAK             */
#define RADCMD_RESERVED   255 /* Reserved            */

static const struct tok radius_command_values[] = {
    { RADCMD_ACCESS_REQ, "Access-Request" },
    { RADCMD_ACCESS_ACC, "Access-Accept" },
    { RADCMD_ACCESS_REJ, "Access-Reject" },
    { RADCMD_ACCOUN_REQ, "Accounting-Request" },
    { RADCMD_ACCOUN_RES, "Accounting-Response" },
    { RADCMD_ACCESS_CHA, "Access-Challenge" },
    { RADCMD_STATUS_SER, "Status-Server" },
    { RADCMD_STATUS_CLI, "Status-Client" },
    { RADCMD_DISCON_REQ, "Disconnect-Request" },
    { RADCMD_DISCON_ACK, "Disconnect-ACK" },
    { RADCMD_DISCON_NAK, "Disconnect-NAK" },
    { RADCMD_COA_REQ,    "CoA-Request" },
    { RADCMD_COA_ACK,    "CoA-ACK" },
    { RADCMD_COA_NAK,    "CoA-NAK" },
    { RADCMD_RESERVED,   "Reserved" },
    { 0, NULL}
};

/********************************/
/* Begin Radius Attribute types */
/********************************/
#define SERV_TYPE    6
#define FRM_IPADDR   8
#define LOG_IPHOST  14
#define LOG_SERVICE 15
#define FRM_IPX     23
#define SESSION_TIMEOUT   27
#define IDLE_TIMEOUT      28
#define FRM_ATALK_LINK    37
#define FRM_ATALK_NETWORK 38

#define ACCT_DELAY        41
#define ACCT_SESSION_TIME 46

#define EGRESS_VLAN_ID   56
#define EGRESS_VLAN_NAME 58

#define TUNNEL_TYPE        64
#define TUNNEL_MEDIUM      65
#define TUNNEL_CLIENT_END  66
#define TUNNEL_SERVER_END  67
#define TUNNEL_PASS        69

#define ARAP_PASS          70
#define ARAP_FEATURES      71

#define TUNNEL_PRIV_GROUP  81
#define TUNNEL_ASSIGN_ID   82
#define TUNNEL_PREFERENCE  83

#define ARAP_CHALLENGE_RESP 84
#define ACCT_INT_INTERVAL   85

#define TUNNEL_CLIENT_AUTH 90
#define TUNNEL_SERVER_AUTH 91

#define ERROR_CAUSE 101
/********************************/
/* End Radius Attribute types */
/********************************/

#define RFC4675_TAGGED   0x31
#define RFC4675_UNTAGGED 0x32

static const struct tok rfc4675_tagged[] = {
    { RFC4675_TAGGED,   "Tagged" },
    { RFC4675_UNTAGGED, "Untagged" },
    { 0, NULL}
};


static void print_attr_string(netdissect_options *, const u_char *, u_int, u_short );
static void print_attr_num(netdissect_options *, const u_char *, u_int, u_short );
static void print_vendor_attr(netdissect_options *, const u_char *, u_int, u_short );
static void print_attr_address(netdissect_options *, const u_char *, u_int, u_short);
static void print_attr_address6(netdissect_options *, const u_char *, u_int, u_short);
static void print_attr_netmask6(netdissect_options *, const u_char *, u_int, u_short);
static void print_attr_mip6_home_link_prefix(netdissect_options *, const u_char *, u_int, u_short);
static void print_attr_time(netdissect_options *, const u_char *, u_int, u_short);
static void print_attr_vector64(netdissect_options *, register const u_char *, u_int, u_short);
static void print_attr_strange(netdissect_options *, const u_char *, u_int, u_short);


struct radius_hdr { nd_uint8_t  code;     /* Radius packet code  */
                    nd_uint8_t  id;       /* Radius packet id    */
                    nd_uint16_t len;      /* Radius total length */
                    nd_byte     auth[16]; /* Authenticator   */
                  };

#define MIN_RADIUS_LEN	20

struct radius_attr { nd_uint8_t type; /* Attribute type   */
                     nd_uint8_t len;  /* Attribute length */
                   };


/* Service-Type Attribute standard values */
static const char *serv_type[]={ NULL,
                                "Login",
                                "Framed",
                                "Callback Login",
                                "Callback Framed",
                                "Outbound",
                                "Administrative",
                                "NAS Prompt",
                                "Authenticate Only",
                                "Callback NAS Prompt",
                                "Call Check",
                                "Callback Administrative",
                               };

/* Framed-Protocol Attribute standard values */
static const char *frm_proto[]={ NULL,
                                 "PPP",
                                 "SLIP",
                                 "ARAP",
                                 "Gandalf proprietary",
                                 "Xylogics IPX/SLIP",
                                 "X.75 Synchronous",
                               };

/* Framed-Routing Attribute standard values */
static const char *frm_routing[]={ "None",
                                   "Send",
                                   "Listen",
                                   "Send&Listen",
                                 };

/* Framed-Compression Attribute standard values */
static const char *frm_comp[]={ "None",
                                "VJ TCP/IP",
                                "IPX",
                                "Stac-LZS",
                              };

/* Login-Service Attribute standard values */
static const char *login_serv[]={ "Telnet",
                                  "Rlogin",
                                  "TCP Clear",
                                  "PortMaster(proprietary)",
                                  "LAT",
                                  "X.25-PAD",
                                  "X.25-T3POS",
                                  "Unassigned",
                                  "TCP Clear Quiet",
                                };


/* Termination-Action Attribute standard values */
static const char *term_action[]={ "Default",
                                   "RADIUS-Request",
                                 };

/* Ingress-Filters Attribute standard values */
static const char *ingress_filters[]={ NULL,
                                       "Enabled",
                                       "Disabled",
                                     };

/* NAS-Port-Type Attribute standard values */
static const char *nas_port_type[]={ "Async",
                                     "Sync",
                                     "ISDN Sync",
                                     "ISDN Async V.120",
                                     "ISDN Async V.110",
                                     "Virtual",
                                     "PIAFS",
                                     "HDLC Clear Channel",
                                     "X.25",
                                     "X.75",
                                     "G.3 Fax",
                                     "SDSL",
                                     "ADSL-CAP",
                                     "ADSL-DMT",
                                     "ISDN-DSL",
                                     "Ethernet",
                                     "xDSL",
                                     "Cable",
                                     "Wireless - Other",
                                     "Wireless - IEEE 802.11",
                                   };

/* Acct-Status-Type Accounting Attribute standard values */
static const char *acct_status[]={ NULL,
                                   "Start",
                                   "Stop",
                                   "Interim-Update",
                                   "Unassigned",
                                   "Unassigned",
                                   "Unassigned",
                                   "Accounting-On",
                                   "Accounting-Off",
                                   "Tunnel-Start",
                                   "Tunnel-Stop",
                                   "Tunnel-Reject",
                                   "Tunnel-Link-Start",
                                   "Tunnel-Link-Stop",
                                   "Tunnel-Link-Reject",
                                   "Failed",
                                 };

/* Acct-Authentic Accounting Attribute standard values */
static const char *acct_auth[]={ NULL,
                                 "RADIUS",
                                 "Local",
                                 "Remote",
                               };

/* Acct-Terminate-Cause Accounting Attribute standard values */
static const char *acct_term[]={ NULL,
                                 "User Request",
                                 "Lost Carrier",
                                 "Lost Service",
                                 "Idle Timeout",
                                 "Session Timeout",
                                 "Admin Reset",
                                 "Admin Reboot",
                                 "Port Error",
                                 "NAS Error",
                                 "NAS Request",
                                 "NAS Reboot",
                                 "Port Unneeded",
                                 "Port Preempted",
                                 "Port Suspended",
                                 "Service Unavailable",
                                 "Callback",
                                 "User Error",
                                 "Host Request",
                               };

/* Tunnel-Type Attribute standard values */
static const char *tunnel_type[]={ NULL,
                                   "PPTP",
                                   "L2F",
                                   "L2TP",
                                   "ATMP",
                                   "VTP",
                                   "AH",
                                   "IP-IP",
                                   "MIN-IP-IP",
                                   "ESP",
                                   "GRE",
                                   "DVS",
                                   "IP-in-IP Tunneling",
                                   "VLAN",
                                 };

/* Tunnel-Medium-Type Attribute standard values */
static const char *tunnel_medium[]={ NULL,
                                     "IPv4",
                                     "IPv6",
                                     "NSAP",
                                     "HDLC",
                                     "BBN 1822",
                                     "802",
                                     "E.163",
                                     "E.164",
                                     "F.69",
                                     "X.121",
                                     "IPX",
                                     "Appletalk",
                                     "Decnet IV",
                                     "Banyan Vines",
                                     "E.164 with NSAP subaddress",
                                   };

/* ARAP-Zone-Access Attribute standard values */
static const char *arap_zone[]={ NULL,
                                 "Only access to dfl zone",
                                 "Use zone filter inc.",
                                 "Not used",
                                 "Use zone filter exc.",
                               };

static const char *prompt[]={ "No Echo",
                              "Echo",
                            };

/* Error-Cause standard values */
#define ERROR_CAUSE_RESIDUAL_CONTEXT_REMOVED 201
#define ERROR_CAUSE_INVALID_EAP_PACKET 202
#define ERROR_CAUSE_UNSUPPORTED_ATTRIBUTE 401
#define ERROR_CAUSE_MISSING_ATTRIBUTE 402
#define ERROR_CAUSE_NAS_IDENTIFICATION_MISMATCH 403
#define ERROR_CAUSE_INVALID_REQUEST 404
#define ERROR_CAUSE_UNSUPPORTED_SERVICE 405
#define ERROR_CAUSE_UNSUPPORTED_EXTENSION 406
#define ERROR_CAUSE_INVALID_ATTRIBUTE_VALUE 407
#define ERROR_CAUSE_ADMINISTRATIVELY_PROHIBITED 501
#define ERROR_CAUSE_PROXY_REQUEST_NOT_ROUTABLE 502
#define ERROR_CAUSE_SESSION_CONTEXT_NOT_FOUND 503
#define ERROR_CAUSE_SESSION_CONTEXT_NOT_REMOVABLE 504
#define ERROR_CAUSE_PROXY_PROCESSING_ERROR 505
#define ERROR_CAUSE_RESOURCES_UNAVAILABLE 506
#define ERROR_CAUSE_REQUEST_INITIATED 507
#define ERROR_CAUSE_MULTIPLE_SESSION_SELECTION_UNSUPPORTED 508
#define ERROR_CAUSE_LOCATION_INFO_REQUIRED 509
static const struct tok errorcausetype[] = {
                                 { ERROR_CAUSE_RESIDUAL_CONTEXT_REMOVED,               "Residual Session Context Removed" },
                                 { ERROR_CAUSE_INVALID_EAP_PACKET,                     "Invalid EAP Packet (Ignored)" },
                                 { ERROR_CAUSE_UNSUPPORTED_ATTRIBUTE,                  "Unsupported Attribute" },
                                 { ERROR_CAUSE_MISSING_ATTRIBUTE,                      "Missing Attribute" },
                                 { ERROR_CAUSE_NAS_IDENTIFICATION_MISMATCH,            "NAS Identification Mismatch" },
                                 { ERROR_CAUSE_INVALID_REQUEST,                        "Invalid Request" },
                                 { ERROR_CAUSE_UNSUPPORTED_SERVICE,                    "Unsupported Service" },
                                 { ERROR_CAUSE_UNSUPPORTED_EXTENSION,                  "Unsupported Extension" },
                                 { ERROR_CAUSE_INVALID_ATTRIBUTE_VALUE,                "Invalid Attribute Value" },
                                 { ERROR_CAUSE_ADMINISTRATIVELY_PROHIBITED,            "Administratively Prohibited" },
                                 { ERROR_CAUSE_PROXY_REQUEST_NOT_ROUTABLE,             "Request Not Routable (Proxy)" },
                                 { ERROR_CAUSE_SESSION_CONTEXT_NOT_FOUND,              "Session Context Not Found" },
                                 { ERROR_CAUSE_SESSION_CONTEXT_NOT_REMOVABLE,          "Session Context Not Removable" },
                                 { ERROR_CAUSE_PROXY_PROCESSING_ERROR,                 "Other Proxy Processing Error" },
                                 { ERROR_CAUSE_RESOURCES_UNAVAILABLE,                  "Resources Unavailable" },
                                 { ERROR_CAUSE_REQUEST_INITIATED,                      "Request Initiated" },
                                 { ERROR_CAUSE_MULTIPLE_SESSION_SELECTION_UNSUPPORTED, "Multiple Session Selection Unsupported" },
                                 { ERROR_CAUSE_LOCATION_INFO_REQUIRED,                 "Location Info Required" },
																 { 0, NULL }
                               };

/* MIP6-Feature-Vector standard values */
#define MIP6_INTEGRATED 0x0000000000000001
#define LOCAL_HOME_AGENT_ASSIGNMENT 0x0000000000000002
#define PMIP6_SUPPORTED 0x0000010000000000
#define IP4_HOA_SUPPORTED 0x0000020000000000
#define LOCAL_MAG_ROUTING_SUPPORTED 0x0000040000000000
#define IP4_TRANSPORT_SUPPORTED 0x0000800000000000
#define IP4_HOA_ONLY_SUPPORTED 0x0001000000000000
static struct mip6_feature_vector {
                  uint64_t v;
                  const char *s;
                } mip6_feature_vector[] = {
                                 { MIP6_INTEGRATED,             "MIP6_INTEGRATED" },
                                 { LOCAL_HOME_AGENT_ASSIGNMENT, "LOCAL_HOME_AGENT_ASSIGNMENT" },
                                 { PMIP6_SUPPORTED,             "PMIP6_SUPPORTED" },
                                 { IP4_HOA_SUPPORTED,           "IP4_HOA_SUPPORTED" },
                                 { LOCAL_MAG_ROUTING_SUPPORTED, "LOCAL_MAG_ROUTING_SUPPORTED" },
                                 { IP4_TRANSPORT_SUPPORTED,     "IP4_TRANSPORT_SUPPORTED" },
                                 { IP4_HOA_ONLY_SUPPORTED,      "IP4_HOA_ONLY_SUPPORTED" }
                               };


static struct attrtype {
                  const char *name;      /* Attribute name                 */
                  const char **subtypes; /* Standard Values (if any)       */
                  u_char siz_subtypes;   /* Size of total standard values  */
                  u_char first_subtype;  /* First standard value is 0 or 1 */
                  void (*print_func)(netdissect_options *, const u_char *, u_int, u_short);
                } attr_type[]=
  {
     { NULL,                              NULL, 0, 0, NULL               },
     { "User-Name",                       NULL, 0, 0, print_attr_string  },
     { "User-Password",                   NULL, 0, 0, NULL               },
     { "CHAP-Password",                   NULL, 0, 0, NULL               },
     { "NAS-IP-Address",                  NULL, 0, 0, print_attr_address },
     { "NAS-Port",                        NULL, 0, 0, print_attr_num     },
     { "Service-Type",                    serv_type, TAM_SIZE(serv_type)-1, 1, print_attr_num },
     { "Framed-Protocol",                 frm_proto, TAM_SIZE(frm_proto)-1, 1, print_attr_num },
     { "Framed-IP-Address",               NULL, 0, 0, print_attr_address },
     { "Framed-IP-Netmask",               NULL, 0, 0, print_attr_address },
     { "Framed-Routing",                  frm_routing, TAM_SIZE(frm_routing), 0, print_attr_num },
     { "Filter-Id",                       NULL, 0, 0, print_attr_string  },
     { "Framed-MTU",                      NULL, 0, 0, print_attr_num     },
     { "Framed-Compression",              frm_comp, TAM_SIZE(frm_comp),   0, print_attr_num },
     { "Login-IP-Host",                   NULL, 0, 0, print_attr_address },
     { "Login-Service",                   login_serv, TAM_SIZE(login_serv), 0, print_attr_num },
     { "Login-TCP-Port",                  NULL, 0, 0, print_attr_num     },
     { "Unassigned",                      NULL, 0, 0, NULL }, /*17*/
     { "Reply-Message",                   NULL, 0, 0, print_attr_string },
     { "Callback-Number",                 NULL, 0, 0, print_attr_string },
     { "Callback-Id",                     NULL, 0, 0, print_attr_string },
     { "Unassigned",                      NULL, 0, 0, NULL }, /*21*/
     { "Framed-Route",                    NULL, 0, 0, print_attr_string },
     { "Framed-IPX-Network",              NULL, 0, 0, print_attr_num    },
     { "State",                           NULL, 0, 0, print_attr_string },
     { "Class",                           NULL, 0, 0, print_attr_string },
     { "Vendor-Specific",                 NULL, 0, 0, print_vendor_attr },
     { "Session-Timeout",                 NULL, 0, 0, print_attr_num    },
     { "Idle-Timeout",                    NULL, 0, 0, print_attr_num    },
     { "Termination-Action",              term_action, TAM_SIZE(term_action), 0, print_attr_num },
     { "Called-Station-Id",               NULL, 0, 0, print_attr_string },
     { "Calling-Station-Id",              NULL, 0, 0, print_attr_string },
     { "NAS-Identifier",                  NULL, 0, 0, print_attr_string },
     { "Proxy-State",                     NULL, 0, 0, print_attr_string },
     { "Login-LAT-Service",               NULL, 0, 0, print_attr_string },
     { "Login-LAT-Node",                  NULL, 0, 0, print_attr_string },
     { "Login-LAT-Group",                 NULL, 0, 0, print_attr_string },
     { "Framed-AppleTalk-Link",           NULL, 0, 0, print_attr_num    },
     { "Framed-AppleTalk-Network",        NULL, 0, 0, print_attr_num    },
     { "Framed-AppleTalk-Zone",           NULL, 0, 0, print_attr_string },
     { "Acct-Status-Type",                acct_status, TAM_SIZE(acct_status)-1, 1, print_attr_num },
     { "Acct-Delay-Time",                 NULL, 0, 0, print_attr_num    },
     { "Acct-Input-Octets",               NULL, 0, 0, print_attr_num    },
     { "Acct-Output-Octets",              NULL, 0, 0, print_attr_num    },
     { "Acct-Session-Id",                 NULL, 0, 0, print_attr_string },
     { "Acct-Authentic",                  acct_auth, TAM_SIZE(acct_auth)-1, 1, print_attr_num },
     { "Acct-Session-Time",               NULL, 0, 0, print_attr_num },
     { "Acct-Input-Packets",              NULL, 0, 0, print_attr_num },
     { "Acct-Output-Packets",             NULL, 0, 0, print_attr_num },
     { "Acct-Terminate-Cause",            acct_term, TAM_SIZE(acct_term)-1, 1, print_attr_num },
     { "Acct-Multi-Session-Id",           NULL, 0, 0, print_attr_string },
     { "Acct-Link-Count",                 NULL, 0, 0, print_attr_num },
     { "Acct-Input-Gigawords",            NULL, 0, 0, print_attr_num },
     { "Acct-Output-Gigawords",           NULL, 0, 0, print_attr_num },
     { "Unassigned",                      NULL, 0, 0, NULL }, /*54*/
     { "Event-Timestamp",                 NULL, 0, 0, print_attr_time },
     { "Egress-VLANID",                   NULL, 0, 0, print_attr_num },
     { "Ingress-Filters",                 ingress_filters, TAM_SIZE(ingress_filters)-1, 1, print_attr_num },
     { "Egress-VLAN-Name",                NULL, 0, 0, print_attr_string },
     { "User-Priority-Table",             NULL, 0, 0, NULL },
     { "CHAP-Challenge",                  NULL, 0, 0, print_attr_string },
     { "NAS-Port-Type",                   nas_port_type, TAM_SIZE(nas_port_type), 0, print_attr_num },
     { "Port-Limit",                      NULL, 0, 0, print_attr_num },
     { "Login-LAT-Port",                  NULL, 0, 0, print_attr_string }, /*63*/
     { "Tunnel-Type",                     tunnel_type, TAM_SIZE(tunnel_type)-1, 1, print_attr_num },
     { "Tunnel-Medium-Type",              tunnel_medium, TAM_SIZE(tunnel_medium)-1, 1, print_attr_num },
     { "Tunnel-Client-Endpoint",          NULL, 0, 0, print_attr_string },
     { "Tunnel-Server-Endpoint",          NULL, 0, 0, print_attr_string },
     { "Acct-Tunnel-Connection",          NULL, 0, 0, print_attr_string },
     { "Tunnel-Password",                 NULL, 0, 0, print_attr_string  },
     { "ARAP-Password",                   NULL, 0, 0, print_attr_strange },
     { "ARAP-Features",                   NULL, 0, 0, print_attr_strange },
     { "ARAP-Zone-Access",                arap_zone, TAM_SIZE(arap_zone)-1, 1, print_attr_num }, /*72*/
     { "ARAP-Security",                   NULL, 0, 0, print_attr_string },
     { "ARAP-Security-Data",              NULL, 0, 0, print_attr_string },
     { "Password-Retry",                  NULL, 0, 0, print_attr_num    },
     { "Prompt",                          prompt, TAM_SIZE(prompt), 0, print_attr_num },
     { "Connect-Info",                    NULL, 0, 0, print_attr_string   },
     { "Configuration-Token",             NULL, 0, 0, print_attr_string   },
     { "EAP-Message",                     NULL, 0, 0, print_attr_string   },
     { "Message-Authenticator",           NULL, 0, 0, print_attr_string }, /*80*/
     { "Tunnel-Private-Group-ID",         NULL, 0, 0, print_attr_string },
     { "Tunnel-Assignment-ID",            NULL, 0, 0, print_attr_string },
     { "Tunnel-Preference",               NULL, 0, 0, print_attr_num    },
     { "ARAP-Challenge-Response",         NULL, 0, 0, print_attr_strange },
     { "Acct-Interim-Interval",           NULL, 0, 0, print_attr_num     },
     { "Acct-Tunnel-Packets-Lost",        NULL, 0, 0, print_attr_num }, /*86*/
     { "NAS-Port-Id",                     NULL, 0, 0, print_attr_string },
     { "Framed-Pool",                     NULL, 0, 0, print_attr_string },
     { "CUI",                             NULL, 0, 0, print_attr_string },
     { "Tunnel-Client-Auth-ID",           NULL, 0, 0, print_attr_string },
     { "Tunnel-Server-Auth-ID",           NULL, 0, 0, print_attr_string },
     { "NAS-Filter-Rule",                 NULL, 0, 0, print_attr_string },
     { "Unassigned",                      NULL, 0, 0, NULL },  /*93*/
     { "Originating-Line-Info",           NULL, 0, 0, NULL },
     { "NAS-IPv6-Address",                NULL, 0, 0, print_attr_address6 },
     { "Framed-Interface-ID",             NULL, 0, 0, NULL },
     { "Framed-IPv6-Prefix",              NULL, 0, 0, print_attr_netmask6 },
     { "Login-IPv6-Host",                 NULL, 0, 0, print_attr_address6 },
     { "Framed-IPv6-Route",               NULL, 0, 0, print_attr_string },
     { "Framed-IPv6-Pool",                NULL, 0, 0, print_attr_string },
     { "Error-Cause",                     NULL, 0, 0, print_attr_strange },
     { "EAP-Key-Name",                    NULL, 0, 0, NULL },
     { "Digest-Response",                 NULL, 0, 0, print_attr_string },
     { "Digest-Realm",                    NULL, 0, 0, print_attr_string },
     { "Digest-Nonce",                    NULL, 0, 0, print_attr_string },
     { "Digest-Response-Auth",            NULL, 0, 0, print_attr_string },
     { "Digest-Nextnonce",                NULL, 0, 0, print_attr_string },
     { "Digest-Method",                   NULL, 0, 0, print_attr_string },
     { "Digest-URI",                      NULL, 0, 0, print_attr_string },
     { "Digest-Qop",                      NULL, 0, 0, print_attr_string },
     { "Digest-Algorithm",                NULL, 0, 0, print_attr_string },
     { "Digest-Entity-Body-Hash",         NULL, 0, 0, print_attr_string },
     { "Digest-CNonce",                   NULL, 0, 0, print_attr_string },
     { "Digest-Nonce-Count",              NULL, 0, 0, print_attr_string },
     { "Digest-Username",                 NULL, 0, 0, print_attr_string },
     { "Digest-Opaque",                   NULL, 0, 0, print_attr_string },
     { "Digest-Auth-Param",               NULL, 0, 0, print_attr_string },
     { "Digest-AKA-Auts",                 NULL, 0, 0, print_attr_string },
     { "Digest-Domain",                   NULL, 0, 0, print_attr_string },
     { "Digest-Stale",                    NULL, 0, 0, print_attr_string },
     { "Digest-HA1",                      NULL, 0, 0, print_attr_string },
     { "SIP-AOR",                         NULL, 0, 0, print_attr_string },
     { "Delegated-IPv6-Prefix",           NULL, 0, 0, print_attr_netmask6 },
     { "MIP6-Feature-Vector",             NULL, 0, 0, print_attr_vector64 },
     { "MIP6-Home-Link-Prefix",           NULL, 0, 0, print_attr_mip6_home_link_prefix },
  };


/*****************************/
/* Print an attribute string */
/* value pointed by 'data'   */
/* and 'length' size.        */
/*****************************/
/* Returns nothing.          */
/*****************************/
static void
print_attr_string(netdissect_options *ndo,
                  const u_char *data, u_int length, u_short attr_code)
{
   u_int i;

   ND_TCHECK_LEN(data, length);

   switch(attr_code)
   {
      case TUNNEL_PASS:
           if (length < 3)
              goto trunc;
           if (EXTRACT_U_1(data) && (EXTRACT_U_1(data) <= 0x1F))
              ND_PRINT("Tag[%u] ", EXTRACT_U_1(data));
           else
              ND_PRINT("Tag[Unused] ");
           data++;
           length--;
           ND_PRINT("Salt %u ", EXTRACT_BE_U_2(data));
           data+=2;
           length-=2;
        break;
      case TUNNEL_CLIENT_END:
      case TUNNEL_SERVER_END:
      case TUNNEL_PRIV_GROUP:
      case TUNNEL_ASSIGN_ID:
      case TUNNEL_CLIENT_AUTH:
      case TUNNEL_SERVER_AUTH:
           if (EXTRACT_U_1(data) <= 0x1F)
           {
              if (length < 1)
                 goto trunc;
              if (EXTRACT_U_1(data))
                ND_PRINT("Tag[%u] ", EXTRACT_U_1(data));
              else
                ND_PRINT("Tag[Unused] ");
              data++;
              length--;
           }
        break;
      case EGRESS_VLAN_NAME:
           if (length < 1)
              goto trunc;
           ND_PRINT("%s (0x%02x) ",
                  tok2str(rfc4675_tagged,"Unknown tag",EXTRACT_U_1(data)),
                  EXTRACT_U_1(data));
           data++;
           length--;
        break;
   }

   for (i=0; i < length && EXTRACT_U_1(data); i++, data++)
       ND_PRINT("%c", ND_ISPRINT(EXTRACT_U_1(data)) ? EXTRACT_U_1(data) : '.');

   return;

   trunc:
      nd_print_trunc(ndo);
}

/*
 * print vendor specific attributes
 */
static void
print_vendor_attr(netdissect_options *ndo,
                  const u_char *data, u_int length, u_short attr_code _U_)
{
    u_int idx;
    u_int vendor_id;
    u_int vendor_type;
    u_int vendor_length;

    if (length < 4)
        goto trunc;
    ND_TCHECK_4(data);
    vendor_id = EXTRACT_BE_U_4(data);
    data+=4;
    length-=4;

    ND_PRINT("Vendor: %s (%u)",
           tok2str(smi_values,"Unknown",vendor_id),
           vendor_id);

    while (length >= 2) {
	ND_TCHECK_2(data);

        vendor_type = EXTRACT_U_1(data);
        vendor_length = EXTRACT_U_1(data + 1);

        if (vendor_length < 2)
        {
            ND_PRINT("\n\t    Vendor Attribute: %u, Length: %u (bogus, must be >= 2)",
                   vendor_type,
                   vendor_length);
            return;
        }
        if (vendor_length > length)
        {
            ND_PRINT("\n\t    Vendor Attribute: %u, Length: %u (bogus, goes past end of vendor-specific attribute)",
                   vendor_type,
                   vendor_length);
            return;
        }
        data+=2;
        vendor_length-=2;
        length-=2;
	ND_TCHECK_LEN(data, vendor_length);

        ND_PRINT("\n\t    Vendor Attribute: %u, Length: %u, Value: ",
               vendor_type,
               vendor_length);
        for (idx = 0; idx < vendor_length ; idx++, data++)
            ND_PRINT("%c", ND_ISPRINT(EXTRACT_U_1(data)) ? EXTRACT_U_1(data) : '.');
        length-=vendor_length;
    }
    return;

   trunc:
     nd_print_trunc(ndo);
}

/******************************/
/* Print an attribute numeric */
/* value pointed by 'data'    */
/* and 'length' size.         */
/******************************/
/* Returns nothing.           */
/******************************/
static void
print_attr_num(netdissect_options *ndo,
               const u_char *data, u_int length, u_short attr_code)
{
   uint32_t timeout;

   if (length != 4)
   {
       ND_PRINT("ERROR: length %u != 4", length);
       return;
   }

   ND_TCHECK_4(data);
                          /* This attribute has standard values */
   if (attr_type[attr_code].siz_subtypes)
   {
      static const char **table;
      uint32_t data_value;
      table = attr_type[attr_code].subtypes;

      if ( (attr_code == TUNNEL_TYPE) || (attr_code == TUNNEL_MEDIUM) )
      {
         if (!EXTRACT_U_1(data))
            ND_PRINT("Tag[Unused] ");
         else
            ND_PRINT("Tag[%u] ", EXTRACT_U_1(data));
         data++;
         data_value = EXTRACT_BE_U_3(data);
      }
      else
      {
         data_value = EXTRACT_BE_U_4(data);
      }
      if ( data_value <= (uint32_t)(attr_type[attr_code].siz_subtypes - 1 +
            attr_type[attr_code].first_subtype) &&
	   data_value >= attr_type[attr_code].first_subtype )
         ND_PRINT("%s", table[data_value]);
      else
         ND_PRINT("#%u", data_value);
   }
   else
   {
      switch(attr_code) /* Be aware of special cases... */
      {
        case FRM_IPX:
             if (EXTRACT_BE_U_4(data) == 0xFFFFFFFE )
                ND_PRINT("NAS Select");
             else
                ND_PRINT("%u", EXTRACT_BE_U_4(data));
          break;

        case SESSION_TIMEOUT:
        case IDLE_TIMEOUT:
        case ACCT_DELAY:
        case ACCT_SESSION_TIME:
        case ACCT_INT_INTERVAL:
             timeout = EXTRACT_BE_U_4(data);
             if ( timeout < 60 )
                ND_PRINT("%02d secs", timeout);
             else
             {
                if ( timeout < 3600 )
                   ND_PRINT("%02d:%02d min",
                          timeout / 60, timeout % 60);
                else
                   ND_PRINT("%02d:%02d:%02d hours",
                          timeout / 3600, (timeout % 3600) / 60,
                          timeout % 60);
             }
          break;

        case FRM_ATALK_LINK:
             if (EXTRACT_BE_U_4(data))
                ND_PRINT("%u", EXTRACT_BE_U_4(data));
             else
                ND_PRINT("Unnumbered");
          break;

        case FRM_ATALK_NETWORK:
             if (EXTRACT_BE_U_4(data))
                ND_PRINT("%u", EXTRACT_BE_U_4(data));
             else
                ND_PRINT("NAS assigned");
          break;

        case TUNNEL_PREFERENCE:
            if (EXTRACT_U_1(data))
               ND_PRINT("Tag[%u] ", EXTRACT_U_1(data));
            else
               ND_PRINT("Tag[Unused] ");
            data++;
            ND_PRINT("%u", EXTRACT_BE_U_3(data));
          break;

        case EGRESS_VLAN_ID:
            ND_PRINT("%s (0x%02x) ",
                   tok2str(rfc4675_tagged,"Unknown tag",EXTRACT_U_1(data)),
                   EXTRACT_U_1(data));
            data++;
            ND_PRINT("%u", EXTRACT_BE_U_3(data));
          break;

        default:
             ND_PRINT("%u", EXTRACT_BE_U_4(data));
          break;

      } /* switch */

   } /* if-else */

   return;

   trunc:
     nd_print_trunc(ndo);
}

/*****************************/
/* Print an attribute IPv4   */
/* address value pointed by  */
/* 'data' and 'length' size. */
/*****************************/
/* Returns nothing.          */
/*****************************/
static void
print_attr_address(netdissect_options *ndo,
                   const u_char *data, u_int length, u_short attr_code)
{
   if (length != 4)
   {
       ND_PRINT("ERROR: length %u != 4", length);
       return;
   }

   ND_TCHECK_4(data);

   switch(attr_code)
   {
      case FRM_IPADDR:
      case LOG_IPHOST:
           if (EXTRACT_BE_U_4(data) == 0xFFFFFFFF )
              ND_PRINT("User Selected");
           else
              if (EXTRACT_BE_U_4(data) == 0xFFFFFFFE )
                 ND_PRINT("NAS Select");
              else
                 ND_PRINT("%s",ipaddr_string(ndo, data));
      break;

      default:
          ND_PRINT("%s", ipaddr_string(ndo, data));
      break;
   }

   return;

   trunc:
     nd_print_trunc(ndo);
}

/*****************************/
/* Print an attribute IPv6   */
/* address value pointed by  */
/* 'data' and 'length' size. */
/*****************************/
/* Returns nothing.          */
/*****************************/
static void
print_attr_address6(netdissect_options *ndo,
                   const u_char *data, u_int length, u_short attr_code _U_)
{
   if (length != 16)
   {
       ND_PRINT("ERROR: length %u != 16", length);
       return;
   }

   ND_TCHECK_16(data);

   ND_PRINT("%s", ip6addr_string(ndo, data));

   return;

   trunc:
     nd_print_trunc(ndo);
}

static void
print_attr_netmask6(netdissect_options *ndo,
                    const u_char *data, u_int length, u_short attr_code _U_)
{
   u_char data2[16];

   if (length < 2 || length > 18)
   {
       ND_PRINT("ERROR: length %u not in range (2..18)", length);
       return;
   }
   ND_TCHECK_LEN(data, length);
   if (EXTRACT_U_1(data + 1) > 128)
   {
      ND_PRINT("ERROR: netmask %u not in range (0..128)", EXTRACT_U_1(data + 1));
      return;
   }

   memset(data2, 0, sizeof(data2));
   if (length > 2)
      memcpy(data2, data+2, length-2);

   ND_PRINT("%s/%u", ip6addr_string(ndo, data2), EXTRACT_U_1(data + 1));

   if (EXTRACT_U_1(data + 1) > 8 * (length - 2))
      ND_PRINT(" (inconsistent prefix length)");

   return;

   trunc:
     nd_print_trunc(ndo);
}

static void
print_attr_mip6_home_link_prefix(netdissect_options *ndo,
                    const u_char *data, u_int length, u_short attr_code _U_)
{
   if (length != 17)
   {
      ND_PRINT("ERROR: length %u != 17", length);
      return;
   }
   ND_TCHECK_LEN(data, length);
   if (EXTRACT_U_1(data) > 128)
   {
      ND_PRINT("ERROR: netmask %u not in range (0..128)", EXTRACT_U_1(data));
      return;
   }

   ND_PRINT("%s/%u", ip6addr_string(ndo, data + 1), EXTRACT_U_1(data));

   return;

   trunc:
     nd_print_trunc(ndo);
}

/*************************************/
/* Print an attribute of 'secs since */
/* January 1, 1970 00:00 UTC' value  */
/* pointed by 'data' and 'length'    */
/* size.                             */
/*************************************/
/* Returns nothing.                  */
/*************************************/
static void
print_attr_time(netdissect_options *ndo,
                const u_char *data, u_int length, u_short attr_code _U_)
{
   time_t attr_time;
   char string[26];

   if (length != 4)
   {
       ND_PRINT("ERROR: length %u != 4", length);
       return;
   }

   ND_TCHECK_4(data);

   attr_time = EXTRACT_BE_U_4(data);
   strlcpy(string, ctime(&attr_time), sizeof(string));
   /* Get rid of the newline */
   string[24] = '\0';
   ND_PRINT("%.24s", string);
   return;

   trunc:
     nd_print_trunc(ndo);
}

static void
print_attr_vector64(netdissect_options *ndo,
                 register const u_char *data, u_int length, u_short attr_code _U_)
{
   uint64_t data_value, i;
   const char *sep = "";

   if (length != 8)
   {
       ND_PRINT("ERROR: length %u != 8", length);
       return;
   }

   ND_PRINT("[");
   ND_TCHECK_8(data[0]);

   data_value = EXTRACT_BE_U_8(data);
   /* Print the 64-bit field in a format similar to bittok2str(), less
    * flagging any unknown bits. This way it should be easier to replace
    * the custom code with a library function later.
    */
   for (i = 0; i < TAM_SIZE(mip6_feature_vector); i++) {
       if (data_value & mip6_feature_vector[i].v) {
           ND_PRINT("%s%s", sep, mip6_feature_vector[i].s);
           sep = ", ";
       }
   }

   ND_PRINT("]");

   return;

   trunc:
     nd_print_trunc(ndo);
}

/***********************************/
/* Print an attribute of 'strange' */
/* data format pointed by 'data'   */
/* and 'length' size.              */
/***********************************/
/* Returns nothing.                */
/***********************************/
static void
print_attr_strange(netdissect_options *ndo,
                   const u_char *data, u_int length, u_short attr_code)
{
   u_short len_data;
   u_int error_cause_value;

   switch(attr_code)
   {
      case ARAP_PASS:
           if (length != 16)
           {
               ND_PRINT("ERROR: length %u != 16", length);
               return;
           }
           ND_PRINT("User_challenge (");
           ND_TCHECK_8(data);
           len_data = 8;
           PRINT_HEX(len_data, data);
           ND_PRINT(") User_resp(");
           ND_TCHECK_8(data);
           len_data = 8;
           PRINT_HEX(len_data, data);
           ND_PRINT(")");
        break;

      case ARAP_FEATURES:
           if (length != 14)
           {
               ND_PRINT("ERROR: length %u != 14", length);
               return;
           }
           ND_TCHECK_1(data);
           if (EXTRACT_U_1(data))
              ND_PRINT("User can change password");
           else
              ND_PRINT("User cannot change password");
           data++;
           ND_TCHECK_1(data);
           ND_PRINT(", Min password length: %u", EXTRACT_U_1(data));
           data++;
           ND_PRINT(", created at: ");
           ND_TCHECK_4(data);
           len_data = 4;
           PRINT_HEX(len_data, data);
           ND_PRINT(", expires in: ");
           ND_TCHECK_4(data);
           len_data = 4;
           PRINT_HEX(len_data, data);
           ND_PRINT(", Current Time: ");
           ND_TCHECK_4(data);
           len_data = 4;
           PRINT_HEX(len_data, data);
        break;

      case ARAP_CHALLENGE_RESP:
           if (length < 8)
           {
               ND_PRINT("ERROR: length %u != 8", length);
               return;
           }
           ND_TCHECK_8(data);
           len_data = 8;
           PRINT_HEX(len_data, data);
        break;

      case ERROR_CAUSE:
           if (length != 4)
           {
               ND_PRINT("Error: length %u != 4", length);
               return;
           }
           ND_TCHECK_4(data);

           error_cause_value = EXTRACT_BE_U_4(data);
           ND_PRINT("Error cause %u: %s", error_cause_value, tok2str(errorcausetype, "Error-Cause %u not known", error_cause_value));
        break;
   }
   return;

   trunc:
     nd_print_trunc(ndo);
}

static void
radius_attrs_print(netdissect_options *ndo,
                   const u_char *attr, u_int length)
{
   const struct radius_attr *rad_attr = (const struct radius_attr *)attr;
   const char *attr_string;
   uint8_t type, len;

   while (length > 0)
   {
     if (length < 2)
        goto trunc;
     ND_TCHECK_SIZE(rad_attr);

     type = EXTRACT_U_1(rad_attr->type);
     len = EXTRACT_U_1(rad_attr->len);
     if (type != 0 && type < TAM_SIZE(attr_type))
	attr_string = attr_type[type].name;
     else
	attr_string = "Unknown";
     if (len < 2)
     {
	ND_PRINT("\n\t  %s Attribute (%u), length: %u (bogus, must be >= 2)",
               attr_string,
               type,
               len);
	return;
     }
     if (len > length)
     {
	ND_PRINT("\n\t  %s Attribute (%u), length: %u (bogus, goes past end of packet)",
               attr_string,
               type,
               len);
        return;
     }
     ND_PRINT("\n\t  %s Attribute (%u), length: %u, Value: ",
            attr_string,
            type,
            len);

     if (type < TAM_SIZE(attr_type))
     {
         if (len > 2)
         {
             if ( attr_type[type].print_func )
                 (*attr_type[type].print_func)(
                     ndo, ((const u_char *)(rad_attr+1)),
                     len - 2, type);
         }
     }
     /* do we also want to see a hex dump ? */
     if (ndo->ndo_vflag> 1)
         print_unknown_data(ndo, (const u_char *)rad_attr+2, "\n\t    ", (len)-2);

     length-=(len);
     rad_attr = (const struct radius_attr *)( ((const char *)(rad_attr))+len);
   }
   return;

trunc:
   nd_print_trunc(ndo);
}

void
radius_print(netdissect_options *ndo,
             const u_char *dat, u_int length)
{
   const struct radius_hdr *rad;
   u_int len, auth_idx;

   ndo->ndo_protocol = "radius";
   ND_TCHECK_LEN(dat, MIN_RADIUS_LEN);
   rad = (const struct radius_hdr *)dat;
   len = EXTRACT_BE_U_2(rad->len);

   if (len < MIN_RADIUS_LEN)
   {
	  nd_print_trunc(ndo);
	  return;
   }

   if (len > length)
	  len = length;

   if (ndo->ndo_vflag < 1) {
       ND_PRINT("RADIUS, %s (%u), id: 0x%02x length: %u",
              tok2str(radius_command_values,"Unknown Command",EXTRACT_U_1(rad->code)),
              EXTRACT_U_1(rad->code),
              EXTRACT_U_1(rad->id),
              len);
       return;
   }
   else {
       ND_PRINT("RADIUS, length: %u\n\t%s (%u), id: 0x%02x, Authenticator: ",
              len,
              tok2str(radius_command_values,"Unknown Command",EXTRACT_U_1(rad->code)),
              EXTRACT_U_1(rad->code),
              EXTRACT_U_1(rad->id));

       for(auth_idx=0; auth_idx < 16; auth_idx++)
            ND_PRINT("%02x", rad->auth[auth_idx]);
   }

   if (len > MIN_RADIUS_LEN)
      radius_attrs_print(ndo, dat + MIN_RADIUS_LEN, len - MIN_RADIUS_LEN);
   return;

trunc:
   nd_print_trunc(ndo);
}
