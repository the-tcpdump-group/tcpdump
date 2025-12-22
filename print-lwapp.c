/*
 * Copyright (c) 1998-2007 The TCPDUMP project
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code
 * distributions retain the above copyright notice and this paragraph
 * in its entirety, and (2) distributions including binary code include
 * the above copyright notice and this paragraph in its entirety in
 * the documentation or other materials provided with the distribution.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND
 * WITHOUT ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, WITHOUT
 * LIMITATION, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE.
 *
 * Original code by Carles Kishimoto <carles.kishimoto@gmail.com>
 */

/* \summary: Light Weight Access Point Protocol (LWAPP) printer */

/* specification: RFC 5412 */

#include <config.h>

#include "netdissect-stdinc.h"

#define ND_LONGJMP_FROM_TCHECK
#include "netdissect.h"
#include "extract.h"
#include "addrtoname.h"


/*
 * LWAPP transport (common) header
 *     0                   1                   2                   3
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |VER| RID |C|F|L|    Frag ID    |            Length             |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |          Status/WLANs         |   Payload...  |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

struct lwapp_transport_header {
	nd_uint8_t  ver_rid_cfl;
	nd_uint8_t  frag_id;
	nd_uint16_t length;
	nd_uint16_t status;
};

#define LWAPP_VERSION 0
#define LWAPP_EXTRACT_VER(x) (((x) & 0xC0) >> 6)
#define LWAPP_EXTRACT_RID(x) (((x) & 0x38) >> 3)
#define LWAPP_EXTRACT_CFL(x) ((x) & 0x07)

#define LWAPP_L_BIT 0x01
#define LWAPP_F_BIT 0x02
#define LWAPP_C_BIT 0x04

static const struct tok lwapp_header_bits_values[] = {
	{ LWAPP_L_BIT, "Not Last" },
	{ LWAPP_F_BIT, "Fragment" },
	{ LWAPP_C_BIT, "Control"  },
	{ 0, NULL}
};

/*
 * LWAPP control header
 *      0                   1                   2                   3
 *      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |  Message Type |    Seq Num    |      Msg Element Length       |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |                           Session ID                          |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |      Msg Element [0..N]       |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

struct lwapp_control_header {
	nd_uint8_t  msg_type;
	nd_uint8_t  seq_num;
	nd_uint16_t len;
	nd_uint32_t session_id;
};

#define LWAPP_MSGTYPE_DISCOVERY_REQ            1
#define LWAPP_MSGTYPE_DISCOVERY_RESP           2
#define LWAPP_MSGTYPE_JOIN_REQ                 3
#define LWAPP_MSGTYPE_JOIN_RESP                4
#define LWAPP_MSGTYPE_JOIN_ACK                 5
#define LWAPP_MSGTYPE_JOIN_CONFIRM             6
// Unused 7-9
#define LWAPP_MSGTYPE_CONFIGURE_REQ           10
#define LWAPP_MSGTYPE_CONFIGURE_RESP          11
#define LWAPP_MSGTYPE_CONF_UPDATE_REQ         12
#define LWAPP_MSGTYPE_CONF_UPDATE_RESP        13
#define LWAPP_MSGTYPE_WTP_EVENT_REQ           14
#define LWAPP_MSGTYPE_WTP_EVENT_RESP          15
#define LWAPP_MSGTYPE_CHANGE_STATE_EVENT_REQ  16
#define LWAPP_MSGTYPE_CHANGE_STATE_EVENT_RESP 17
// Unused 18-21
#define LWAPP_MSGTYPE_ECHO_REQ                22
#define LWAPP_MSGTYPE_ECHO_RESP               23
#define LWAPP_MSGTYPE_IMAGE_DATA_REQ          24
#define LWAPP_MSGTYPE_IMAGE_DATA_RESP         25
#define LWAPP_MSGTYPE_RESET_REQ               26
#define LWAPP_MSGTYPE_RESET_RESP              27
// Unused 28-29
#define LWAPP_MSGTYPE_KEY_UPDATE_REQ          30
#define LWAPP_MSGTYPE_KEY_UPDATE_RESP         31
#define LWAPP_MSGTYPE_PRIMARY_DISCOVERY_REQ   32
#define LWAPP_MSGTYPE_PRIMARY_DISCOVERY_RESP  33
#define LWAPP_MSGTYPE_DATA_TRANSFER_REQ       34
#define LWAPP_MSGTYPE_DATA_TRANSFER_RESP      35
#define LWAPP_MSGTYPE_CLEAR_CONFIG_INDICATION 36
#define LWAPP_MSGTYPE_WLAN_CONFIG_REQ         37
#define LWAPP_MSGTYPE_WLAN_CONFIG_RESP        38
#define LWAPP_MSGTYPE_MOBILE_CONFIG_REQ       39
#define LWAPP_MSGTYPE_MOBILE_CONFIG_RESP      40

static const struct tok lwapp_msg_type_values[] = {
	{ LWAPP_MSGTYPE_DISCOVERY_REQ,           "Discovery req"           },
	{ LWAPP_MSGTYPE_DISCOVERY_RESP,          "Discovery resp"          },
	{ LWAPP_MSGTYPE_JOIN_REQ,                "Join req"                },
	{ LWAPP_MSGTYPE_JOIN_RESP,               "Join resp"               },
	{ LWAPP_MSGTYPE_JOIN_ACK,                "Join ack"                },
	{ LWAPP_MSGTYPE_JOIN_CONFIRM,            "Join confirm"            },
	{ LWAPP_MSGTYPE_CONFIGURE_REQ,           "Configure req"           },
	{ LWAPP_MSGTYPE_CONFIGURE_RESP,          "Configure resp"          },
	{ LWAPP_MSGTYPE_CONF_UPDATE_REQ,         "Update req"              },
	{ LWAPP_MSGTYPE_CONF_UPDATE_RESP,        "Update resp"             },
	{ LWAPP_MSGTYPE_WTP_EVENT_REQ,           "WTP event req"           },
	{ LWAPP_MSGTYPE_WTP_EVENT_RESP,          "WTP event resp"          },
	{ LWAPP_MSGTYPE_CHANGE_STATE_EVENT_REQ,  "Change state event req"  },
	{ LWAPP_MSGTYPE_CHANGE_STATE_EVENT_RESP, "Change state event resp" },
	{ LWAPP_MSGTYPE_ECHO_REQ,                "Echo req"                },
	{ LWAPP_MSGTYPE_ECHO_RESP,               "Echo resp"               },
	{ LWAPP_MSGTYPE_IMAGE_DATA_REQ,          "Image data req"          },
	{ LWAPP_MSGTYPE_IMAGE_DATA_RESP,         "Image data resp"         },
	{ LWAPP_MSGTYPE_RESET_REQ,               "Channel status req"      },
	{ LWAPP_MSGTYPE_RESET_RESP,              "Channel status resp"     },
	{ LWAPP_MSGTYPE_KEY_UPDATE_REQ,          "Key update req"          },
	{ LWAPP_MSGTYPE_KEY_UPDATE_RESP,         "Key update resp"         },
	{ LWAPP_MSGTYPE_PRIMARY_DISCOVERY_REQ,   "Primary discovery req"   },
	{ LWAPP_MSGTYPE_PRIMARY_DISCOVERY_RESP,  "Primary discovery resp"  },
	{ LWAPP_MSGTYPE_DATA_TRANSFER_REQ,       "Data transfer req"       },
	{ LWAPP_MSGTYPE_DATA_TRANSFER_RESP,      "Data transfer resp"      },
	{ LWAPP_MSGTYPE_CLEAR_CONFIG_INDICATION, "Clear config ind"        },
	{ LWAPP_MSGTYPE_WLAN_CONFIG_REQ,         "Wlan config req"         },
	{ LWAPP_MSGTYPE_WLAN_CONFIG_RESP,        "Wlan config resp"        },
	{ LWAPP_MSGTYPE_MOBILE_CONFIG_REQ,       "Mobile config req"       },
	{ LWAPP_MSGTYPE_MOBILE_CONFIG_RESP,      "Mobile config resp"      },
	{ 0, NULL}
};

/*
 * LWAPP message elements
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |      Type     |             Length            |   Value ...   |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct lwapp_msgelem_header {
	nd_uint8_t  type;
	nd_uint16_t length;
};

#define LWAPP_MSGELEM_AC_ADDRESS                           2
#define LWAPP_MSGELEM_WTP_DESCRIPTOR                       3
#define LWAPP_MSGELEM_WTP_RADIO_INFO                       4
#define LWAPP_MSGELEM_WTP_NAME                             5
#define LWAPP_MSGELEM_AC_DESCRIPTOR                        6
#define LWAPP_MSGELEM_80211_ADD_WLAN                       7
#define LWAPP_MSGELEM_80211_WTP_WLAN_RADIO_CONFIG          8
#define LWAPP_MSGELEM_80211_MULTI_DOMAIN_CAP              10
#define LWAPP_MSGELEM_80211_MAC_OPERATION                 11
#define LWAPP_MSGELEM_80211_TX_POWER                      12
#define LWAPP_MSGELEM_80211_TX_POWER_LEVEL                13
#define LWAPP_MSGELEM_80211_DIRECT_SEQ_CONTROL            14
#define LWAPP_MSGELEM_80211_OFDM_CONTROL                  15
#define LWAPP_MSGELEM_80211_RATE_SET                      16
#define LWAPP_MSGELEM_TEST                                18
#define LWAPP_MSGELEM_CHANGE_STATE_EVENT                  26
#define LWAPP_MSGELEM_ADMIN_STATE                         27
#define LWAPP_MSGELEM_80211_DELETE_WLAN                   28
#define LWAPP_MSGELEM_ADD_MOBILE                          29
#define LWAPP_MSGELEM_DELETE_MOBILE                       30
#define LWAPP_MSGELEM_AC_NAME                             31
#define LWAPP_MSGELEM_IMAGE_DATA                          33
#define LWAPP_MSGELEM_80211_UPDATE_WLAN                   34
#define LWAPP_MSGELEM_LOCATION_DATA                       35
#define LWAPP_MSGELEM_STATISTICS_TIMER                    37
#define LWAPP_MSGELEM_DECRYPTION_ERROR_REPORT_PERIOD      38
#define LWAPP_MSGELEM_DECRYPTION_ERROR_REPORT             39
#define LWAPP_MSGELEM_80211_ANTENNA                       41
#define LWAPP_MSGELEM_CERTIFICATE                         44
#define LWAPP_MSGELEM_SESSION_ID                          45
#define LWAPP_MSGELEM_80211_CFP_STATUS                    48
#define LWAPP_MSGELEM_WTP_BOARD_DATA                      50
#define LWAPP_MSGELEM_80211_BROADCAST_PROBE_MODE          51
#define LWAPP_MSGELEM_DATA_TRANSFER_MODE                  52
#define LWAPP_MSGELEM_DATA_TRANSFER_DATA                  53
#define LWAPP_MSGELEM_WTP_MODE_AND_TYPE                   54
#define LWAPP_MSGELEM_WTP_QOS                             57
#define LWAPP_MSGELEM_DISCOVERY_TYPE                      58
#define LWAPP_MSGELEM_AC_IPV4_LIST                        59
#define LWAPP_MSGELEM_STATUS                              60
#define LWAPP_MSGELEM_80211_MIC_COUNTERMEASURES           61
#define LWAPP_MSGELEM_ADD_BLACKLIST_ENTRY                 65
#define LWAPP_MSGELEM_DELETE_BLACKLIST_ENTRY              66
#define LWAPP_MSGELEM_WTP_REBOOT_STATISTICS               67
#define LWAPP_MSGELEM_LWAPP_TIMERS                        68
#define LWAPP_MSGELEM_ADD_STATIC_BLACKLIST_ENTRY          70
#define LWAPP_MSGELEM_DELETE_STATIC_BLACKLIST_ENTRY       71
#define LWAPP_MSGELEM_DUPLICATE_IPV4_ADDR                 77
#define LWAPP_MSGELEM_80211_MIC_ERROR_REPORT_FROM_MOBILE  79
#define LWAPP_MSGELEM_WTP_STATIC_IP_ADDR_INFO             82
#define LWAPP_MSGELEM_AC_NAME_WITH_INDEX                  90
#define LWAPP_MSGELEM_WTP_FALLBACK                        91
#define LWAPP_MSGELEM_80211_WTP_RADIO_FAIL_ALARM_IND      95
#define LWAPP_MSGELEM_IDLE_TIMEOUT                        97
#define LWAPP_MSGELEM_WTP_MGR_CTRL_IPV4                   99
#define LWAPP_MSGELEM_VENDOR_SPECIFIC                    104
#define LWAPP_MSGELEM_80211_MOBILE_SESSION_KEY           105
#define LWAPP_MSGELEM_80211_UPDATE_MOBILE_QOS            106
#define LWAPP_MSGELEM_WNONCE                             107
#define LWAPP_MSGELEM_ANONCE                             108
#define LWAPP_MSGELEM_PSK_MIC                            109
#define LWAPP_MSGELEM_XNONCE                             111
#define LWAPP_MSGELEM_WTP_MGR_CTRL_IPV6                  137
#define LWAPP_MSGELEM_WTP_MGR_DATA_IPV4                  138
#define LWAPP_MSGELEM_WTP_MGR_DATA_IPV6                  139
#define LWAPP_MSGELEM_80211_STATION_QOS_PROFILE          140
#define LWAPP_MSGELEM_AC_IPV6_LIST                       141
/*
 * RFC5412 also defines the "Image Download" message element in Section 8.1.1,
 * but does not assign a type for it (Errata ID: 8509).  Also it assigns the
 * following duplicate message element IDs:
 *
 * - 2 "Result Code" (Errata ID: 8538)
 * - 16 "IEEE 802.11 Supported Rates" (Errata ID: 8548)
 * - 38 "IEEE 802.11 Statistics" (Errata ID: 8546)
 * - 77 "Duplicate IPv6 Address" (Errata ID: 8544)
 */


static const struct tok lwapp_msg_elem_values[] = {
	{ LWAPP_MSGELEM_AC_ADDRESS,                         "AC Address"                               },
	// Omit "Result Code".
	{ LWAPP_MSGELEM_WTP_DESCRIPTOR,                     "WTP Descriptor"                           },
	{ LWAPP_MSGELEM_WTP_RADIO_INFO,                     "WTP Radio Information"                    },
	{ LWAPP_MSGELEM_WTP_NAME,                           "WTP Name"                                 },
	{ LWAPP_MSGELEM_AC_DESCRIPTOR,                      "AC Descriptor"                            },
	{ LWAPP_MSGELEM_80211_ADD_WLAN,                     "IEEE 802.11 Add WLAN"                     },
	{ LWAPP_MSGELEM_80211_WTP_WLAN_RADIO_CONFIG,        "IEEE 802.11 WTP WLAN Radio Configuration" },
	{ LWAPP_MSGELEM_80211_MULTI_DOMAIN_CAP,             "IEEE 802.11 Multi-Domain Capability"      },
	{ LWAPP_MSGELEM_80211_MAC_OPERATION,                "IEEE 802.11 MAC Operation"                },
	{ LWAPP_MSGELEM_80211_TX_POWER,                     "IEEE 802.11 Tx Power"                     },
	{ LWAPP_MSGELEM_80211_TX_POWER_LEVEL,               "IEEE 802.11 Tx Power Level"               },
	{ LWAPP_MSGELEM_80211_DIRECT_SEQ_CONTROL,           "IEEE 802.11 Direct Sequence Control"      },
	{ LWAPP_MSGELEM_80211_OFDM_CONTROL,                 "IEEE 802.11 OFDM Control"                 },
	{ LWAPP_MSGELEM_80211_RATE_SET,                     "IEEE 802.11 Rate Set"                     },
	// Omit "IEEE 802.11 Supported Rates".
	{ LWAPP_MSGELEM_TEST,                               "Test"                                     },
	{ LWAPP_MSGELEM_CHANGE_STATE_EVENT,                 "Change State Event"                       },
	{ LWAPP_MSGELEM_ADMIN_STATE,                        "Administrative State"                     },
	{ LWAPP_MSGELEM_80211_DELETE_WLAN,                  "IEEE 802.11 Delete WLAN"                  },
	{ LWAPP_MSGELEM_ADD_MOBILE,                         "Add Mobile"                               },
	{ LWAPP_MSGELEM_DELETE_MOBILE,                      "Delete Mobile"                            },
	{ LWAPP_MSGELEM_AC_NAME,                            "AC Name"                                  },
	{ LWAPP_MSGELEM_IMAGE_DATA,                         "Image Data"                               },
	{ LWAPP_MSGELEM_80211_UPDATE_WLAN,                  "IEEE 802.11 Update WLAN"                  },
	{ LWAPP_MSGELEM_LOCATION_DATA,                      "Location Data"                            },
	{ LWAPP_MSGELEM_STATISTICS_TIMER,                   "Statistics Timer"                         },
	{ LWAPP_MSGELEM_DECRYPTION_ERROR_REPORT_PERIOD,     "Decryption Error Report Period"           },
	// Omit "IEEE 802.11 Statistics".
	{ LWAPP_MSGELEM_DECRYPTION_ERROR_REPORT,            "Decryption Error Report"                  },
	{ LWAPP_MSGELEM_80211_ANTENNA,                      "IEEE 802.11 Antenna"                      },
	{ LWAPP_MSGELEM_CERTIFICATE,                        "Certificate"                              },
	{ LWAPP_MSGELEM_SESSION_ID,                         "Session ID"                               },
	{ LWAPP_MSGELEM_80211_CFP_STATUS,                   "IEEE 802.11 CFP Status"                   },
	{ LWAPP_MSGELEM_WTP_BOARD_DATA,                     "WTP Board Data"                           },
	{ LWAPP_MSGELEM_80211_BROADCAST_PROBE_MODE,         "IEEE 802.11 Broadcast Probe Mode"         },
	{ LWAPP_MSGELEM_DATA_TRANSFER_MODE,                 "Data Transfer Mode"                       },
	{ LWAPP_MSGELEM_DATA_TRANSFER_DATA,                 "Data Transfer Data"                       },
	{ LWAPP_MSGELEM_WTP_MODE_AND_TYPE,                  "IEEE 802.11 WTP Mode and Type"            },
	{ LWAPP_MSGELEM_WTP_QOS,                            "IEEE 802.11 WTP Quality of Service"       },
	{ LWAPP_MSGELEM_DISCOVERY_TYPE,                     "Discovery Type"                           },
	{ LWAPP_MSGELEM_AC_IPV4_LIST,                       "AC IPv4 List"                             },
	{ LWAPP_MSGELEM_STATUS,                             "Status"                                   },
	{ LWAPP_MSGELEM_80211_MIC_COUNTERMEASURES,          "IEEE 802.11 MIC Countermeasures"          },
	{ LWAPP_MSGELEM_ADD_BLACKLIST_ENTRY,                "Add Blacklist Entry"                      },
	{ LWAPP_MSGELEM_DELETE_BLACKLIST_ENTRY,             "Delete Blacklist Entry"                   },
	{ LWAPP_MSGELEM_WTP_REBOOT_STATISTICS,              "WTP Reboot Statistics"                    },
	{ LWAPP_MSGELEM_LWAPP_TIMERS,                       "LWAPP Timers"                             },

	// Incorrect names in the spec (Errata ID: 8460).
	{ LWAPP_MSGELEM_ADD_STATIC_BLACKLIST_ENTRY,         "Add Static Blacklist Entry"               },
	{ LWAPP_MSGELEM_DELETE_STATIC_BLACKLIST_ENTRY,      "Delete Static Blacklist Entry"            },

	{ LWAPP_MSGELEM_DUPLICATE_IPV4_ADDR,                "Duplicate IPv4 Address"                   },
	// Omit "Duplicate IPv6 Address".
	{ LWAPP_MSGELEM_80211_MIC_ERROR_REPORT_FROM_MOBILE, "IEEE 802.11 MIC Error Report From Mobile" },
	{ LWAPP_MSGELEM_WTP_STATIC_IP_ADDR_INFO,            "WTP Static IP Address Information"        },
	{ LWAPP_MSGELEM_AC_NAME_WITH_INDEX,                 "AC Name with Index"                       },
	{ LWAPP_MSGELEM_WTP_FALLBACK,                       "WTP Fallback"                             },
	{ LWAPP_MSGELEM_80211_WTP_RADIO_FAIL_ALARM_IND,     "WTP Radio Fail Alarm Indication"          },
	{ LWAPP_MSGELEM_IDLE_TIMEOUT,                       "Idle Timeout"                             },
	{ LWAPP_MSGELEM_WTP_MGR_CTRL_IPV4,                  "WTP Manager Control IPv4 Address"         },
	{ LWAPP_MSGELEM_VENDOR_SPECIFIC,                    "Vendor Specific"                          },
	{ LWAPP_MSGELEM_80211_MOBILE_SESSION_KEY,           "IEEE 802.11 Mobile Session Key"           },
	{ LWAPP_MSGELEM_80211_UPDATE_MOBILE_QOS,            "IEEE 802.11 Update Mobile QoS"            },
	{ LWAPP_MSGELEM_WNONCE,                             "WNonce"                                   },
	{ LWAPP_MSGELEM_ANONCE,                             "ANonce"                                   },
	{ LWAPP_MSGELEM_PSK_MIC,                            "PSK-MIC"                                  },
	{ LWAPP_MSGELEM_XNONCE,                             "XNonce"                                   },
	{ LWAPP_MSGELEM_WTP_MGR_CTRL_IPV6,                  "WTP Manager Control IPv6 Address"         },
	{ LWAPP_MSGELEM_WTP_MGR_DATA_IPV4,                  "WTP Manager Data IPv4 Address"            },
	{ LWAPP_MSGELEM_WTP_MGR_DATA_IPV6,                  "WTP Manager Data IPv6 Address"            },
	{ LWAPP_MSGELEM_80211_STATION_QOS_PROFILE,          "IEEE 802.11 Station QoS Profile"          },
	{ LWAPP_MSGELEM_AC_IPV6_LIST,                       "AC IPv6 List"                             },
	{ 0, NULL}
};

/*
 * Message element type is an 8-bit value, so size the array to make any
 * uint8_t index valid.  Array elements that are implicitly initialized to 0
 * effectively mean no minimum length requirement for the respective message
 * element types.
 */
static const uint16_t msg_elem_minlen[UINT8_MAX + 1] = {
	[LWAPP_MSGELEM_AC_ADDRESS]                         =   7,
	// Omit "Result Code".
	[LWAPP_MSGELEM_WTP_DESCRIPTOR]                     =  16,
	[LWAPP_MSGELEM_WTP_RADIO_INFO]                     =   2,
	[LWAPP_MSGELEM_WTP_NAME]                           =   1,
	[LWAPP_MSGELEM_AC_DESCRIPTOR]                      =  18, // 17 in the spec (Errata ID: 8536).
	[LWAPP_MSGELEM_80211_ADD_WLAN]                     = 298,
	[LWAPP_MSGELEM_80211_WTP_WLAN_RADIO_CONFIG]        =  21, // 20 in the spec (Errata ID: 8547).
	[LWAPP_MSGELEM_80211_MULTI_DOMAIN_CAP]             =   8,
	[LWAPP_MSGELEM_80211_MAC_OPERATION]                =  16,
	[LWAPP_MSGELEM_80211_TX_POWER]                     =   4,
	[LWAPP_MSGELEM_80211_TX_POWER_LEVEL]               =   4,
	[LWAPP_MSGELEM_80211_DIRECT_SEQ_CONTROL]           =   8,
	[LWAPP_MSGELEM_80211_OFDM_CONTROL]                 =   8,
	[LWAPP_MSGELEM_80211_RATE_SET]                     =   4,
	// Omit "IEEE 802.11 Supported Rates".
	[LWAPP_MSGELEM_TEST]                               =   1,
	[LWAPP_MSGELEM_CHANGE_STATE_EVENT]                 =   3,
	[LWAPP_MSGELEM_ADMIN_STATE]                        =   2,
	[LWAPP_MSGELEM_80211_DELETE_WLAN]                  =   3,
	[LWAPP_MSGELEM_ADD_MOBILE]                         =  36,
	[LWAPP_MSGELEM_DELETE_MOBILE]                      =   7,
	[LWAPP_MSGELEM_AC_NAME]                            =   1,
	[LWAPP_MSGELEM_IMAGE_DATA]                         =   3, // 5 in the spec (Errata ID: 8543).
	[LWAPP_MSGELEM_80211_UPDATE_WLAN]                  =  43,
	[LWAPP_MSGELEM_LOCATION_DATA]                      =   1,
	[LWAPP_MSGELEM_STATISTICS_TIMER]                   =   2,
	[LWAPP_MSGELEM_DECRYPTION_ERROR_REPORT_PERIOD]     =   3,
	// Omit "IEEE 802.11 Statistics".
	[LWAPP_MSGELEM_DECRYPTION_ERROR_REPORT]            =   8,
	[LWAPP_MSGELEM_80211_ANTENNA]                      =   8,
	[LWAPP_MSGELEM_CERTIFICATE]                        =   1,
	[LWAPP_MSGELEM_SESSION_ID]                         =   4,
	[LWAPP_MSGELEM_80211_CFP_STATUS]                   =   2,
	[LWAPP_MSGELEM_WTP_BOARD_DATA]                     =  26,
	[LWAPP_MSGELEM_80211_BROADCAST_PROBE_MODE]         =   1,
	[LWAPP_MSGELEM_DATA_TRANSFER_MODE]                 =   1,
	[LWAPP_MSGELEM_DATA_TRANSFER_DATA]                 =   3,
	[LWAPP_MSGELEM_WTP_MODE_AND_TYPE]                  =   2,
	[LWAPP_MSGELEM_WTP_QOS]                            =  52, // 12 in the spec (Errata ID: 8549).
	[LWAPP_MSGELEM_DISCOVERY_TYPE]                     =   1,
	[LWAPP_MSGELEM_AC_IPV4_LIST]                       =   4,
	[LWAPP_MSGELEM_STATUS]                             =   1,
	[LWAPP_MSGELEM_80211_MIC_COUNTERMEASURES]          =   8,
	[LWAPP_MSGELEM_ADD_BLACKLIST_ENTRY]                =   7,
	[LWAPP_MSGELEM_DELETE_BLACKLIST_ENTRY]             =   7,
	[LWAPP_MSGELEM_WTP_REBOOT_STATISTICS]              =   7,
	[LWAPP_MSGELEM_LWAPP_TIMERS]                       =   2,
	[LWAPP_MSGELEM_ADD_STATIC_BLACKLIST_ENTRY]         =   7,
	[LWAPP_MSGELEM_DELETE_STATIC_BLACKLIST_ENTRY]      =   7,
	[LWAPP_MSGELEM_DUPLICATE_IPV4_ADDR]                =  10,
	// Omit "Duplicate IPv6 Address".
	[LWAPP_MSGELEM_80211_MIC_ERROR_REPORT_FROM_MOBILE] =  14,
	[LWAPP_MSGELEM_WTP_STATIC_IP_ADDR_INFO]            =  13,
	[LWAPP_MSGELEM_AC_NAME_WITH_INDEX]                 =   2, // 5 in the spec (Errata ID: 8542).
	[LWAPP_MSGELEM_WTP_FALLBACK]                       =   1,
	[LWAPP_MSGELEM_80211_WTP_RADIO_FAIL_ALARM_IND]     =   4,
	[LWAPP_MSGELEM_IDLE_TIMEOUT]                       =   4,
	[LWAPP_MSGELEM_WTP_MGR_CTRL_IPV4]                  =   6,
	[LWAPP_MSGELEM_VENDOR_SPECIFIC]                    =   7,
	[LWAPP_MSGELEM_80211_MOBILE_SESSION_KEY]           =  11,
	[LWAPP_MSGELEM_80211_UPDATE_MOBILE_QOS]            =  14,
	[LWAPP_MSGELEM_WNONCE]                             =  16,
	[LWAPP_MSGELEM_ANONCE]                             =  16,
	[LWAPP_MSGELEM_PSK_MIC]                            =   2,
	[LWAPP_MSGELEM_XNONCE]                             =  16,
	[LWAPP_MSGELEM_WTP_MGR_CTRL_IPV6]                  =  18, // 6 in the spec (Errata ID: 8537).
	[LWAPP_MSGELEM_WTP_MGR_DATA_IPV4]                  =   4,
	[LWAPP_MSGELEM_WTP_MGR_DATA_IPV6]                  =  16, // 4 in the spec (Errata ID: 8539).
	[LWAPP_MSGELEM_80211_STATION_QOS_PROFILE]          =   8, // 12 in the spec (Errata ID: 8545).
	[LWAPP_MSGELEM_AC_IPV6_LIST]                       =  16, // 4 in the spec (Errata ID: 8541).
};

/*
 * "Every control message in this specification specifies which
 * message elements are permitted." -- Section 4.2.1.5
 * Return 1 iff the message type permits the element type.
 */
static u_char
permitted_msg_elem(const uint8_t msg_type, const uint8_t msgelem_type)
{
	switch(msg_type) {
	case LWAPP_MSGTYPE_DISCOVERY_REQ: // Section 5.1
	case LWAPP_MSGTYPE_PRIMARY_DISCOVERY_REQ: // Section 5.3
		switch (msgelem_type) {
		case LWAPP_MSGELEM_DISCOVERY_TYPE:
		case LWAPP_MSGELEM_WTP_DESCRIPTOR:
		case LWAPP_MSGELEM_WTP_RADIO_INFO:
			return 1;
		}
		break;
	case LWAPP_MSGTYPE_DISCOVERY_RESP: // Section 5.2
		switch (msgelem_type) {
		case LWAPP_MSGELEM_AC_ADDRESS:
		case LWAPP_MSGELEM_AC_DESCRIPTOR:
		case LWAPP_MSGELEM_AC_NAME:
		case LWAPP_MSGELEM_WTP_MGR_CTRL_IPV4:
		case LWAPP_MSGELEM_WTP_MGR_CTRL_IPV6:
			return 1;
		}
		break;
	case LWAPP_MSGTYPE_PRIMARY_DISCOVERY_RESP: // Section 5.4
		switch (msgelem_type) {
		case LWAPP_MSGELEM_AC_DESCRIPTOR:
		case LWAPP_MSGELEM_AC_NAME:
		case LWAPP_MSGELEM_WTP_MGR_CTRL_IPV4:
		case LWAPP_MSGELEM_WTP_MGR_CTRL_IPV6:
			return 1;
		}
		break;
	case LWAPP_MSGTYPE_JOIN_REQ: // Section 6.1
		switch (msgelem_type) {
		case LWAPP_MSGELEM_WTP_DESCRIPTOR:
		case LWAPP_MSGELEM_AC_ADDRESS:
		case LWAPP_MSGELEM_WTP_NAME:
		case LWAPP_MSGELEM_LOCATION_DATA:
		case LWAPP_MSGELEM_WTP_RADIO_INFO:
		case LWAPP_MSGELEM_CERTIFICATE:
		case LWAPP_MSGELEM_SESSION_ID:
		case LWAPP_MSGELEM_TEST:
		case LWAPP_MSGELEM_XNONCE:
			return 1;
		}
		break;
	case LWAPP_MSGTYPE_JOIN_RESP: // Section 6.2
		switch (msgelem_type) {
		// Omit "Result Code".
		case LWAPP_MSGELEM_STATUS:
		case LWAPP_MSGELEM_CERTIFICATE:
		case LWAPP_MSGELEM_WTP_MGR_DATA_IPV4:
		case LWAPP_MSGELEM_WTP_MGR_DATA_IPV6:
		case LWAPP_MSGELEM_AC_IPV4_LIST:
		case LWAPP_MSGELEM_AC_IPV6_LIST:
		case LWAPP_MSGELEM_ANONCE:
		case LWAPP_MSGELEM_PSK_MIC:
			return 1;
		}
		break;
	case LWAPP_MSGTYPE_JOIN_ACK: // Section 6.3
		switch (msgelem_type) {
		case LWAPP_MSGELEM_SESSION_ID:
		case LWAPP_MSGELEM_WNONCE:
		case LWAPP_MSGELEM_PSK_MIC:
			return 1;
		}
		break;
	case LWAPP_MSGTYPE_JOIN_CONFIRM: // Section 6.4
		switch (msgelem_type) {
		case LWAPP_MSGELEM_SESSION_ID:
		case LWAPP_MSGELEM_PSK_MIC:
			return 1;
		}
		break;
	case LWAPP_MSGTYPE_KEY_UPDATE_REQ: // Section 6.7
		switch (msgelem_type) {
		case LWAPP_MSGELEM_SESSION_ID:
		case LWAPP_MSGELEM_XNONCE:
			return 1;
		}
		break;
	case LWAPP_MSGTYPE_KEY_UPDATE_RESP: // Section 6.8
		switch (msgelem_type) {
		case LWAPP_MSGELEM_SESSION_ID:
		case LWAPP_MSGELEM_ANONCE:
		case LWAPP_MSGELEM_PSK_MIC:
			return 1;
		}
		break;
	case LWAPP_MSGTYPE_CONFIGURE_REQ:
		switch (msgelem_type) {
		// Section 7.2
		case LWAPP_MSGELEM_ADMIN_STATE:
		case LWAPP_MSGELEM_AC_NAME:
		case LWAPP_MSGELEM_AC_NAME_WITH_INDEX:
		case LWAPP_MSGELEM_WTP_BOARD_DATA:
		case LWAPP_MSGELEM_STATISTICS_TIMER:
		case LWAPP_MSGELEM_WTP_STATIC_IP_ADDR_INFO:
		case LWAPP_MSGELEM_WTP_REBOOT_STATISTICS:
		// Section 11.9
		case LWAPP_MSGELEM_80211_WTP_WLAN_RADIO_CONFIG:
		case LWAPP_MSGELEM_80211_MULTI_DOMAIN_CAP:
		case LWAPP_MSGELEM_80211_MAC_OPERATION:
		case LWAPP_MSGELEM_80211_TX_POWER:
		case LWAPP_MSGELEM_80211_TX_POWER_LEVEL:
		case LWAPP_MSGELEM_80211_DIRECT_SEQ_CONTROL:
		case LWAPP_MSGELEM_80211_OFDM_CONTROL:
		// Omit "IEEE 802.11 Supported Rates".
		case LWAPP_MSGELEM_80211_ANTENNA:
		case LWAPP_MSGELEM_80211_CFP_STATUS:
		case LWAPP_MSGELEM_WTP_MODE_AND_TYPE:
			return 1;
		}
		break;
	case LWAPP_MSGTYPE_CONFIGURE_RESP:
		switch (msgelem_type) {
		// Section 7.3
		case LWAPP_MSGELEM_DECRYPTION_ERROR_REPORT_PERIOD:
		case LWAPP_MSGELEM_CHANGE_STATE_EVENT:
		case LWAPP_MSGELEM_LWAPP_TIMERS:
		case LWAPP_MSGELEM_AC_IPV4_LIST:
		case LWAPP_MSGELEM_AC_IPV6_LIST:
		case LWAPP_MSGELEM_WTP_FALLBACK:
		case LWAPP_MSGELEM_IDLE_TIMEOUT:
		// Section 11.9
		case LWAPP_MSGELEM_80211_WTP_WLAN_RADIO_CONFIG:
		case LWAPP_MSGELEM_80211_RATE_SET:
		case LWAPP_MSGELEM_80211_MULTI_DOMAIN_CAP:
		case LWAPP_MSGELEM_80211_MAC_OPERATION:
		case LWAPP_MSGELEM_80211_TX_POWER:
		case LWAPP_MSGELEM_80211_DIRECT_SEQ_CONTROL:
		case LWAPP_MSGELEM_80211_OFDM_CONTROL:
		// Omit "IEEE 802.11 Supported Rates".
		case LWAPP_MSGELEM_80211_ANTENNA:
		case LWAPP_MSGELEM_80211_BROADCAST_PROBE_MODE:
		case LWAPP_MSGELEM_WTP_QOS:
			return 1;
		}
		break;
	case LWAPP_MSGTYPE_CONF_UPDATE_REQ:
		switch (msgelem_type) {
		// Section 7.4
		case LWAPP_MSGELEM_WTP_NAME:
		case LWAPP_MSGELEM_CHANGE_STATE_EVENT:
		case LWAPP_MSGELEM_ADMIN_STATE:
		case LWAPP_MSGELEM_STATISTICS_TIMER:
		case LWAPP_MSGELEM_LOCATION_DATA:
		case LWAPP_MSGELEM_DECRYPTION_ERROR_REPORT_PERIOD:
		case LWAPP_MSGELEM_AC_IPV4_LIST:
		case LWAPP_MSGELEM_AC_IPV6_LIST:
		case LWAPP_MSGELEM_ADD_BLACKLIST_ENTRY:
		case LWAPP_MSGELEM_DELETE_BLACKLIST_ENTRY:
		case LWAPP_MSGELEM_ADD_STATIC_BLACKLIST_ENTRY:
		case LWAPP_MSGELEM_DELETE_STATIC_BLACKLIST_ENTRY:
		case LWAPP_MSGELEM_LWAPP_TIMERS:
		case LWAPP_MSGELEM_AC_NAME_WITH_INDEX:
		case LWAPP_MSGELEM_WTP_FALLBACK:
		case LWAPP_MSGELEM_IDLE_TIMEOUT:
		// Section 11.9
		case LWAPP_MSGELEM_80211_WTP_WLAN_RADIO_CONFIG:
		case LWAPP_MSGELEM_80211_RATE_SET:
		case LWAPP_MSGELEM_80211_MULTI_DOMAIN_CAP:
		case LWAPP_MSGELEM_80211_MAC_OPERATION:
		case LWAPP_MSGELEM_80211_TX_POWER:
		case LWAPP_MSGELEM_80211_DIRECT_SEQ_CONTROL:
		case LWAPP_MSGELEM_80211_OFDM_CONTROL:
		case LWAPP_MSGELEM_80211_ANTENNA:
		case LWAPP_MSGELEM_80211_CFP_STATUS:
		case LWAPP_MSGELEM_80211_BROADCAST_PROBE_MODE:
		case LWAPP_MSGELEM_WTP_MODE_AND_TYPE:
		case LWAPP_MSGELEM_WTP_QOS:
		case LWAPP_MSGELEM_80211_MIC_ERROR_REPORT_FROM_MOBILE:
			return 1;
		}
		break;
	case LWAPP_MSGTYPE_CONF_UPDATE_RESP: // Section 7.5
		// Omit "Result Code".
		break;
	case LWAPP_MSGTYPE_CHANGE_STATE_EVENT_REQ: // Section 7.6
		return msgelem_type == LWAPP_MSGELEM_CHANGE_STATE_EVENT;
	case LWAPP_MSGTYPE_IMAGE_DATA_REQ: // Section 8.1
		return msgelem_type == LWAPP_MSGELEM_IMAGE_DATA;
	case LWAPP_MSGTYPE_WTP_EVENT_REQ: // Sections 8.5 and 11.7.2
		switch (msgelem_type) {
		case LWAPP_MSGELEM_DECRYPTION_ERROR_REPORT:
		case LWAPP_MSGELEM_DUPLICATE_IPV4_ADDR:
			// Omit "IEEE 802.11 Statistics" and "Duplicate IPv6 Address".
			return 1;
		}
		break;
	case LWAPP_MSGTYPE_DATA_TRANSFER_REQ: // Section 8.7
		switch (msgelem_type) {
		case LWAPP_MSGELEM_DATA_TRANSFER_MODE:
		case LWAPP_MSGELEM_DATA_TRANSFER_DATA:
			return 1;
		}
		break;
	case LWAPP_MSGTYPE_MOBILE_CONFIG_REQ: // Sections 9.1 and 11.7.1
		switch (msgelem_type) {
		case LWAPP_MSGELEM_DELETE_MOBILE:
		case LWAPP_MSGELEM_ADD_MOBILE:
		case LWAPP_MSGELEM_80211_MOBILE_SESSION_KEY:
		case LWAPP_MSGELEM_80211_STATION_QOS_PROFILE:
		case LWAPP_MSGELEM_80211_UPDATE_MOBILE_QOS:
			return 1;
		}
		break;
	case LWAPP_MSGTYPE_MOBILE_CONFIG_RESP: // Sections 9.2
		// Omit "Result Code".
		break;
	case LWAPP_MSGTYPE_WLAN_CONFIG_REQ: // Section 11.8.1
		switch (msgelem_type) {
		case LWAPP_MSGELEM_80211_ADD_WLAN:
		case LWAPP_MSGELEM_80211_DELETE_WLAN:
		case LWAPP_MSGELEM_80211_UPDATE_WLAN:
			return 1;
		}
		break;
	}
	/*
	 * RFC5412 also defines the following messages with message elements,
	 * but without any assigned message types (Errata ID: 8511):
	 * - Key Update ACK (Section 6.9)
	 * - Key Update Confirm (Section 6.10)
	 * - Key Update Trigger (Section 6.11)
	 * - IEEE 802.11 WTP Event (Section 11.8.3)
	 */
	return 0;
}

static void
lwapp_control_print(netdissect_options *ndo,
                    const u_char *cp, uint16_t len)
{
	/*
	 * cp is the beginning and len is the length of LWAPP payload, which in
	 * this case should be exactly one LWAPP control header followed by 0 or
	 * more message elements.
	 */
	const size_t ctrlhdrlen = sizeof(struct lwapp_control_header);
	ND_ICHECKMSG_ZU("transport payload length", len, <, ctrlhdrlen);
	const struct lwapp_control_header *ctrlhdr =
		(const struct lwapp_control_header *)cp;

	uint8_t msg_type = GET_U_1(ctrlhdr->msg_type);
	ND_PRINT("\n\t  Msg type: %s (%u)",
	         tok2str(lwapp_msg_type_values, "Unknown", msg_type),
	         msg_type);

	ND_PRINT(", Seqnum: %u", GET_U_1(ctrlhdr->seq_num));

	uint16_t msg_elem_len = GET_BE_U_2(ctrlhdr->len);
	ND_PRINT(", Msg len: %u", msg_elem_len);
	ND_ICHECK_ZU(msg_elem_len, !=, len - ctrlhdrlen);

	ND_PRINT(", Session: 0x%08x", GET_BE_U_4(ctrlhdr->session_id));

	/*
	 * Done with the Control header.  Make cp the beginning and len -- the
	 * length of Msg Element TLV space.  Print the message elements, if any.
	 */
	cp += ctrlhdrlen;
	len -= ctrlhdrlen;
	const size_t mehdrlen = sizeof(struct lwapp_msgelem_header);
	u_int elem_num = 0;
	while(len) {
		ND_ICHECKMSG_ZU("remaining length", len, <, mehdrlen);
		const struct lwapp_msgelem_header *mehdr =
			(const struct lwapp_msgelem_header *)cp;

		uint8_t elem_type = GET_U_1(mehdr->type);
		ND_PRINT("\n\t  Msg Elem %u Type: %u (%s)", elem_num, elem_type,
		         tok2str(lwapp_msg_elem_values, "Unknown", elem_type));
		if (! permitted_msg_elem(msg_type, elem_type))
			ND_PRINT(" [unexpected!]");

		uint16_t elem_len = GET_BE_U_2(mehdr->length);
		ND_PRINT(", Length: %u", elem_len);
		if (elem_len < msg_elem_minlen[elem_type])
			ND_PRINT(" [too short!]");
		ND_ICHECK_ZU(elem_len, >, len - mehdrlen);

		cp += mehdrlen;
		len -= mehdrlen;
		// Done with Type and Length, but let's not decode the Value.
		ND_TCHECK_LEN(cp, elem_len);
		cp += elem_len;
		len -= elem_len;
		elem_num++;
	}
	return;
invalid:
	nd_print_invalid(ndo);
}

void
lwapp_print(netdissect_options *ndo,
            const u_char *pptr, const u_int pktlen, const u_char has_ap_ident)
{
	ndo->ndo_protocol = "lwapp";
	nd_print_protocol_caps(ndo);

	const u_char *cp = pptr;
	u_int hdrlen = sizeof(struct lwapp_transport_header);
	/*
	 * The [documented] transport header begins after the [undocumented] AP
	 * identity if the latter is present.  This is not in RFC 5412, but is
	 * in encoding of the test packet capture and of Wireshark LWAPP
	 * decoder.
	 */
	if (has_ap_ident) {
		cp += MAC48_LEN;
		hdrlen += MAC48_LEN;
	}
	ND_ICHECKMSG_U("UDP payload length", pktlen, <, hdrlen);

	const struct lwapp_transport_header *h =
		(const struct lwapp_transport_header *)cp;
	uint8_t ver_rid_cfl = GET_U_1(h->ver_rid_cfl);
	uint8_t version = LWAPP_EXTRACT_VER(ver_rid_cfl);
	ND_ICHECK_U(version, !=, LWAPP_VERSION);
	uint8_t flags = LWAPP_EXTRACT_CFL(ver_rid_cfl);
	ND_PRINT("v%u, %s frame",
	         version,
	         (flags & LWAPP_C_BIT) ? "Control" : "Data");
	if (ndo->ndo_vflag)
		ND_PRINT(", Radio-id %u", LWAPP_EXTRACT_RID(ver_rid_cfl));
	/*
	 * For UDP transport F Bit, L bit, and Frag ID are all assumed to be
	 * zero (Section 3.3.3).
	 */
	ND_PRINT(", Flags [%s]%s",
	         bittok2str(lwapp_header_bits_values, "none", flags),
	         (flags & (LWAPP_L_BIT | LWAPP_F_BIT)) ? " (bogus)" : "");
	if (ndo->ndo_vflag) {
		uint8_t frag_id = GET_U_1(h->frag_id);
		ND_PRINT(", Frag-id %u%s", frag_id, frag_id ? " (MBZ!)" : "");
	}

	uint16_t paylen = GET_BE_U_2(h->length);
	ND_PRINT(", length %u", paylen);
	ND_ICHECKMSG_U("LWAPP payload length", paylen, !=, pktlen - hdrlen);
	if (! ndo->ndo_vflag || ! paylen)
		return;
	if (has_ap_ident)
		ND_PRINT("\n\tAP identity: %s", GET_MAC48_STRING(pptr));
	// The Status/WLANs field has not been fetched.
	ND_TCHECK_SIZE(h);
	cp += sizeof(struct lwapp_transport_header);

	/*
	 * Now cp is the beginning and paylen is the length of LWAPP transport
	 * header payload.  Encoding of the payload depends on the frame type,
	 * which is a function of C Bit of the transport header regardless of
	 * whether the transport is IEEE 802.3 or UDP (RFC 5412 Section 3.2.5).
	 * Ibid., Section 3.3.1 discusses UDP ports for particular frame types,
	 * but the UDP port is a function of the frame type, not the other way
	 * around.
	 */
	if (flags & LWAPP_C_BIT)
		lwapp_control_print(ndo, cp, paylen);
	else
		// FIXME - An IEEE 802.11 frame follows - hexdump for now.
		print_unknown_data(ndo, cp, "\n\t", paylen);

	return;
invalid:
	nd_print_invalid(ndo);
}
