/*
 * This module implements decoding of OpenFlow protocol version 1.3 (wire
 * protocol 0x04). It is based on the implementation conventions explained in
 * print-openflow-1.0.c.
 *
 * [OF13] https://www.opennetworking.org/wp-content/uploads/2014/10/openflow-switch-v1.3.4.pdf
 *
 * Copyright (c) 2020 The TCPDUMP project
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
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/* \summary: OpenFlow protocol version 1.3 printer */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "netdissect-stdinc.h"

#define ND_LONGJMP_FROM_TCHECK
#include "netdissect.h"
#include "extract.h"
#include "openflow.h"

#define OFPT_HELLO                     0U
#define OFPT_ERROR                     1U
#define OFPT_ECHO_REQUEST              2U
#define OFPT_ECHO_REPLY                3U
#define OFPT_EXPERIMENTER              4U
#define OFPT_FEATURES_REQUEST          5U
#define OFPT_FEATURES_REPLY            6U
#define OFPT_GET_CONFIG_REQUEST        7U
#define OFPT_GET_CONFIG_REPLY          8U
#define OFPT_SET_CONFIG                9U
#define OFPT_PACKET_IN                10U
#define OFPT_FLOW_REMOVED             11U
#define OFPT_PORT_STATUS              12U
#define OFPT_PACKET_OUT               13U
#define OFPT_FLOW_MOD                 14U
#define OFPT_GROUP_MOD                15U
#define OFPT_PORT_MOD                 16U
#define OFPT_TABLE_MOD                17U
#define OFPT_MULTIPART_REQUEST        18U
#define OFPT_MULTIPART_REPLY          19U
#define OFPT_BARRIER_REQUEST          20U
#define OFPT_BARRIER_REPLY            21U
#define OFPT_QUEUE_GET_CONFIG_REQUEST 22U
#define OFPT_QUEUE_GET_CONFIG_REPLY   23U
#define OFPT_ROLE_REQUEST             24U
#define OFPT_ROLE_REPLY               25U
#define OFPT_GET_ASYNC_REQUEST        26U
#define OFPT_GET_ASYNC_REPLY          27U
#define OFPT_SET_ASYNC                28U
#define OFPT_METER_MOD                29U
static const struct tok ofpt_str[] = {
	{ OFPT_HELLO,                    "HELLO"                    },
	{ OFPT_ERROR,                    "ERROR"                    },
	{ OFPT_ECHO_REQUEST,             "ECHO_REQUEST"             },
	{ OFPT_ECHO_REPLY,               "ECHO_REPLY"               },
	{ OFPT_EXPERIMENTER,             "EXPERIMENTER"             },
	{ OFPT_FEATURES_REQUEST,         "FEATURES_REQUEST"         },
	{ OFPT_FEATURES_REPLY,           "FEATURES_REPLY"           },
	{ OFPT_GET_CONFIG_REQUEST,       "GET_CONFIG_REQUEST"       },
	{ OFPT_GET_CONFIG_REPLY,         "GET_CONFIG_REPLY"         },
	{ OFPT_SET_CONFIG,               "SET_CONFIG"               },
	{ OFPT_PACKET_IN,                "PACKET_IN"                },
	{ OFPT_FLOW_REMOVED,             "FLOW_REMOVED"             },
	{ OFPT_PORT_STATUS,              "PORT_STATUS"              },
	{ OFPT_PACKET_OUT,               "PACKET_OUT"               },
	{ OFPT_FLOW_MOD,                 "FLOW_MOD"                 },
	{ OFPT_GROUP_MOD,                "GROUP_MOD"                },
	{ OFPT_PORT_MOD,                 "PORT_MOD"                 },
	{ OFPT_TABLE_MOD,                "TABLE_MOD"                },
	{ OFPT_MULTIPART_REQUEST,        "MULTIPART_REQUEST"        },
	{ OFPT_MULTIPART_REPLY,          "MULTIPART_REPLY"          },
	{ OFPT_BARRIER_REQUEST,          "BARRIER_REQUEST"          },
	{ OFPT_BARRIER_REPLY,            "BARRIER_REPLY"            },
	{ OFPT_QUEUE_GET_CONFIG_REQUEST, "QUEUE_GET_CONFIG_REQUEST" },
	{ OFPT_QUEUE_GET_CONFIG_REPLY,   "QUEUE_GET_CONFIG_REPLY"   },
	{ OFPT_ROLE_REQUEST,             "ROLE_REQUEST"             },
	{ OFPT_ROLE_REPLY,               "ROLE_REPLY"               },
	{ OFPT_GET_ASYNC_REQUEST,        "GET_ASYNC_REQUEST"        },
	{ OFPT_GET_ASYNC_REPLY,          "GET_ASYNC_REPLY"          },
	{ OFPT_SET_ASYNC,                "SET_ASYNC"                },
	{ OFPT_METER_MOD,                "METER_MOD"                },
	{ 0, NULL }
};

#define OFPC_FLOW_STATS   (1U <<0)
#define OFPC_TABLE_STATS  (1U <<1)
#define OFPC_PORT_STATS   (1U <<2)
#define OFPC_GROUP_STATS  (1U <<3)
#define OFPC_IP_REASM     (1U <<5)
#define OFPC_QUEUE_STATS  (1U <<6)
#define OFPC_PORT_BLOCKED (1U <<8)
static const struct tok ofp_capabilities_bm[] = {
	{ OFPC_FLOW_STATS,   "FLOW_STATS"   },
	{ OFPC_TABLE_STATS,  "TABLE_STATS"  },
	{ OFPC_PORT_STATS,   "PORT_STATS"   },
	{ OFPC_GROUP_STATS,  "GROUP_STATS"  },
	{ OFPC_IP_REASM,     "IP_REASM"     },
	{ OFPC_QUEUE_STATS,  "QUEUE_STATS"  },
	{ OFPC_PORT_BLOCKED, "PORT_BLOCKED" },
	{ 0, NULL }
};
#define OFPCAP_U (~(OFPC_FLOW_STATS | OFPC_TABLE_STATS | OFPC_PORT_STATS | \
                    OFPC_GROUP_STATS | OFPC_IP_REASM | OFPC_QUEUE_STATS | \
                    OFPC_PORT_BLOCKED))

#define OFPHET_VERSIONBITMAP 1U
static const struct tok ofphet_str[] = {
	{ OFPHET_VERSIONBITMAP, "VERSIONBITMAP" },
	{ 0, NULL }
};

#define OFPP_MAX        0xffffff00U
#define OFPP_IN_PORT    0xfffffff8U
#define OFPP_TABLE      0xfffffff9U
#define OFPP_NORMAL     0xfffffffaU
#define OFPP_FLOOD      0xfffffffbU
#define OFPP_ALL        0xfffffffcU
#define OFPP_CONTROLLER 0xfffffffdU
#define OFPP_LOCAL      0xfffffffeU
#define OFPP_ANY        0xffffffffU
static const struct tok ofpp_str[] = {
	{ OFPP_MAX,        "MAX"        },
	{ OFPP_IN_PORT,    "IN_PORT"    },
	{ OFPP_TABLE,      "TABLE"      },
	{ OFPP_NORMAL,     "NORMAL"     },
	{ OFPP_FLOOD,      "FLOOD"      },
	{ OFPP_ALL,        "ALL"        },
	{ OFPP_CONTROLLER, "CONTROLLER" },
	{ OFPP_LOCAL,      "LOCAL"      },
	{ OFPP_ANY,        "ANY"        },
	{ 0, NULL }
};

#define OF_BIT_VER_1_0 (1U << (OF_VER_1_0 - 1))
#define OF_BIT_VER_1_1 (1U << (OF_VER_1_1 - 1))
#define OF_BIT_VER_1_2 (1U << (OF_VER_1_2 - 1))
#define OF_BIT_VER_1_3 (1U << (OF_VER_1_3 - 1))
#define OF_BIT_VER_1_4 (1U << (OF_VER_1_4 - 1))
#define OF_BIT_VER_1_5 (1U << (OF_VER_1_5 - 1))
static const struct tok ofverbm_str[] = {
	{ OF_BIT_VER_1_0, "1.0" },
	{ OF_BIT_VER_1_1, "1.1" },
	{ OF_BIT_VER_1_2, "1.2" },
	{ OF_BIT_VER_1_3, "1.3" },
	{ OF_BIT_VER_1_4, "1.4" },
	{ OF_BIT_VER_1_5, "1.5" },
	{ 0, NULL }
};
#define OF_BIT_VER_U (~(OF_BIT_VER_1_0 | OF_BIT_VER_1_1 | OF_BIT_VER_1_2 | \
                        OF_BIT_VER_1_3 | OF_BIT_VER_1_4 | OF_BIT_VER_1_5))

#define OFPET_HELLO_FAILED           0U
#define OFPET_BAD_REQUEST            1U
#define OFPET_BAD_ACTION             2U
#define OFPET_BAD_INSTRUCTION        3U
#define OFPET_BAD_MATCH              4U
#define OFPET_FLOW_MOD_FAILED        5U
#define OFPET_GROUP_MOD_FAILED       6U
#define OFPET_PORT_MOD_FAILED        7U
#define OFPET_TABLE_MOD_FAILED       8U
#define OFPET_QUEUE_OP_FAILED        9U
#define OFPET_SWITCH_CONFIG_FAILED  10U
#define OFPET_ROLE_REQUEST_FAILED   11U
#define OFPET_METER_MOD_FAILED      12U
#define OFPET_TABLE_FEATURES_FAILED 13U
#define OFPET_EXPERIMENTER          0xffffU /* a special case */
static const struct tok ofpet_str[] = {
	{ OFPET_HELLO_FAILED,          "HELLO_FAILED"          },
	{ OFPET_BAD_REQUEST,           "BAD_REQUEST"           },
	{ OFPET_BAD_ACTION,            "BAD_ACTION"            },
	{ OFPET_BAD_INSTRUCTION,       "BAD_INSTRUCTION"       },
	{ OFPET_BAD_MATCH,             "BAD_MATCH"             },
	{ OFPET_FLOW_MOD_FAILED,       "FLOW_MOD_FAILED"       },
	{ OFPET_GROUP_MOD_FAILED,      "GROUP_MOD_FAILED"      },
	{ OFPET_PORT_MOD_FAILED,       "PORT_MOD_FAILED"       },
	{ OFPET_TABLE_MOD_FAILED,      "TABLE_MOD_FAILED"      },
	{ OFPET_QUEUE_OP_FAILED,       "QUEUE_OP_FAILED"       },
	{ OFPET_SWITCH_CONFIG_FAILED,  "SWITCH_CONFIG_FAILED"  },
	{ OFPET_ROLE_REQUEST_FAILED,   "ROLE_REQUEST_FAILED"   },
	{ OFPET_METER_MOD_FAILED,      "METER_MOD_FAILED"      },
	{ OFPET_TABLE_FEATURES_FAILED, "TABLE_FEATURES_FAILED" },
	{ OFPET_EXPERIMENTER,          "EXPERIMENTER"          },
	{ 0, NULL }
};
/*
 * As far as of13_error_print() is concerned, OFPET_EXPERIMENTER is too large
 * and defines no codes anyway.
 */
#define OFPET_MAX OFPET_TABLE_FEATURES_FAILED

#define OFPHFC_INCOMPATIBLE 0U
#define OFPHFC_EPERM        1U
static const struct tok ofphfc_str[] = {
	{ OFPHFC_INCOMPATIBLE, "INCOMPATIBLE" },
	{ OFPHFC_EPERM,        "EPERM"        },
	{ 0, NULL }
};

#define OFPBRC_BAD_VERSION                0U
#define OFPBRC_BAD_TYPE                   1U
#define OFPBRC_BAD_MULTIPART              2U
#define OFPBRC_BAD_EXPERIMENTER           3U
#define OFPBRC_BAD_EXP_TYPE               4U
#define OFPBRC_EPERM                      5U
#define OFPBRC_BAD_LEN                    6U
#define OFPBRC_BUFFER_EMPTY               7U
#define OFPBRC_BUFFER_UNKNOWN             8U
#define OFPBRC_BAD_TABLE_ID               9U
#define OFPBRC_IS_SLAVE                  10U
#define OFPBRC_BAD_PORT                  11U
#define OFPBRC_BAD_PACKET                12U
#define OFPBRC_MULTIPART_BUFFER_OVERFLOW 13U
static const struct tok ofpbrc_str[] = {
	{ OFPBRC_BAD_VERSION,               "BAD_VERSION"               },
	{ OFPBRC_BAD_TYPE,                  "BAD_TYPE"                  },
	{ OFPBRC_BAD_MULTIPART,             "BAD_MULTIPART"             },
	{ OFPBRC_BAD_EXPERIMENTER,          "BAD_EXPERIMENTER"          },
	{ OFPBRC_BAD_EXP_TYPE,              "BAD_EXP_TYPE"              },
	{ OFPBRC_EPERM,                     "EPERM"                     },
	{ OFPBRC_BAD_LEN,                   "BAD_LEN"                   },
	{ OFPBRC_BUFFER_EMPTY,              "BUFFER_EMPTY"              },
	{ OFPBRC_BUFFER_UNKNOWN,            "BUFFER_UNKNOWN"            },
	{ OFPBRC_BAD_TABLE_ID,              "BAD_TABLE_ID"              },
	{ OFPBRC_IS_SLAVE,                  "IS_SLAVE"                  },
	{ OFPBRC_BAD_PORT,                  "BAD_PORT"                  },
	{ OFPBRC_BAD_PACKET,                "BAD_PACKET"                },
	{ OFPBRC_MULTIPART_BUFFER_OVERFLOW, "MULTIPART_BUFFER_OVERFLOW" },
	{ 0, NULL }
};

#define OFPBAC_BAD_TYPE            0U
#define OFPBAC_BAD_LEN             1U
#define OFPBAC_BAD_EXPERIMENTER    2U
#define OFPBAC_BAD_EXP_TYPE        3U
#define OFPBAC_BAD_OUT_PORT        4U
#define OFPBAC_BAD_ARGUMENT        5U
#define OFPBAC_EPERM               6U
#define OFPBAC_TOO_MANY            7U
#define OFPBAC_BAD_QUEUE           8U
#define OFPBAC_BAD_OUT_GROUP       9U
#define OFPBAC_MATCH_INCONSISTENT 10U
#define OFPBAC_UNSUPPORTED_ORDER  11U
#define OFPBAC_BAD_TAG            12U
#define OFPBAC_BAD_SET_TYPE       13U
#define OFPBAC_BAD_SET_LEN        14U
#define OFPBAC_BAD_SET_ARGUMENT   15U
static const struct tok ofpbac_str[] = {
	{ OFPBAC_BAD_TYPE,           "BAD_TYPE"           },
	{ OFPBAC_BAD_LEN,            "BAD_LEN"            },
	{ OFPBAC_BAD_EXPERIMENTER,   "BAD_EXPERIMENTER"   },
	{ OFPBAC_BAD_EXP_TYPE,       "BAD_EXP_TYPE"       },
	{ OFPBAC_BAD_OUT_PORT,       "BAD_OUT_PORT"       },
	{ OFPBAC_BAD_ARGUMENT,       "BAD_ARGUMENT"       },
	{ OFPBAC_EPERM,              "EPERM"              },
	{ OFPBAC_TOO_MANY,           "TOO_MANY"           },
	{ OFPBAC_BAD_QUEUE,          "BAD_QUEUE"          },
	{ OFPBAC_BAD_OUT_GROUP,      "BAD_OUT_GROUP"      },
	{ OFPBAC_MATCH_INCONSISTENT, "MATCH_INCONSISTENT" },
	{ OFPBAC_UNSUPPORTED_ORDER,  "UNSUPPORTED_ORDER"  },
	{ OFPBAC_BAD_TAG,            "BAD_TAG"            },
	{ OFPBAC_BAD_SET_TYPE,       "BAD_SET_TYPE"       },
	{ OFPBAC_BAD_SET_LEN,        "BAD_SET_LEN"        },
	{ OFPBAC_BAD_SET_ARGUMENT,   "BAD_SET_ARGUMENT"   },
	{ 0, NULL }
};

#define OFPBIC_UNKNOWN_INST        0U
#define OFPBIC_UNSUP_INST          1U
#define OFPBIC_BAD_TABLE_ID        2U
#define OFPBIC_UNSUP_METADATA      3U
#define OFPBIC_UNSUP_METADATA_MASK 4U
#define OFPBIC_BAD_EXPERIMENTER    5U
#define OFPBIC_BAD_EXP_TYPE        6U
#define OFPBIC_BAD_LEN             7U
#define OFPBIC_EPERM               8U
static const struct tok ofpbic_str[] = {
	{ OFPBIC_UNKNOWN_INST,        "UNKNOWN_INST"        },
	{ OFPBIC_UNSUP_INST,          "UNSUP_INST"          },
	{ OFPBIC_BAD_TABLE_ID,        "BAD_TABLE_ID"        },
	{ OFPBIC_UNSUP_METADATA,      "UNSUP_METADATA"      },
	{ OFPBIC_UNSUP_METADATA_MASK, "UNSUP_METADATA_MASK" },
	{ OFPBIC_BAD_EXPERIMENTER,    "BAD_EXPERIMENTER"    },
	{ OFPBIC_BAD_EXP_TYPE,        "BAD_EXP_TYPE"        },
	{ OFPBIC_BAD_LEN,             "BAD_LEN"             },
	{ OFPBIC_EPERM,               "EPERM"               },
	{ 0, NULL }
};

#define OFPBMC_BAD_TYPE          0U
#define OFPBMC_BAD_LEN           1U
#define OFPBMC_BAD_TAG           2U
#define OFPBMC_BAD_DL_ADDR_MASK  3U
#define OFPBMC_BAD_NW_ADDR_MASK  4U
#define OFPBMC_BAD_WILDCARDS     5U
#define OFPBMC_BAD_FIELD         6U
#define OFPBMC_BAD_VALUE         7U
#define OFPBMC_BAD_MASK          8U
#define OFPBMC_BAD_PREREQ        9U
#define OFPBMC_DUP_FIELD        10U
#define OFPBMC_EPERM            11U
static const struct tok ofpbmc_str[] = {
	{ OFPBMC_BAD_TYPE,         "BAD_TYPE"         },
	{ OFPBMC_BAD_LEN,          "BAD_LEN"          },
	{ OFPBMC_BAD_TAG,          "BAD_TAG"          },
	{ OFPBMC_BAD_DL_ADDR_MASK, "BAD_DL_ADDR_MASK" },
	{ OFPBMC_BAD_NW_ADDR_MASK, "BAD_NW_ADDR_MASK" },
	{ OFPBMC_BAD_WILDCARDS,    "BAD_WILDCARDS"    },
	{ OFPBMC_BAD_FIELD,        "BAD_FIELD"        },
	{ OFPBMC_BAD_VALUE,        "BAD_VALUE"        },
	{ OFPBMC_BAD_MASK,         "BAD_MASK"         },
	{ OFPBMC_BAD_PREREQ,       "BAD_PREREQ"       },
	{ OFPBMC_DUP_FIELD,        "DUP_FIELD"        },
	{ OFPBMC_EPERM,            "EPERM"            },
	{ 0, NULL }
};

#define OFPFMFC_UNKNOWN      0U
#define OFPFMFC_TABLE_FULL   1U
#define OFPFMFC_BAD_TABLE_ID 2U
#define OFPFMFC_OVERLAP      3U
#define OFPFMFC_EPERM        4U
#define OFPFMFC_BAD_TIMEOUT  5U
#define OFPFMFC_BAD_COMMAND  6U
#define OFPFMFC_BAD_FLAGS    7U
static const struct tok ofpfmfc_str[] = {
	{ OFPFMFC_UNKNOWN,      "UNKNOWN"      },
	{ OFPFMFC_TABLE_FULL,   "TABLE_FULL"   },
	{ OFPFMFC_BAD_TABLE_ID, "BAD_TABLE_ID" },
	{ OFPFMFC_OVERLAP,      "OVERLAP"      },
	{ OFPFMFC_EPERM,        "EPERM"        },
	{ OFPFMFC_BAD_TIMEOUT,  "BAD_TIMEOUT"  },
	{ OFPFMFC_BAD_COMMAND,  "BAD_COMMAND"  },
	{ OFPFMFC_BAD_FLAGS,    "BAD_FLAGS"    },
	{ 0, NULL }
};

#define OFPGMFC_GROUP_EXISTS          0U
#define OFPGMFC_INVALID_GROUP         1U
#define OFPGMFC_WEIGHT_UNSUPPORTED    2U
#define OFPGMFC_OUT_OF_GROUPS         3U
#define OFPGMFC_OUT_OF_BUCKETS        4U
#define OFPGMFC_CHAINING_UNSUPPORTED  5U
#define OFPGMFC_WATCH_UNSUPPORTED     6U
#define OFPGMFC_LOOP                  7U
#define OFPGMFC_UNKNOWN_GROUP         8U
#define OFPGMFC_CHAINED_GROUP         9U
#define OFPGMFC_BAD_TYPE             10U
#define OFPGMFC_BAD_COMMAND          11U
#define OFPGMFC_BAD_BUCKET           12U
#define OFPGMFC_BAD_MATCH            13U
#define OFPGMFC_EPERM                14U
static const struct tok ofpgmfc_str[] = {
	{ OFPGMFC_GROUP_EXISTS,         "GROUP_EXISTS"         },
	{ OFPGMFC_INVALID_GROUP,        "INVALID_GROUP"        },
	{ OFPGMFC_WEIGHT_UNSUPPORTED,   "WEIGHT_UNSUPPORTED"   },
	{ OFPGMFC_OUT_OF_GROUPS,        "OUT_OF_GROUPS"        },
	{ OFPGMFC_OUT_OF_BUCKETS,       "OUT_OF_BUCKETS"       },
	{ OFPGMFC_CHAINING_UNSUPPORTED, "CHAINING_UNSUPPORTED" },
	{ OFPGMFC_WATCH_UNSUPPORTED,    "WATCH_UNSUPPORTED"    },
	{ OFPGMFC_LOOP,                 "LOOP"                 },
	{ OFPGMFC_UNKNOWN_GROUP,        "UNKNOWN_GROUP"        },
	{ OFPGMFC_CHAINED_GROUP,        "CHAINED_GROUP"        },
	{ OFPGMFC_BAD_TYPE,             "BAD_TYPE"             },
	{ OFPGMFC_BAD_COMMAND,          "BAD_COMMAND"          },
	{ OFPGMFC_BAD_BUCKET,           "BAD_BUCKET"           },
	{ OFPGMFC_BAD_MATCH,            "BAD_MATCH"            },
	{ OFPGMFC_EPERM,                "EPERM"                },
	{ 0, NULL }
};

#define OFPPMFC_BAD_PORT      0U
#define OFPPMFC_BAD_HW_ADDR   1U
#define OFPPMFC_BAD_CONFIG    2U
#define OFPPMFC_BAD_ADVERTISE 3U
#define OFPPMFC_EPERM         4U
static const struct tok ofppmfc_str[] = {
	{ OFPPMFC_BAD_PORT,      "BAD_PORT"      },
	{ OFPPMFC_BAD_HW_ADDR,   "BAD_HW_ADDR"   },
	{ OFPPMFC_BAD_CONFIG,    "BAD_CONFIG"    },
	{ OFPPMFC_BAD_ADVERTISE, "BAD_ADVERTISE" },
	{ OFPPMFC_EPERM,         "EPERM"         },
	{ 0, NULL }
};

#define OFPTMFC_BAD_TABLE  0U
#define OFPTMFC_BAD_CONFIG 1U
#define OFPTMFC_EPERM      2U
static const struct tok ofptmfc_str[] = {
	{ OFPTMFC_BAD_TABLE,  "BAD_TABLE"  },
	{ OFPTMFC_BAD_CONFIG, "BAD_CONFIG" },
	{ OFPTMFC_EPERM,      "EPERM"      },
	{ 0, NULL }
};

#define OFPQOFC_BAD_PORT  0U
#define OFPQOFC_BAD_QUEUE 1U
#define OFPQOFC_EPERM     2U
static const struct tok ofpqofc_str[] = {
	{ OFPQOFC_BAD_PORT,  "BAD_PORT"  },
	{ OFPQOFC_BAD_QUEUE, "BAD_QUEUE" },
	{ OFPQOFC_EPERM,     "EPERM"     },
	{ 0, NULL }
};

#define OFPSCFC_BAD_FLAGS 0U
#define OFPSCFC_BAD_LEN   1U
#define OFPSCFC_EPERM     2U
static const struct tok ofpscfc_str[] = {
	{ OFPSCFC_BAD_FLAGS, "BAD_FLAGS" },
	{ OFPSCFC_BAD_LEN,   "BAD_LEN"   },
	{ OFPSCFC_EPERM,     "EPERM"     },
	{ 0, NULL }
};

#define OFPRRFC_STALE    0U
#define OFPRRFC_UNSUP    1U
#define OFPRRFC_BAD_ROLE 2U
static const struct tok ofprrfc_str[] = {
	{ OFPRRFC_STALE,    "STALE"    },
	{ OFPRRFC_UNSUP,    "UNSUP"    },
	{ OFPRRFC_BAD_ROLE, "BAD_ROLE" },
	{ 0, NULL }
};

#define OFPMMFC_UNKNOWN         0U
#define OFPMMFC_METER_EXISTS    1U
#define OFPMMFC_INVALID_METER   2U
#define OFPMMFC_UNKNOWN_METER   3U
#define OFPMMFC_BAD_COMMAND     4U
#define OFPMMFC_BAD_FLAGS       5U
#define OFPMMFC_BAD_RATE        6U
#define OFPMMFC_BAD_BURST       7U
#define OFPMMFC_BAD_BAND        8U
#define OFPMMFC_BAD_BAND_VALUE  9U
#define OFPMMFC_OUT_OF_METERS  10U
#define OFPMMFC_OUT_OF_BANDS   11U
static const struct tok ofpmmfc_str[] = {
	{ OFPMMFC_UNKNOWN,        "UNKNOWN"        },
	{ OFPMMFC_METER_EXISTS,   "METER_EXISTS"   },
	{ OFPMMFC_INVALID_METER,  "INVALID_METER"  },
	{ OFPMMFC_UNKNOWN_METER,  "UNKNOWN_METER"  },
	{ OFPMMFC_BAD_COMMAND,    "BAD_COMMAND"    },
	{ OFPMMFC_BAD_FLAGS,      "BAD_FLAGS"      },
	{ OFPMMFC_BAD_RATE,       "BAD_RATE"       },
	{ OFPMMFC_BAD_BURST,      "BAD_BURST"      },
	{ OFPMMFC_BAD_BAND,       "BAD_BAND"       },
	{ OFPMMFC_BAD_BAND_VALUE, "BAD_BAND_VALUE" },
	{ OFPMMFC_OUT_OF_METERS,  "OUT_OF_METERS"  },
	{ OFPMMFC_OUT_OF_BANDS,   "OUT_OF_BANDS"   },
	{ 0, NULL }
};

#define OFPTFFC_BAD_TABLE    0U
#define OFPTFFC_BAD_METADATA 1U
#define OFPTFFC_BAD_TYPE     2U
#define OFPTFFC_BAD_LEN      3U
#define OFPTFFC_BAD_ARGUMENT 4U
#define OFPTFFC_EPERM        5U
static const struct tok ofptffc_str[] = {
	{ OFPTFFC_BAD_TABLE,    "BAD_TABLE"    },
	{ OFPTFFC_BAD_METADATA, "BAD_METADATA" },
	{ OFPTFFC_BAD_TYPE,     "BAD_TYPE"     },
	{ OFPTFFC_BAD_LEN,      "BAD_LEN"      },
	{ OFPTFFC_BAD_ARGUMENT, "BAD_ARGUMENT" },
	{ OFPTFFC_EPERM,        "EPERM"        },
	{ 0, NULL }
};

/* lengths (fixed or minimal) of particular protocol structures */
#define OF_HELLO_ELEM_MINSIZE                 4U
#define OF_ERROR_MSG_MINLEN                   12U
#define OF_FEATURES_REPLY_FIXLEN              32U
#define OF_QUEUE_GET_CONFIG_REQUEST_FIXLEN    16U

/* [OF13] Section A.1 */
const char *
of13_msgtype_str(const uint8_t type)
{
	return tok2str(ofpt_str, "invalid (0x%02x)", type);
}

/* [OF13] Section 7.3.1 */
static void
of13_features_reply_print(netdissect_options *ndo,
                          const u_char *cp, u_int len)
{
	/* datapath_id */
	ND_PRINT("\n\t dpid 0x%016" PRIx64, GET_BE_U_8(cp));
	OF_FWD(8);
	/* n_buffers */
	ND_PRINT(", n_buffers %u", GET_BE_U_4(cp));
	OF_FWD(4);
	/* n_tables */
	ND_PRINT(", n_tables %u", GET_U_1(cp));
	OF_FWD(1);
	/* auxiliary_id */
	ND_PRINT(", auxiliary_id %u", GET_U_1(cp));
	OF_FWD(1);
	/* pad */
	OF_FWD(2);
	/* capabilities */
	ND_PRINT("\n\t capabilities 0x%08x", GET_BE_U_4(cp));
	of_bitmap_print(ndo, ofp_capabilities_bm, GET_BE_U_4(cp), OFPCAP_U);
	OF_FWD(4);
	/* reserved */
	ND_TCHECK_4(cp);
}

/* [OF13] Section 7.5.1 */
static void
of13_hello_elements_print(netdissect_options *ndo,
                          const u_char *cp, u_int len)
{
	while (len) {
		uint16_t type, bmlen;

		if (len < OF_HELLO_ELEM_MINSIZE)
			goto invalid;
		/* type */
		type = GET_BE_U_2(cp);
		OF_FWD(2);
		ND_PRINT("\n\t type %s",
		         tok2str(ofphet_str, "unknown (0x%04x)", type));
		/* length */
		bmlen = GET_BE_U_2(cp);
		OF_FWD(2);
		ND_PRINT(", length %u", bmlen);
		/* cp is OF_HELLO_ELEM_MINSIZE bytes in */
		if (bmlen < OF_HELLO_ELEM_MINSIZE ||
		    bmlen > OF_HELLO_ELEM_MINSIZE + len)
			goto invalid;
		switch (type) {
		case OFPHET_VERSIONBITMAP:
			/*
			 * The specification obviously overprovisions the space
			 * for version bitmaps in this element ("ofp versions
			 * 32 to 63 are encoded in the second bitmap and so
			 * on"). Keep this code simple for now and recognize
			 * only a single bitmap with no padding.
			 */
			if (bmlen == OF_HELLO_ELEM_MINSIZE + 4) {
				uint32_t bitmap = GET_BE_U_4(cp);
				ND_PRINT(", bitmap 0x%08x", bitmap);
				of_bitmap_print(ndo, ofverbm_str, bitmap,
				                OF_BIT_VER_U);
			} else {
				ND_PRINT(" (bogus)");
				ND_TCHECK_LEN(cp, bmlen - OF_HELLO_ELEM_MINSIZE);
			}
			break;
		default:
			ND_TCHECK_LEN(cp, bmlen - OF_HELLO_ELEM_MINSIZE);
		}
		OF_FWD(bmlen - OF_HELLO_ELEM_MINSIZE);
	}
	return;

invalid:
	nd_print_invalid(ndo);
	ND_TCHECK_LEN(cp, len);
}

/* [OF13] Section A.4.4 */
static void
of13_error_print(netdissect_options *ndo,
                 const u_char *cp, u_int len)
{
	uint16_t type, code;
	const struct tok *code_str[OFPET_MAX + 1] = {
		/* [OFPET_HELLO_FAILED         ] = */ ofphfc_str,
		/* [OFPET_BAD_REQUEST          ] = */ ofpbrc_str,
		/* [OFPET_BAD_ACTION           ] = */ ofpbac_str,
		/* [OFPET_BAD_INSTRUCTION      ] = */ ofpbic_str,
		/* [OFPET_BAD_MATCH            ] = */ ofpbmc_str,
		/* [OFPET_FLOW_MOD_FAILED      ] = */ ofpfmfc_str,
		/* [OFPET_GROUP_MOD_FAILED     ] = */ ofpgmfc_str,
		/* [OFPET_PORT_MOD_FAILED      ] = */ ofppmfc_str,
		/* [OFPET_TABLE_MOD_FAILED     ] = */ ofptmfc_str,
		/* [OFPET_QUEUE_OP_FAILED      ] = */ ofpqofc_str,
		/* [OFPET_SWITCH_CONFIG_FAILED ] = */ ofpscfc_str,
		/* [OFPET_ROLE_REQUEST_FAILED  ] = */ ofprrfc_str,
		/* [OFPET_METER_MOD_FAILED     ] = */ ofpmmfc_str,
		/* [OFPET_TABLE_FEATURES_FAILED] = */ ofptffc_str,
	};

	/* type */
	type = GET_BE_U_2(cp);
	OF_FWD(2);
	ND_PRINT("\n\t type %s", tok2str(ofpet_str, "invalid (0x%04x)", type));
	/* code */
	code = GET_BE_U_2(cp);
	OF_FWD(2);
	if (type <= OFPET_MAX && code_str[type] != NULL)
		ND_PRINT(", code %s",
		         tok2str(code_str[type], "invalid (0x%04x)", code));
	else
		ND_PRINT(", code invalid (0x%04x)", code);
	/* data */
	of_data_print(ndo, cp, len);
}

void
of13_message_print(netdissect_options *ndo,
                   const u_char *cp, uint16_t len, const uint8_t type)
{
	/* See the comment at the beginning of of10_message_print(). */
	switch (type) {
	/* OpenFlow header only. */
	case OFPT_FEATURES_REQUEST: /* [OF13] Section A.3.1 */
	case OFPT_GET_CONFIG_REQUEST: /* [OF13] Section A.3.2 */
	case OFPT_BARRIER_REQUEST: /* [OF13] Section A.3.8 */
	case OFPT_BARRIER_REPLY: /* ibid */
		if (len)
			goto invalid;
		return;

	/* OpenFlow header and fixed-size message body. */
	case OFPT_FEATURES_REPLY:
		if (len != OF_FEATURES_REPLY_FIXLEN - OF_HEADER_FIXLEN)
			goto invalid;
		if (ndo->ndo_vflag < 1)
			break;
		of13_features_reply_print(ndo, cp, len);
		return;
	case OFPT_QUEUE_GET_CONFIG_REQUEST: /* [OF13] Section A.3.6 */
		if (len != OF_QUEUE_GET_CONFIG_REQUEST_FIXLEN - OF_HEADER_FIXLEN)
			goto invalid;
		if (ndo->ndo_vflag < 1)
			break;
		/* port */
		ND_PRINT("\n\t port %s",
		         tok2str(ofpp_str, "%u", GET_BE_U_4(cp)));
		OF_FWD(4);
		/* pad */
		/* Always the last field, check bounds. */
		ND_TCHECK_4(cp);
		return;

	/* OpenFlow header and variable-size data. */
	case OFPT_ECHO_REQUEST: /* [OF13] Section A.5.2 */
	case OFPT_ECHO_REPLY: /* [OF13] Section A.5.3 */
		if (ndo->ndo_vflag < 1)
			break;
		of_data_print(ndo, cp, len);
		return;

	/* OpenFlow header and n * variable-size data units. */
	case OFPT_HELLO: /* [OF13] Section A.5.1 */
		if (ndo->ndo_vflag < 1)
			break;
		of13_hello_elements_print(ndo, cp, len);
		return;

	/* OpenFlow header, fixed-size message body and variable-size data. */
	case OFPT_ERROR:
		if (len < OF_ERROR_MSG_MINLEN - OF_HEADER_FIXLEN)
			goto invalid;
		if (ndo->ndo_vflag < 1)
			break;
		of13_error_print(ndo, cp, len);
		return;
	}
	/*
	 * Not a recognised type or did not print the details, fall back to
	 * a bounds check.
	 */
	ND_TCHECK_LEN(cp, len);
	return;

invalid: /* skip the message body */
	nd_print_invalid(ndo);
	ND_TCHECK_LEN(cp, len);
}
