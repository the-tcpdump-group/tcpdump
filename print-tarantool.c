/*
 * Copyright (c) 2023 The TCPDUMP project
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
 *
 * Initial contribution by Pavel Balaev (balaev@tarantool.org).
 */

/* \summary: tarantool binary protocol printer */

#include <stdint.h>
#include <limits.h>
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef HAVE_MSGPUCK

#include <msgpuck.h>
#define ND_LONGJMP_FROM_TCHECK
#include "netdissect.h"
#include "netdissect-alloc.h"
#include "extract.h"

/*
 * For information regarding tarantool binary protocol, see:
 * https://www.tarantool.io/en/doc/latest/dev_guide/internals/box_protocol/
 */

/* IPROTO_FLAGS bitfield constants. */
enum {
    IPROTO_FLAG_COMMIT = 0x01,
    IPROTO_FLAG_WAIT_SYNC = 0x02,
    IPROTO_FLAG_WAIT_ACK = 0x04,
};

/* IPROTO command codes. */
enum request_type {
    IPROTO_OK = 0,
    IPROTO_SELECT = 1,
    IPROTO_INSERT = 2,
    IPROTO_REPLACE = 3,
    IPROTO_UPDATE = 4,
    IPROTO_DELETE = 5,
    IPROTO_CALL_16 = 6,
    IPROTO_AUTH = 7,
    IPROTO_EVAL = 8,
    IPROTO_UPSERT = 9,
    IPROTO_CALL = 10,
    IPROTO_EXECUTE = 11,
    IPROTO_NOP = 12,
    IPROTO_PREPARE = 13,
    IPROTO_BEGIN = 14,
    IPROTO_COMMIT = 15,
    IPROTO_ROLLBACK = 16,
    IPROTO_TYPE_STAT_MAX,
    IPROTO_RAFT = 30,
    IPROTO_RAFT_PROMOTE = 31,
    IPROTO_RAFT_DEMOTE = 32,
    IPROTO_RAFT_CONFIRM = 40,
    IPROTO_RAFT_ROLLBACK = 41,
    IPROTO_PING = 64,
    IPROTO_JOIN = 65,
    IPROTO_SUBSCRIBE = 66,
    IPROTO_VOTE_DEPRECATED = 67,
    IPROTO_VOTE = 68,
    IPROTO_FETCH_SNAPSHOT = 69,
    IPROTO_REGISTER = 70,
    IPROTO_JOIN_META = 71,
    IPROTO_JOIN_SNAPSHOT = 72,
    IPROTO_ID = 73,
    IPROTO_WATCH = 74,
    IPROTO_UNWATCH = 75,
    IPROTO_EVENT = 76,
    IPROTO_TYPE_ERROR = 1 << 15
};

enum iproto_key {
    IPROTO_REQUEST_TYPE = 0x00,
    IPROTO_SYNC = 0x01,
    IPROTO_REPLICA_ID = 0x02,
    IPROTO_LSN = 0x03,
    IPROTO_TIMESTAMP = 0x04,
    IPROTO_SCHEMA_VERSION = 0x05,
    IPROTO_SERVER_VERSION = 0x06,
    IPROTO_GROUP_ID = 0x07,
    IPROTO_TSN = 0x08,
    IPROTO_FLAGS = 0x09,
    IPROTO_STREAM_ID = 0x0a,
    IPROTO_SPACE_ID = 0x10,
    IPROTO_INDEX_ID = 0x11,
    IPROTO_LIMIT = 0x12,
    IPROTO_OFFSET = 0x13,
    IPROTO_ITERATOR = 0x14,
    IPROTO_INDEX_BASE = 0x15,
    IPROTO_KEY = 0x20,
    IPROTO_TUPLE = 0x21,
    IPROTO_FUNCTION_NAME = 0x22,
    IPROTO_USER_NAME = 0x23,
    IPROTO_INSTANCE_UUID = 0x24,
    IPROTO_CLUSTER_UUID = 0x25,
    IPROTO_VCLOCK = 0x26,
    IPROTO_EXPR = 0x27,
    IPROTO_OPS = 0x28,
    IPROTO_BALLOT = 0x29,
    IPROTO_TUPLE_META = 0x2a,
    IPROTO_OPTIONS = 0x2b,
    IPROTO_DATA = 0x30,
    IPROTO_ERROR_24 = 0x31,
    IPROTO_METADATA = 0x32,
    IPROTO_BIND_METADATA = 0x33,
    IPROTO_BIND_COUNT = 0x34,
    IPROTO_SQL_TEXT = 0x40,
    IPROTO_SQL_BIND = 0x41,
    IPROTO_SQL_INFO = 0x42,
    IPROTO_STMT_ID = 0x43,
    IPROTO_REPLICA_ANON = 0x50,
    IPROTO_ID_FILTER = 0x51,
    IPROTO_ERROR = 0x52,
    IPROTO_TERM = 0x53,
    IPROTO_VERSION = 0x54,
    IPROTO_FEATURES = 0x55,
    IPROTO_TIMEOUT = 0x56,
    IPROTO_EVENT_KEY = 0x57,
    IPROTO_EVENT_DATA = 0x58,
    IPROTO_KEY_MAX
};

enum iproto_metadata_key {
    IPROTO_FIELD_NAME = 0,
    IPROTO_FIELD_TYPE = 1,
    IPROTO_FIELD_COLL = 2,
    IPROTO_FIELD_IS_NULLABLE = 3,
    IPROTO_FIELD_IS_AUTOINCREMENT = 4,
    IPROTO_FIELD_SPAN = 5,
};

enum iproto_ballot_key {
    IPROTO_BALLOT_IS_RO_CFG = 0x01,
    IPROTO_BALLOT_VCLOCK = 0x02,
    IPROTO_BALLOT_GC_VCLOCK = 0x03,
    IPROTO_BALLOT_IS_RO = 0x04,
    IPROTO_BALLOT_IS_ANON = 0x05,
    IPROTO_BALLOT_IS_BOOTED = 0x06,
    IPROTO_BALLOT_CAN_LEAD = 0x07,
};

enum iproto_raft_keys {
    IPROTO_RAFT_TERM = 0,
    IPROTO_RAFT_VOTE = 1,
    IPROTO_RAFT_STATE = 2,
    IPROTO_RAFT_VCLOCK = 3,
};

enum mp_extension_type {
    MP_UNKNOWN_EXTENSION = 0,
    MP_DECIMAL = 1,
    MP_UUID = 2,
    MP_ERROR = 3,
    MP_DATETIME = 4,
};

/* MP_ERROR keys. */
enum {
    MP_ERROR_STACK = 0x00
};

static const char *extension_type[] = {
    "UNKNOWN_EXTENSION", "DECIMAL", "UUID", "ERROR", "DATETIME"
};

static const char *iterator_type[] = {
    "EQ", "REQ", "ALL", "LT", "LE", "GE", "GT",
    "BITS_ALL_SET", "BITS_ANY_SET", "BITS_ALL_NOT_SET",
    "OVERLAPS", "NEIGHBOR"
};

static const char *error_codes[] = {
    "ER_UNKNOWN",
    "ER_ILLEGAL_PARAMS",
    "ER_MEMORY_ISSUE",
    "ER_TUPLE_FOUND",
    "ER_TUPLE_NOT_FOUND",
    "ER_UNSUPPORTED",
    "ER_NONMASTER",
    "ER_READONLY",
    "ER_INJECTION",
    "ER_CREATE_SPACE",
    "ER_SPACE_EXISTS",
    "ER_DROP_SPACE",
    "ER_ALTER_SPACE",
    "ER_INDEX_TYPE",
    "ER_MODIFY_INDEX",
    "ER_LAST_DROP",
    "ER_TUPLE_FORMAT_LIMIT",
    "ER_DROP_PRIMARY_KEY",
    "ER_KEY_PART_TYPE",
    "ER_EXACT_MATCH",
    "ER_INVALID_MSGPACK",
    "ER_PROC_RET",
    "ER_TUPLE_NOT_ARRAY",
    "ER_FIELD_TYPE",
    "ER_INDEX_PART_TYPE_MISMATCH",
    "ER_UPDATE_SPLICE",
    "ER_UPDATE_ARG_TYPE",
    "ER_FORMAT_MISMATCH_INDEX_PART",
    "ER_UNKNOWN_UPDATE_OP",
    "ER_UPDATE_FIELD",
    "ER_FUNCTION_TX_ACTIVE",
    "ER_KEY_PART_COUNT",
    "ER_PROC_LUA",
    "ER_NO_SUCH_PROC",
    "ER_NO_SUCH_TRIGGER",
    "ER_NO_SUCH_INDEX_ID",
    "ER_NO_SUCH_SPACE",
    "ER_NO_SUCH_FIELD_NO",
    "ER_EXACT_FIELD_COUNT",
    "ER_FIELD_MISSING",
    "ER_WAL_IO",
    "ER_MORE_THAN_ONE_TUPLE",
    "ER_ACCESS_DENIED",
    "ER_CREATE_USER",
    "ER_DROP_USER",
    "ER_NO_SUCH_USER",
    "ER_USER_EXISTS",
    "ER_PASSWORD_MISMATCH",
    "ER_UNKNOWN_REQUEST_TYPE",
    "ER_UNKNOWN_SCHEMA_OBJECT",
    "ER_CREATE_FUNCTION",
    "ER_NO_SUCH_FUNCTION",
    "ER_FUNCTION_EXISTS",
    "ER_BEFORE_REPLACE_RET",
    "ER_MULTISTATEMENT_TRANSACTION",
    "ER_TRIGGER_EXISTS",
    "ER_USER_MAX",
    "ER_NO_SUCH_ENGINE",
    "ER_RELOAD_CFG",
    "ER_CFG",
    "ER_SAVEPOINT_EMPTY_TX",
    "ER_NO_SUCH_SAVEPOINT",
    "ER_UNKNOWN_REPLICA",
    "ER_REPLICASET_UUID_MISMATCH",
    "ER_INVALID_UUID",
    "ER_REPLICASET_UUID_IS_RO",
    "ER_INSTANCE_UUID_MISMATCH",
    "ER_REPLICA_ID_IS_RESERVED",
    "ER_INVALID_ORDER",
    "ER_MISSING_REQUEST_FIELD",
    "ER_IDENTIFIER",
    "ER_DROP_FUNCTION",
    "ER_ITERATOR_TYPE",
    "ER_REPLICA_MAX",
    "ER_INVALID_XLOG",
    "ER_INVALID_XLOG_NAME",
    "ER_INVALID_XLOG_ORDER",
    "ER_NO_CONNECTION",
    "ER_TIMEOUT",
    "ER_ACTIVE_TRANSACTION",
    "ER_CURSOR_NO_TRANSACTION",
    "ER_CROSS_ENGINE_TRANSACTION",
    "ER_NO_SUCH_ROLE",
    "ER_ROLE_EXISTS",
    "ER_CREATE_ROLE",
    "ER_INDEX_EXISTS",
    "ER_SESSION_CLOSED",
    "ER_ROLE_LOOP",
    "ER_GRANT",
    "ER_PRIV_GRANTED",
    "ER_ROLE_GRANTED",
    "ER_PRIV_NOT_GRANTED",
    "ER_ROLE_NOT_GRANTED",
    "ER_MISSING_SNAPSHOT",
    "ER_CANT_UPDATE_PRIMARY_KEY",
    "ER_UPDATE_INTEGER_OVERFLOW",
    "ER_GUEST_USER_PASSWORD",
    "ER_TRANSACTION_CONFLICT",
    "ER_UNSUPPORTED_PRIV",
    "ER_LOAD_FUNCTION",
    "ER_FUNCTION_LANGUAGE",
    "ER_RTREE_RECT",
    "ER_PROC_C",
    "ER_UNKNOWN_RTREE_INDEX_DISTANCE_TYPE",
    "ER_PROTOCOL",
    "ER_UPSERT_UNIQUE_SECONDARY_KEY",
    "ER_WRONG_INDEX_RECORD",
    "ER_WRONG_INDEX_PARTS",
    "ER_WRONG_INDEX_OPTIONS",
    "ER_WRONG_SCHEMA_VERSION",
    "ER_MEMTX_MAX_TUPLE_SIZE",
    "ER_WRONG_SPACE_OPTIONS",
    "ER_UNSUPPORTED_INDEX_FEATURE",
    "ER_VIEW_IS_RO",
    "ER_NO_TRANSACTION",
    "ER_SYSTEM",
    "ER_LOADING",
    "ER_CONNECTION_TO_SELF",
    "ER_KEY_PART_IS_TOO_LONG",
    "ER_COMPRESSION",
    "ER_CHECKPOINT_IN_PROGRESS",
    "ER_SUB_STMT_MAX",
    "ER_COMMIT_IN_SUB_STMT",
    "ER_ROLLBACK_IN_SUB_STMT",
    "ER_DECOMPRESSION",
    "ER_INVALID_XLOG_TYPE",
    "ER_ALREADY_RUNNING",
    "ER_INDEX_FIELD_COUNT_LIMIT",
    "ER_LOCAL_INSTANCE_ID_IS_READ_ONLY",
    "ER_BACKUP_IN_PROGRESS",
    "ER_READ_VIEW_ABORTED",
    "ER_INVALID_INDEX_FILE",
    "ER_INVALID_RUN_FILE",
    "ER_INVALID_VYLOG_FILE",
    "ER_CASCADE_ROLLBACK",
    "ER_VY_QUOTA_TIMEOUT",
    "ER_PARTIAL_KEY",
    "ER_TRUNCATE_SYSTEM_SPACE",
    "ER_LOAD_MODULE",
    "ER_VINYL_MAX_TUPLE_SIZE",
    "ER_WRONG_DD_VERSION",
    "ER_WRONG_SPACE_FORMAT",
    "ER_CREATE_SEQUENCE",
    "ER_ALTER_SEQUENCE",
    "ER_DROP_SEQUENCE",
    "ER_NO_SUCH_SEQUENCE",
    "ER_SEQUENCE_EXISTS",
    "ER_SEQUENCE_OVERFLOW",
    "ER_NO_SUCH_INDEX_NAME",
    "ER_SPACE_FIELD_IS_DUPLICATE",
    "ER_CANT_CREATE_COLLATION",
    "ER_WRONG_COLLATION_OPTIONS",
    "ER_NULLABLE_PRIMARY",
    "ER_NO_SUCH_FIELD_NAME_IN_SPACE",
    "ER_TRANSACTION_YIELD",
    "ER_NO_SUCH_GROUP",
    "ER_SQL_BIND_VALUE",
    "ER_SQL_BIND_TYPE",
    "ER_SQL_BIND_PARAMETER_MAX",
    "ER_SQL_EXECUTE",
    "ER_UPDATE_DECIMAL_OVERFLOW",
    "ER_SQL_BIND_NOT_FOUND",
    "ER_ACTION_MISMATCH",
    "ER_VIEW_MISSING_SQL",
    "ER_FOREIGN_KEY_CONSTRAINT",
    "ER_NO_SUCH_MODULE",
    "ER_NO_SUCH_COLLATION",
    "ER_CREATE_FK_CONSTRAINT",
    "ER_DROP_FK_CONSTRAINT",
    "ER_NO_SUCH_CONSTRAINT",
    "ER_CONSTRAINT_EXISTS",
    "ER_SQL_TYPE_MISMATCH",
    "ER_ROWID_OVERFLOW",
    "ER_DROP_COLLATION",
    "ER_ILLEGAL_COLLATION_MIX",
    "ER_SQL_NO_SUCH_PRAGMA",
    "ER_SQL_CANT_RESOLVE_FIELD",
    "ER_INDEX_EXISTS_IN_SPACE",
    "ER_INCONSISTENT_TYPES",
    "ER_SQL_SYNTAX_WITH_POS",
    "ER_SQL_STACK_OVERFLOW",
    "ER_SQL_SELECT_WILDCARD",
    "ER_SQL_STATEMENT_EMPTY",
    "ER_SQL_KEYWORD_IS_RESERVED",
    "ER_SQL_SYNTAX_NEAR_TOKEN",
    "ER_SQL_UNKNOWN_TOKEN",
    "ER_SQL_PARSER_GENERIC",
    "ER_SQL_ANALYZE_ARGUMENT",
    "ER_SQL_COLUMN_COUNT_MAX",
    "ER_HEX_LITERAL_MAX",
    "ER_INT_LITERAL_MAX",
    "ER_SQL_PARSER_LIMIT",
    "ER_INDEX_DEF_UNSUPPORTED",
    "ER_CK_DEF_UNSUPPORTED",
    "ER_MULTIKEY_INDEX_MISMATCH",
    "ER_CREATE_CK_CONSTRAINT",
    "ER_CK_CONSTRAINT_FAILED",
    "ER_SQL_COLUMN_COUNT",
    "ER_FUNC_INDEX_FUNC",
    "ER_FUNC_INDEX_FORMAT",
    "ER_FUNC_INDEX_PARTS",
    "ER_NO_SUCH_FIELD_NAME",
    "ER_FUNC_WRONG_ARG_COUNT",
    "ER_BOOTSTRAP_READONLY",
    "ER_SQL_FUNC_WRONG_RET_COUNT",
    "ER_FUNC_INVALID_RETURN_TYPE",
    "ER_SQL_PARSER_GENERIC_WITH_POS",
    "ER_REPLICA_NOT_ANON",
    "ER_CANNOT_REGISTER",
    "ER_SESSION_SETTING_INVALID_VALUE",
    "ER_SQL_PREPARE",
    "ER_WRONG_QUERY_ID",
    "ER_SEQUENCE_NOT_STARTED",
    "ER_NO_SUCH_SESSION_SETTING",
    "ER_UNCOMMITTED_FOREIGN_SYNC_TXNS",
    "ER_SYNC_MASTER_MISMATCH",
    "ER_SYNC_QUORUM_TIMEOUT",
    "ER_SYNC_ROLLBACK",
    "ER_TUPLE_METADATA_IS_TOO_BIG",
    "ER_XLOG_GAP",
    "ER_TOO_EARLY_SUBSCRIBE",
    "ER_SQL_CANT_ADD_AUTOINC",
    "ER_QUORUM_WAIT",
    "ER_INTERFERING_PROMOTE",
    "ER_ELECTION_DISABLED",
    "ER_TXN_ROLLBACK",
    "ER_NOT_LEADER",
    "ER_SYNC_QUEUE_UNCLAIMED",
    "ER_SYNC_QUEUE_FOREIGN",
    "ER_UNABLE_TO_PROCESS_IN_STREAM",
    "ER_UNABLE_TO_PROCESS_OUT_OF_STREAM",
    "ER_TRANSACTION_TIMEOUT",
    "ER_ACTIVE_TIMER",
    "ER_TUPLE_FIELD_COUNT_LIMIT"
};

enum error_keys {
    MP_ERROR_TYPE = 0x00,
    MP_ERROR_FILE = 0x01,
    MP_ERROR_LINE = 0x02,
    MP_ERROR_MESSAGE = 0x03,
    MP_ERROR_ERRNO = 0x04,
    MP_ERROR_CODE = 0x05,
    MP_ERROR_FIELDS = 0x06,
};

enum system_space_id {
    BOX_VINYL_DEFERRED_DELETE_ID = 257,
    BOX_SCHEMA_ID = 272,
    BOX_COLLATION_ID = 276,
    BOX_VCOLLATION_ID = 277,
    BOX_SPACE_ID = 280,
    BOX_VSPACE_ID = 281,
    BOX_SEQUENCE_ID = 284,
    BOX_SEQUENCE_DATA_ID = 285,
    BOX_VSEQUENCE_ID = 286,
    BOX_INDEX_ID = 288,
    BOX_VINDEX_ID = 289,
    BOX_FUNC_ID = 296,
    BOX_VFUNC_ID = 297,
    BOX_USER_ID = 304,
    BOX_VUSER_ID = 305,
    BOX_PRIV_ID = 312,
    BOX_VPRIV_ID = 313,
    BOX_CLUSTER_ID = 320,
    BOX_TRIGGER_ID = 328,
    BOX_TRUNCATE_ID = 330,
    BOX_SPACE_SEQUENCE_ID = 340,
    BOX_FK_CONSTRAINT_ID = 356,
    BOX_CK_CONSTRAINT_ID = 364,
    BOX_FUNC_INDEX_ID = 372,
    BOX_SESSION_SETTINGS_ID = 380,
    BOX_SYSTEM_ID_MAX = 511,
};

/* Must be sorted by id. */
static struct space {
    enum system_space_id id;
    const char *name;
} system_spaces[] = {
    { BOX_VINYL_DEFERRED_DELETE_ID, "_vinyl_deferred_delete" },
    { BOX_SCHEMA_ID,                "_schema"                },
    { BOX_COLLATION_ID,             "_collation"             },
    { BOX_VCOLLATION_ID,            "_vcollation"            },
    { BOX_SPACE_ID,                 "_space"                 },
    { BOX_VSPACE_ID,                "_vspace"                },
    { BOX_SEQUENCE_ID,              "_sequence"              },
    { BOX_SEQUENCE_DATA_ID,         "_sequence_data"         },
    { BOX_VSEQUENCE_ID,             "_vsequence"             },
    { BOX_INDEX_ID,                 "_index"                 },
    { BOX_VINDEX_ID,                "_vindex"                },
    { BOX_FUNC_ID,                  "_func"                  },
    { BOX_VFUNC_ID,                 "_vfunc"                 },
    { BOX_USER_ID,                  "_user"                  },
    { BOX_VUSER_ID,                 "_vuser"                 },
    { BOX_PRIV_ID,                  "_priv"                  },
    { BOX_VPRIV_ID,                 "_vpriv"                 },
    { BOX_CLUSTER_ID,               "_cluster"               },
    { BOX_TRIGGER_ID,               "_trigger"               },
    { BOX_TRUNCATE_ID,              "_truncate"              },
    { BOX_SPACE_SEQUENCE_ID,        "_space_sequence"        },
    { BOX_FK_CONSTRAINT_ID,         "_fk_constraint"         },
    { BOX_CK_CONSTRAINT_ID,         "_ck_constraint"         },
    { BOX_FUNC_INDEX_ID,            "_func_index"            },
    { BOX_SESSION_SETTINGS_ID,      "_session_settings"      }
};

enum { UUID_STR_LEN = 36 };

struct uuid {
    uint32_t time_low;
    uint16_t time_mid;
    uint16_t time_hi_and_version;
    uint8_t clock_seq_hi_and_reserved;
    uint8_t clock_seq_low;
    uint8_t node[6];
};

const char *get_time(netdissect_options *ndo, double ts);

static inline int
uuid_check(struct uuid *uu)
{
    /* Check variant (NCS, RFC4122, MSFT). */
    uint8_t n = uu->clock_seq_hi_and_reserved;
    if ((n & 0x80) != 0x00 && (n & 0xc0) != 0x80 && (n & 0xe0) != 0xc0) {
        return 1;
    }

    return 0;
}

static inline void
uuid_to_string(const struct uuid *uu, char *out)
{
    snprintf(out, UUID_STR_LEN + 1,
            "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
            uu->time_low, uu->time_mid, uu->time_hi_and_version,
            uu->clock_seq_hi_and_reserved, uu->clock_seq_low, uu->node[0],
            uu->node[1], uu->node[2], uu->node[3], uu->node[4], uu->node[5]);
}

static struct uuid *
uuid_unpack(const char **data, uint32_t len, struct uuid *uuid)
{
    const char *const svp = *data;

    if (len != sizeof(struct uuid)) {
        return NULL;
    }

    uuid->time_low = mp_load_u32(data);
    uuid->time_mid = mp_load_u16(data);
    uuid->time_hi_and_version = mp_load_u16(data);
    uuid->clock_seq_hi_and_reserved = mp_load_u8(data);
    uuid->clock_seq_low = mp_load_u8(data);

    for (int i = 0; i < 6; i++) {
        uuid->node[i] = mp_load_u8(data);
    }

    if (uuid_check(uuid) != 0) {
        *data = svp;
        return NULL;
    }
    return uuid;
}

#define DECIMAL_MAX_DIGITS 38
#define DECIMAL_MAX_STR_LEN DECIMAL_MAX_DIGITS + 14

static int
decimal_unpack(const char **data, uint32_t len, char *res)
{
    enum mp_type type;
    int32_t scale, digits = 0;
    const char *const svp = *data;
    char last_byte;
    uint8_t sign;

    if (!len) {
        return 1;
    }

    type = mp_typeof(**data);

    if (type == MP_UINT) {
        if (mp_check_uint(*data, *data + len) > 0) {
            return 1;
        }
        scale = mp_decode_uint(data);
    } else if (mp_typeof(**data) == MP_INT) {
        if (mp_check_int(*data, *data + len) > 0) {
            return 1;
        }
        scale = mp_decode_int(data);
    } else {
        return 1;
    }

    if (scale > DECIMAL_MAX_DIGITS || scale <= -DECIMAL_MAX_DIGITS) {
        *data = svp;
        return 1;
    }

    len -= *data - svp;

    for (uint32_t n = 0; n < len; n++) {
        uint8_t high_nibble = (*data)[n];
        uint8_t low_nibble = high_nibble;

        high_nibble >>= 4;
        low_nibble &= 0x0f;

        sprintf(res + digits, "%u", high_nibble);
        digits++;

        if (!(strlen(res) == 0 && low_nibble == 0) && n != len - 1) {
            sprintf(res + digits, "%u", low_nibble);
            digits++;
        }
    }

    /* Add missing zeros when scale is less than current length. */
    if (scale >= digits) {
        char zeroes[DECIMAL_MAX_STR_LEN] = {0};
        int32_t z = 0;

        for (; z <= scale - digits; z++) {
            sprintf(zeroes + z, "%d", 0);
        }
        memmove(res + z, res, digits);
        memcpy(res, zeroes, z);
    }

    /* Add a dot when number is fractional. */
    if (scale != 0) {
        size_t res_len = strlen(res);
        size_t shift = res_len - scale;
        memmove(res + shift + 1, res + shift, scale);
        res[shift] = '.';
    }

    /* Add a sign, it is encoded in a low nibble of a last byte. */
    last_byte = (*data)[len - 1];
    sign = last_byte & 0x0f;
    if (sign == 0x0d || sign == 0x0b) {
        memmove(res + 1, res, strlen(res));
        res[0] = '-';
    }

    return 0;
}

static int ext_error_check(const char **data)
{
    uint32_t map_size;
    uint64_t key;

    if (mp_typeof(**data) != MP_MAP) {
        return 1;
    }

    map_size = mp_decode_map(data);
    for (uint32_t i = 0; i < map_size; i++) {
        if (mp_typeof(**data) != MP_UINT) {
            return 1;
        }

        key = mp_decode_uint(data);
        switch (key) {
        case MP_ERROR_STACK:
        {
            uint32_t stack_size;

            if (mp_typeof(**data) != MP_ARRAY) {
                return 1;
            }

            stack_size = mp_decode_array(data);
            for (uint32_t j = 0; j < stack_size; j++) {
                uint32_t err_map_size;

                if (mp_typeof(**data) != MP_MAP) {
                    return 1;
                }

                err_map_size = mp_decode_map(data);
                for (uint32_t k = 0; k < err_map_size; k++) {
                    uint64_t err_key;

                    if (mp_typeof(**data) != MP_UINT) {
                        return 1;
                    }

                    err_key = mp_decode_uint(data);
                    switch (err_key) {
                    case MP_ERROR_TYPE:
                    case MP_ERROR_FILE:
                    case MP_ERROR_MESSAGE:
                    {
                        uint32_t str_len;

                        if (mp_typeof(**data) != MP_STR) {
                            return 1;
                        }
                        mp_decode_str(data, &str_len);
                        break;
                    }
                    case MP_ERROR_LINE:
                    case MP_ERROR_CODE:
                    case MP_ERROR_ERRNO:
                        if (mp_typeof(**data) != MP_UINT) {
                            return 1;
                        }
                        mp_decode_uint(data);
                        break;
                    case MP_ERROR_FIELDS:
                    {
                        uint32_t fields_size;
                        uint32_t str_len;

                        if (mp_typeof(**data) != MP_MAP) {
                            return 1;
                        }
                        fields_size = mp_decode_map(data);
                        for (size_t f = 0; f < fields_size; f++) {
                            if (mp_typeof(**data) != MP_STR) {
                                return 1;
                            }
                            mp_decode_str(data, &str_len);
                            mp_next(data);
                        }
                        break;
                    }
                    default:
                        mp_next(data);
                    }
                }
            }
            break;
        }
        default:
            mp_next(data);
        }
    }

    return 0;
}

static int snprint_error(const char **msg, char *buf, int size);

static int
snprint_ext_custom(char *buf, int size, const char **data, int depth)
{
    (void) depth;
    int8_t type;
    uint32_t len;
    const char *ext = mp_decode_ext(data, &type, &len);

    switch (type) {
    case MP_UUID:
    {
        struct uuid uuid = {0};
        char uuid_out[UUID_STR_LEN + 1] = {0};

        if (uuid_unpack(&ext, len, &uuid) == NULL) {
            memcpy(uuid_out, "corrupted", 9);
        } else {
            uuid_to_string(&uuid, uuid_out);
        }

        return snprintf(buf, size, "(UUID: %s)", uuid_out);
    }
    case MP_ERROR:
        return snprint_error(&ext, buf, size);
    case MP_DECIMAL:
    {
        char dec_str[DECIMAL_MAX_STR_LEN + 1] = {0};

        if (decimal_unpack(&ext, len, dec_str) != 0) {
            memcpy(dec_str, "Error", 5);
        }
        return snprintf(buf, size, "(Decimal: %s)", dec_str);
    }
    case MP_DATETIME:
        return snprintf(buf, size, "(Datetime: len %u)", len);
    }

    return snprintf(buf, size, "(extension: type %d, len %u)", (int)type,
            (unsigned)len);
}

static inline int validate_uuid(const char *data, uint32_t len)
{
    struct uuid uuid;

    return uuid_unpack(&data, len, &uuid) == NULL;
}

static inline int validate_decimal(const char *data, uint32_t len)
{
    char dec_str[DECIMAL_MAX_STR_LEN + 1] = {0};

    return decimal_unpack(&data, len, dec_str);
}

static inline int validate_error(const char *data, uint32_t len)
{
    const char *end = data + len;
    const char *check = data;

    /*
     * The error extension stores the payload in MsgPack format
     * inside the MsgPack. So we need to check all MsgPack messages first.
     */
    if (mp_check(&check, end) != 0 || check != end) {
        return 1;
    }

    return ext_error_check(&data);
}

static int
check_ext_data_custom(int8_t type, const char *data, uint32_t len)
{
    switch (type) {
    case MP_UUID:
        return validate_uuid(data, len);
    case MP_DECIMAL:
        return validate_decimal(data, len);
    case MP_ERROR:
        return validate_error(data, len);
    default:
        return mp_check_ext_data_default(type, data, len);
    }

    return 0;
}

static int space_compar(const void *s1, const void *s2)
{
    const struct space *sp1 = s1;
    const struct space *sp2 = s2;

    if (sp1->id == sp2->id) {
        return 0;
    }

    return (sp1->id < sp2->id) ? -1 : 1;
}

#define TIME_BUF_LEN 32

const char *get_time(netdissect_options *ndo, double ts)
{
    char buf[10] = {0};
#if !defined(_MSC_VER)
    struct tm time;
#else
    struct tm *time;
#endif
    time_t t = ts;
    char *res, *p;
    double fract;
    size_t len;

#if !defined(_MSC_VER)
    if ((localtime_r(&t, &time)) != &time) {
#else
    if ((time = localtime(&t)) == NULL) {
#endif
        return NULL;
    }

    if ((res = nd_malloc(ndo, TIME_BUF_LEN)) == NULL) {
        return NULL;
    }
    p = res;
    memset(res, 0, TIME_BUF_LEN);

#if !defined(_MSC_VER)
    if (!strftime(res, TIME_BUF_LEN, "%Y-%m-%d %H:%M:%S", &time)) {
#else
    if (!strftime(res, TIME_BUF_LEN, "%Y-%m-%d %H:%M:%S", time)) {
#endif
        return NULL;
    }

    len = strlen(res);
    p += len;
    fract = ts - t;
    snprintf(buf, sizeof(buf), "%lf", fract);
    snprintf(p, TIME_BUF_LEN - len, "%s", buf + 1);

    return res;
}

#define GR_NAME "Tarantool"
#define GR_MAXLEN 64
#define ARR_LEN(p) (sizeof(p) / sizeof((p)[0]))
#define ND_PRINT_INVALID() (ndo->ndo_printf)(ndo, " [|iproto]")

typedef struct {
    uint64_t key;
    union {
        uint64_t val;
        double val_d;
    } u;
} kv_t;

#define GEN_REQ(req)                                                   \
    static int parse_ ## req(netdissect_options *ndo, const char *msg, \
            const char *body_end, const kv_t *kv, size_t kv_len);

#define GEN_REQ_FUNC(req, name)                                     \
static int parse_ ## req(netdissect_options *ndo, const char *msg,  \
        const char *body_end, const kv_t *kv, size_t kv_len)        \
{                                                                   \
    double timestamp = 0;                                           \
    uint64_t sync = 0, lsn = 0, rid = 0, flags = 0;                 \
                                                                    \
    for (size_t n = 0; n < kv_len; n++) {                           \
        switch (kv[n].key) {                                        \
        case IPROTO_SYNC:                                           \
            sync = kv[n].u.val;                                     \
            break;                                                  \
        case IPROTO_LSN:                                            \
            lsn = kv[n].u.val;                                      \
            break;                                                  \
        case IPROTO_REPLICA_ID:                                     \
            rid = kv[n].u.val;                                      \
            break;                                                  \
        case IPROTO_FLAGS:                                          \
            flags = kv[n].u.val;                                    \
            break;                                                  \
        case IPROTO_TIMESTAMP:                                      \
            timestamp = kv[n].u.val_d;                              \
            break;                                                  \
        }                                                           \
    }                                                               \
                                                                    \
    ND_PRINT(" request: %s, SYNC: %" PRIu64, #name, sync);          \
    if (rid) {                                                      \
        ND_PRINT(", REPLICA_ID: %" PRIu64, rid);                    \
    }                                                               \
    if (lsn) {                                                      \
        ND_PRINT(", LSN: %" PRIu64, lsn);                           \
    }                                                               \
    if (timestamp) {                                                \
        const char *time = get_time(ndo, timestamp);                \
        ND_PRINT(", TIMESTAMP: %s", (time) ? time : "NULL");        \
    }                                                               \
    if (flags) {                                                    \
        ND_PRINT(", FLAGS: %" PRIu64, flags);                       \
    }                                                               \
                                                                    \
    if (ndo->ndo_vflag == 0) {                                      \
        return 0;                                                   \
    }                                                               \
                                                                    \
    return parse_body(ndo, msg, body_end);                          \
}

#define GEN_NOBODY_REQ_FUNC(req, name)                              \
static int parse_ ## req(netdissect_options *ndo, const char *msg,  \
        const char *body_end, const kv_t *kv, size_t kv_len)        \
{                                                                   \
    uint64_t sync = 0;                                              \
    (void) msg;                                                     \
    (void) body_end;                                                \
                                                                    \
    for (size_t n = 0; n < kv_len; n++) {                           \
        switch (kv[n].key) {                                        \
        case IPROTO_SYNC:                                           \
            sync = kv[n].u.val;                                     \
            break;                                                  \
        }                                                           \
    }                                                               \
                                                                    \
    ND_PRINT(" request: %s, SYNC: %" PRIu64, #name, sync);          \
    return 0;                                                       \
}

#define GEN_TRANS_REQ_FUNC(req, name)                                     \
static int parse_ ## req(netdissect_options *ndo, const char *msg,        \
        const char *body_end, const kv_t *kv, size_t kv_len)              \
{                                                                         \
    uint64_t sync, id;                                                    \
    (void) msg;                                                           \
    (void) body_end;                                                      \
                                                                          \
    sync = id = 0;                                                        \
                                                                          \
    for (size_t n = 0; n < kv_len; n++) {                                 \
        switch (kv[n].key) {                                              \
        case IPROTO_SYNC:                                                 \
            sync = kv[n].u.val;                                           \
            break;                                                        \
        case IPROTO_STREAM_ID:                                            \
            id = kv[n].u.val;                                             \
            break;                                                        \
        default:                                                          \
            goto out;                                                     \
        }                                                                 \
    }                                                                     \
                                                                          \
    ND_PRINT(" request: %s, STREAM_ID: %" PRIu64 ", SYNC: %" PRIu64,      \
        #name, id, sync);                                                 \
                                                                          \
    return 0;                                                             \
out:                                                                      \
    nd_print_invalid(ndo);                                                \
    return -1;                                                            \
}

typedef int (*request_print_t)(netdissect_options *ndo, const char *msg,
        const char *body_end, const kv_t *kv, size_t kv_len);

GEN_REQ(ok)
GEN_REQ(id)
GEN_REQ(eval)
GEN_REQ(ping)
GEN_REQ(select)
GEN_REQ(insert)
GEN_REQ(update)
GEN_REQ(replace)
GEN_REQ(delete)
GEN_REQ(call)
GEN_REQ(call16)
GEN_REQ(auth)
GEN_REQ(upsert)
GEN_REQ(execute)
GEN_REQ(nop)
GEN_REQ(prepare)
GEN_REQ(begin)
GEN_REQ(commit)
GEN_REQ(rollback)
GEN_REQ(vote)
GEN_REQ(join)
GEN_REQ(subscribe)
GEN_REQ(join_meta)
GEN_REQ(join_snapshot)
GEN_REQ(raft)
GEN_REQ(raft_promote)
GEN_REQ(raft_confirm)
GEN_REQ(error)

#define CASE_IPROTO_STR(param)                                      \
    case IPROTO_ ## param:                                          \
    {                                                               \
        const char *func;                                           \
                                                                    \
        if (mp_typeof(*msg) != MP_STR) {                            \
            ND_PRINT_INVALID();                                     \
            return -1;                                              \
        }                                                           \
                                                                    \
        func = get_string(ndo, &msg);                               \
        if (func) {                                                 \
            ND_PRINT("\n\t%s: %s", #param, func);                   \
        }                                                           \
        break;                                                      \
    }                                                               \

#define CASE_IPROTO_UINT(param)                                     \
    case IPROTO_ ## param:                                          \
        if (mp_typeof(*msg) != MP_UINT) {                           \
            ND_PRINT_INVALID();                                     \
            return -1;                                              \
        }                                                           \
        ND_PRINT("\n\t%s: %" PRIu64, #param, mp_decode_uint(&msg)); \
        break;

#define CASE_IPROTO_ARRAY(param)                                    \
    case IPROTO_ ## param:                                          \
        if (mp_typeof(*msg) != MP_ARRAY) {                          \
            ND_PRINT_INVALID();                                     \
            return -1;                                              \
        }                                                           \
                                                                    \
        ND_PRINT("\n\t%s: %s", #param, get_content(ndo, msg));      \
        mp_next(&msg);                                              \
        break;                                                      \

#define CASE_IPROTO_MAP(param)                                      \
    case IPROTO_ ## param:                                          \
        if (mp_typeof(*msg) != MP_MAP) {                            \
            ND_PRINT_INVALID();                                     \
            return -1;                                              \
        }                                                           \
        ND_PRINT("\n\t%s: %s", #param, get_content(ndo, msg));      \
        mp_next(&msg);                                              \
        break;

#define CASE_IPROTO_BOOL(param)                                     \
    case IPROTO_ ## param:                                          \
        if (mp_typeof(*msg) != MP_BOOL) {                           \
            ND_PRINT_INVALID();                                     \
            return -1;                                              \
        }                                                           \
        ND_PRINT("\n\t%s: %s", #param,                              \
                mp_decode_bool(&msg) ? "true" : "false");           \
        break;

/* Must be sorted by type. */
static struct request {
    enum request_type type;
    request_print_t print;
} request_ops[] = {
    { .type = IPROTO_OK,            .print = parse_ok            },
    { .type = IPROTO_SELECT,        .print = parse_select        },
    { .type = IPROTO_INSERT,        .print = parse_insert        },
    { .type = IPROTO_REPLACE,       .print = parse_replace       },
    { .type = IPROTO_UPDATE,        .print = parse_update        },
    { .type = IPROTO_DELETE,        .print = parse_delete        },
    { .type = IPROTO_CALL_16,       .print = parse_call16        },
    { .type = IPROTO_AUTH,          .print = parse_auth          },
    { .type = IPROTO_EVAL,          .print = parse_eval          },
    { .type = IPROTO_UPSERT,        .print = parse_upsert        },
    { .type = IPROTO_CALL,          .print = parse_call          },
    { .type = IPROTO_EXECUTE,       .print = parse_execute       },
    { .type = IPROTO_NOP,           .print = parse_nop           },
    { .type = IPROTO_PREPARE,       .print = parse_prepare       },
    { .type = IPROTO_BEGIN,         .print = parse_begin         },
    { .type = IPROTO_COMMIT,        .print = parse_commit        },
    { .type = IPROTO_ROLLBACK,      .print = parse_rollback      },
    { .type = IPROTO_RAFT,          .print = parse_raft          },
    { .type = IPROTO_RAFT_PROMOTE,  .print = parse_raft_promote  },
    { .type = IPROTO_RAFT_CONFIRM,  .print = parse_raft_confirm  },
    { .type = IPROTO_PING,          .print = parse_ping          },
    { .type = IPROTO_JOIN,          .print = parse_join          },
    { .type = IPROTO_SUBSCRIBE,     .print = parse_subscribe     },
    { .type = IPROTO_VOTE,          .print = parse_vote          },
    { .type = IPROTO_JOIN_META,     .print = parse_join_meta     },
    { .type = IPROTO_JOIN_SNAPSHOT, .print = parse_join_snapshot },
    { .type = IPROTO_ID,            .print = parse_id            },
    { .type = IPROTO_TYPE_ERROR,    .print = parse_error         }
};

static int request_compar(const void *r1, const void *r2)
{
    const struct request *re1 = r1;
    const struct request *re2 = r2;

    if (re1->type == re2->type) {
        return 0;
    }

    return (re1->type < re2->type) ? -1 : 1;
}

static char *get_content(netdissect_options *ndo, const char *msg)
{
    int len = mp_snprint(NULL, 0, msg);
    char *data = NULL;

    if (len > 0) {
        len++; /* '\0' */

        data = nd_malloc(ndo, len);
        if (!data) {
            return NULL;
        }
        mp_snprint(data, len, msg);
    }

    return data;
}

static char *get_string(netdissect_options *ndo, const char **msg)
{
    const char *str;
    uint32_t len;
    char *res;

    str = mp_decode_str(msg, &len);
    res = (char *) nd_malloc(ndo, len + 1);
    if (!res) {
        return NULL;
    }
    memcpy(res, str, len);
    res[len] = '\0';

    return res;
}

static int snprint_error(const char **msg, char *buf, int size)
{
    int n = 0;
    uint32_t stack_size;
    int wlen = 0;
    char *tmpbuf = NULL;
    const char *err_ext = "(ERROR: ";
    size_t err_ext_len = strlen(err_ext);

    if (buf != NULL) {
        tmpbuf = calloc(1, size);
    }

    if (!tmpbuf && buf) {
        return snprintf(buf, size, "(Error: ENOMEM)");
    }

    if (mp_typeof(**msg) != MP_MAP) {
        goto err_exit;
    }

    if (mp_decode_map(msg) != 1) {
        goto err_exit;
    }

    if (mp_typeof(**msg) != MP_UINT) {
        goto err_exit;
    }

    if (mp_decode_uint(msg) != MP_ERROR_STACK) {
        goto err_exit;
    }

    if (mp_typeof(**msg) != MP_ARRAY) {
        goto err_exit;
    }

    stack_size = mp_decode_array(msg);

    if (buf != NULL) {
        memcpy(tmpbuf + wlen, err_ext, err_ext_len);
    }
    wlen += err_ext_len;

    for (uint32_t s = 0; s < stack_size; s++) {
        uint32_t map_items = mp_decode_map(msg);

        if (buf != NULL) {
            memcpy(tmpbuf + wlen, "[", 1);
        }
        wlen++;

        for (uint32_t i = 0; i < map_items; i++) {
            if (mp_typeof(**msg) != MP_UINT) {
                goto err_exit;
            }
            uint64_t err_key = mp_decode_uint(msg);

            switch (err_key) {
            case MP_ERROR_TYPE:
            {
                const char *type;
                const char *info = "{ \"type\": \"";
                size_t info_len = strlen(info);
                uint32_t len;

                if (mp_typeof(**msg) != MP_STR) {
                    goto err_exit;
                }

                type = mp_decode_str(msg, &len);
                if (type != NULL) {
                    if (buf != NULL) {
                        memcpy(tmpbuf + wlen, info, info_len);
                        memcpy(tmpbuf + wlen + info_len, type, len);
                        memcpy(tmpbuf + wlen + info_len + len, "\"", 1);
                    }
                    wlen += (len + info_len + 1);
                }
                break;
            }
            case MP_ERROR_FILE:
            {
                const char *type;
                const char *info = ", \"file\": \"";
                size_t info_len = strlen(info);
                uint32_t len;

                if (mp_typeof(**msg) != MP_STR) {
                    goto err_exit;
                }

                type = mp_decode_str(msg, &len);
                if (type != NULL) {
                    if (buf != NULL) {
                        memcpy(tmpbuf + wlen, info, info_len);
                        memcpy(tmpbuf + wlen + info_len, type, len);
                        memcpy(tmpbuf + wlen + info_len + len, "\"", 1);
                    }
                    wlen += (len + info_len + 1);
                }
                break;
            }
            case MP_ERROR_MESSAGE:
            {
                const char *type;
                const char *info = ", \"message\": \"";
                size_t info_len = strlen(info);
                uint32_t len;

                if (mp_typeof(**msg) != MP_STR) {
                    goto err_exit;
                }

                type = mp_decode_str(msg, &len);
                if (type != NULL) {
                    if (buf != NULL) {
                        memcpy(tmpbuf + wlen, info, info_len);
                        memcpy(tmpbuf + wlen + info_len, type, len);
                        memcpy(tmpbuf + wlen + info_len + len, "\"", 1);
                    }
                    wlen += (len + info_len + 1);
                }
                break;
            }
            case MP_ERROR_LINE:
            {
                uint64_t num;
                size_t num_len;
                char num_buf[32] = {0};

                if (mp_typeof(**msg) != MP_UINT) {
                    goto err_exit;
                }
                num = mp_decode_uint(msg);
                snprintf(num_buf, sizeof(num_buf),
                        ", \"line\": %" PRIu64, num);
                num_len = strlen(num_buf);
                if (buf != NULL) {
                    memcpy(tmpbuf + wlen, num_buf, num_len);
                }
                wlen += num_len;
                break;
            }
            case MP_ERROR_CODE:
            {
                uint64_t num;
                size_t num_len;
                char num_buf[32] = {0};

                if (mp_typeof(**msg) != MP_UINT) {
                    goto err_exit;
                }
                num = mp_decode_uint(msg);
                snprintf(num_buf, sizeof(num_buf),
                        ", \"code\": %" PRIu64 " }", num);
                num_len = strlen(num_buf);
                if (buf != NULL) {
                    memcpy(tmpbuf + wlen, num_buf, num_len);
                }
                wlen += num_len;
                break;
            }
            case MP_ERROR_ERRNO:
            {
                uint64_t num;
                size_t num_len;
                char num_buf[32] = {0};

                if (mp_typeof(**msg) != MP_UINT) {
                    goto err_exit;
                }
                num = mp_decode_uint(msg);
                snprintf(num_buf, sizeof(num_buf),
                        ", \"errno\": %" PRIu64, num);
                num_len = strlen(num_buf);
                if (buf != NULL) {
                    memcpy(tmpbuf + wlen, num_buf, num_len);
                }
                wlen += num_len;
                break;
            }
            case MP_ERROR_FIELDS:
            {
                if (mp_typeof(**msg) != MP_MAP) {
                    goto err_exit;
                }
                const char *fields_msg = ", \"fields\": {";
                size_t fields_len = strlen(fields_msg);
                uint32_t fields = mp_decode_map(msg);

                if (buf != NULL && fields) {
                    memcpy(tmpbuf + wlen, fields_msg, fields_len);
                }

                if (fields) {
                    wlen += fields_len;
                }

                for (size_t f = 0; f < fields; f++) {
                    uint32_t len, val_len;
                    const char *k, *v;

                    if (mp_typeof(**msg) != MP_STR) {
                        goto err_exit;
                    }

                    k = mp_decode_str(msg, &len);
                    v = *msg;
                    mp_next(msg);
                    val_len = *msg - v;

                    if (mp_typeof(*v) == MP_STR) {
                        v++;
                        val_len--;
                    }

                    if (k && v && buf != NULL) {
                        memcpy(tmpbuf + wlen, " \"", 2);
                        memcpy(tmpbuf + wlen + 2, k, len);
                        memcpy(tmpbuf + wlen + 2 + len, "\": ", 3);
                        memcpy(tmpbuf + wlen + 5 + len, v, val_len);
                        memcpy(tmpbuf + wlen + 5 + len + val_len,
                                (f != fields - 1) ? "," : " ", 1);
                    }

                    if (k && v) {
                        wlen += len + val_len + 6;
                    }
                }

                if (buf != NULL && fields) {
                    memcpy(tmpbuf + wlen, "}", 1);
                }
                if (fields) {
                    wlen++;
                }
                break;
            }
            default:
                mp_next(msg);
            }
        }

        if (buf != NULL) {
            memcpy(tmpbuf + wlen, "]", 1);
        }
        wlen++;
    }

    if (buf != NULL) {
        memcpy(tmpbuf + wlen, ")", 1);
    }
    wlen++;

    if (buf != NULL) {
        n = snprintf(buf, size, "%s", tmpbuf);
        free(tmpbuf);
    } else {
        n = wlen;
    }
    return n;

err_exit:
    if (buf != NULL) {
        free(tmpbuf);
        return snprintf(buf, size, "(Error: incorrect message)");
    } else {
        return strlen("(Error: incorrect message)");
    }
}

/* Format: {0: [{}]} */
static int print_error(netdissect_options *ndo, const char **msg)
{
    uint32_t stack_size;

    if (!msg) {
        return -1;
    }

    if (mp_typeof(**msg) != MP_MAP) {
        ND_PRINT_INVALID();
        return -1;
    }

    if (mp_decode_map(msg) != 1) {
        return -1;
    }

    if (mp_typeof(**msg) != MP_UINT) {
        ND_PRINT_INVALID();
        return -1;
    }

    if (mp_decode_uint(msg) != MP_ERROR_STACK) {
        return -1;
    }

    if (mp_typeof(**msg) != MP_ARRAY) {
        ND_PRINT_INVALID();
        return -1;
    }

    stack_size = mp_decode_array(msg);
    for (uint32_t s = 0; s < stack_size; s++) {
        uint32_t map_items = mp_decode_map(msg);

        if (map_items && s != 0) {
            ND_PRINT("\n\t---");
        }

        for (uint32_t i = 0; i < map_items; i++) {
            uint64_t err_key;

            if (mp_typeof(**msg) != MP_UINT) {
                ND_PRINT_INVALID();
                return -1;
            }

            err_key = mp_decode_uint(msg);
            switch (err_key) {
            case MP_ERROR_TYPE:
            {
                const char *type;

                if (mp_typeof(**msg) != MP_STR) {
                    ND_PRINT_INVALID();
                    return -1;
                }

                type = get_string(ndo, msg);
                if (type) {
                    ND_PRINT("\n\tTYPE: %s", type);
                }
                break;
            }
            case MP_ERROR_FILE:
            {
                const char *file;

                if (mp_typeof(**msg) != MP_STR) {
                    ND_PRINT_INVALID();
                    return -1;
                }

                file = get_string(ndo, msg);
                if (file) {
                    ND_PRINT("\n\tFILE: %s", file);
                }
                break;
            }
            case MP_ERROR_LINE:
                if (mp_typeof(**msg) != MP_UINT) {
                    ND_PRINT_INVALID();
                    return -1;
                }
                ND_PRINT("\n\tLINE: %" PRIu64, mp_decode_uint(msg));
                break;
            case MP_ERROR_MESSAGE:
            {
                const char *message;

                if (mp_typeof(**msg) != MP_STR) {
                    ND_PRINT_INVALID();
                    return -1;
                }

                message = get_string(ndo, msg);
                if (message) {
                    ND_PRINT("\n\tMESSAGE: %s", message);
                }
                break;
            }
            case MP_ERROR_ERRNO:
                if (mp_typeof(**msg) != MP_UINT) {
                    ND_PRINT_INVALID();
                    return -1;
                }
                ND_PRINT("\n\tERRNO: %" PRIu64, mp_decode_uint(msg));
                break;
            case MP_ERROR_CODE:
                if (mp_typeof(**msg) != MP_UINT) {
                    ND_PRINT_INVALID();
                    return -1;
                }
                ND_PRINT("\n\tCODE: %" PRIu64, mp_decode_uint(msg));
                break;
            case MP_ERROR_FIELDS:
            {
                uint32_t fields = mp_decode_map(msg);

                if (fields) {
                    ND_PRINT("\n\tFIELDS:");
                }

                for (size_t f = 0; f < fields; f++) {
                    const char *k, *v;

                    if (mp_typeof(**msg) != MP_STR) {
                        ND_PRINT_INVALID();
                        return -1;
                    }

                    k = get_string(ndo, msg);
                    v = get_string(ndo, msg);

                    if (k && v) {
                        ND_PRINT(" %s: %s%s", k, v,
                                (f != fields - 1) ? "," : "");
                    }
                }
                break;
            }
            }
        }
    }

    return 0;
}

static int
parse_body(netdissect_options *ndo, const char *msg, const char *body_end)
{
    uint32_t body_items;
    const char *p = msg;

    if (mp_check(&p, body_end) != 0 || p != body_end) {
        ND_PRINT(" [|iproto]");
        return -1;
    }

    if (mp_typeof(*msg) != MP_MAP) {
        ND_PRINT_INVALID();
        return -1;
    }

    body_items = mp_decode_map(&msg);

    for (uint32_t n = 0; n < body_items; n++) {
        uint64_t key;

        if (mp_typeof(*msg) != MP_UINT) {
            ND_PRINT_INVALID();
            return -1;
        }

        key = mp_decode_uint(&msg);
        switch (key) {
        case IPROTO_SPACE_ID:
        {
            uint64_t sid;

            if (mp_typeof(*msg) != MP_UINT) {
                ND_PRINT_INVALID();
                return -1;
            }

            sid = mp_decode_uint(&msg);
            if (sid >= BOX_SYSTEM_ID_MAX) {
                ND_PRINT("\n\tSPACE_ID: %" PRIu64, sid);
            } else {
                struct space sp = { .id = sid };
                struct space *res;

                res = bsearch(&sp, system_spaces, ARR_LEN(system_spaces),
                        sizeof(struct space), space_compar);
                if (res) {
                    ND_PRINT("\n\tSPACE: %s (ID: %" PRIu64 ")",
                            res->name, sid);
                } else {
                    ND_PRINT("\n\tSPACE_ID: %" PRIu64, sid);
                }
            }
            break;
        }
        case IPROTO_ITERATOR:
        {
            uint64_t it;

            if (mp_typeof(*msg) != MP_UINT) {
                ND_PRINT_INVALID();
                return -1;
            }

            it = mp_decode_uint(&msg);

            ND_PRINT("\n\tITERATOR: %s", (it >= ARR_LEN(iterator_type)) ?
                    "unknown" : iterator_type[it]);
            break;
        }
        case IPROTO_BALLOT:
        {
            uint32_t ballot_items;

            if (mp_typeof(*msg) != MP_MAP) {
                ND_PRINT_INVALID();
                return -1;
            }

            ballot_items = mp_decode_map(&msg);
            if (ballot_items) {
                ND_PRINT("\n\t[BALLOT]");
            }
            for (uint32_t b = 0; b < ballot_items; b++) {
                uint64_t bkey;

                if (mp_typeof(*msg) != MP_UINT) {
                    ND_PRINT_INVALID();
                    return -1;
                }

                bkey = mp_decode_uint(&msg);
                switch (bkey) {
                    CASE_IPROTO_BOOL(BALLOT_IS_RO_CFG);
                    CASE_IPROTO_BOOL(BALLOT_IS_RO);
                    CASE_IPROTO_BOOL(BALLOT_IS_ANON);
                    CASE_IPROTO_BOOL(BALLOT_IS_BOOTED);
                    CASE_IPROTO_BOOL(BALLOT_CAN_LEAD);
                    CASE_IPROTO_MAP(BALLOT_VCLOCK);
                    CASE_IPROTO_MAP(BALLOT_GC_VCLOCK);
                }
            }
            break;
        }
        case IPROTO_DATA:
        {
            uint32_t data_items;

            if (mp_typeof(*msg) != MP_ARRAY) {
                ND_PRINT_INVALID();
                return -1;
            }

            data_items = mp_decode_array(&msg);
            if (data_items) {
                ND_PRINT("\n\tDATA:");
            }
            for (uint32_t d = 0; d < data_items; d++) {
                switch (mp_typeof(*msg)) {
                case MP_EXT:
                {
                    int8_t type;
                    uint32_t len;
                    const char *ext = mp_decode_ext(&msg, &type, &len);
                    uint8_t idx = type;
                    ND_PRINT("\n\tEXTENSION: type %s [%d], len %u",
                            (idx >= ARR_LEN(extension_type)) ?
                            "UNKNOWN" : extension_type[idx],
                            type, len);
                    switch (type) {
                    case MP_ERROR:
                        if (print_error(ndo, &ext) == -1) {
                            return -1;
                        }
                        break;
                    }
                    break;
                }
                default:
                    ND_PRINT("\n\t%s", get_content(ndo, msg));
                    mp_next(&msg);
                    break;
                }
            }
            break;
        }
        CASE_IPROTO_STR(INSTANCE_UUID);
        CASE_IPROTO_STR(CLUSTER_UUID);
        CASE_IPROTO_STR(FUNCTION_NAME);
        CASE_IPROTO_STR(SQL_TEXT);
        CASE_IPROTO_STR(EXPR);
        CASE_IPROTO_MAP(VCLOCK);
        CASE_IPROTO_UINT(SERVER_VERSION);
        CASE_IPROTO_UINT(VERSION);
        CASE_IPROTO_UINT(BIND_COUNT);
        CASE_IPROTO_UINT(INDEX_ID);
        CASE_IPROTO_UINT(INDEX_BASE);
        CASE_IPROTO_UINT(STMT_ID);
        CASE_IPROTO_UINT(OFFSET);
        CASE_IPROTO_UINT(LIMIT);
        CASE_IPROTO_UINT(REPLICA_ID);
        CASE_IPROTO_UINT(LSN);
        CASE_IPROTO_UINT(TERM);
        CASE_IPROTO_BOOL(REPLICA_ANON);
        CASE_IPROTO_ARRAY(FEATURES);
        CASE_IPROTO_ARRAY(METADATA);
        CASE_IPROTO_ARRAY(BIND_METADATA);
        CASE_IPROTO_ARRAY(KEY);
        CASE_IPROTO_ARRAY(TUPLE);
        CASE_IPROTO_ARRAY(OPS);
        CASE_IPROTO_ARRAY(OPTIONS);
        CASE_IPROTO_ARRAY(SQL_BIND);
        CASE_IPROTO_ARRAY(ID_FILTER);
        default:
            ND_PRINT("\n\tUNKNOWN");
            mp_next(&msg);
        }
    }

    return 0;
}

GEN_REQ_FUNC(prepare, PREPARE)
GEN_REQ_FUNC(call, CALL)
GEN_REQ_FUNC(call16, CALL_16)
GEN_REQ_FUNC(id, ID)
GEN_REQ_FUNC(delete, DELETE)
GEN_REQ_FUNC(replace, REPLACE)
GEN_REQ_FUNC(upsert, UPSERT)
GEN_REQ_FUNC(update, UPDATE)
GEN_REQ_FUNC(execute, EXECUTE)
GEN_REQ_FUNC(insert, INSERT)
GEN_REQ_FUNC(select, SELECT)
GEN_REQ_FUNC(eval, EVAL)
GEN_REQ_FUNC(join, JOIN)
GEN_REQ_FUNC(subscribe, SUBSCRIBE)
GEN_REQ_FUNC(join_meta, JOIN_META)
GEN_REQ_FUNC(raft_promote, RAFT_PROMOTE)
GEN_REQ_FUNC(raft_confirm, RAFT_CONFIRM)
GEN_NOBODY_REQ_FUNC(ping, PING)
GEN_NOBODY_REQ_FUNC(nop, NOP)
GEN_NOBODY_REQ_FUNC(join_snapshot, JOIN_SNAPSHOT)
GEN_TRANS_REQ_FUNC(begin, BEGIN)
GEN_TRANS_REQ_FUNC(commit, COMMIT)
GEN_TRANS_REQ_FUNC(rollback, ROLLBACK)

static int
parse_heartbeat(netdissect_options *ndo, const char *msg, const char *body_end)
{
    uint32_t body_items;
    const char *p = msg;
    bool heartbeat_resp = false;

    if (mp_check(&p, body_end) != 0 || p != body_end) {
        ND_PRINT(" [|iproto]");
        return -1;
    }

    if (mp_typeof(*msg) != MP_MAP) {
        ND_PRINT_INVALID();
        return -1;
    }

    body_items = mp_decode_map(&msg);

    for (uint32_t n = 0; n < body_items; n++) {
        uint64_t key;

        if (mp_typeof(*msg) != MP_UINT) {
            ND_PRINT_INVALID();
            return -1;
        }

        key = mp_decode_uint(&msg);
        switch (key) {
        case IPROTO_VCLOCK:
            if (mp_typeof(*msg) != MP_MAP) {
                ND_PRINT_INVALID();
                return -1;
            }

            heartbeat_resp = true;
            break;
        }
    }

    if (heartbeat_resp) {
        ND_PRINT(" response: HEARTBEAT");
        if (ndo->ndo_vflag == 0) {
            return 0;
        }
        ND_PRINT("\n\tVCLOCK: %s", get_content(ndo, msg));
    }

    return 0;
}

static int
parse_ok(netdissect_options *ndo, const char *msg,
        const char *body_end, const kv_t *kv, size_t kv_len)
{
    uint64_t sync, version, key, replica_id;
    double timestamp = 0;

    sync = version = key = replica_id = 0;

    if (!kv_len) { /* May be a heartbeat response. */
        return parse_heartbeat(ndo, msg, body_end);
    }

    for (size_t n = 0; n < kv_len; n++) {
        switch (kv[n].key) {
        case IPROTO_SYNC:
            sync = kv[n].u.val;
            break;
        case IPROTO_SCHEMA_VERSION:
            version = kv[n].u.val;
            break;
        case IPROTO_REPLICA_ID:
            replica_id = kv[n].u.val;
            break;
        case IPROTO_TIMESTAMP:
            timestamp = kv[n].u.val_d;
            break;
        default:
            return -1;
        }
    }

    if (replica_id && timestamp) { /* Heartbeat request. */
        const char *time = get_time(ndo, timestamp);
        ND_PRINT(" request: HEARTBEAT, REPLICA_ID: %" PRIu64 ", TIMESTAMP: %s",
                replica_id, (time) ? time : "NULL");
        return 0;
    }

    ND_PRINT(" response: OK, SYNC: %" PRIu64 ", SCHEMA_VERSION: %" PRIu64,
            sync, version);
    if (timestamp) {
        const char *time = get_time(ndo, timestamp);
        ND_PRINT(", TIMESTAMP: %s", (time) ? time : "NULL");
    }

    if (ndo->ndo_vflag == 0) {
        return 0;
    }

    return parse_body(ndo, msg, body_end);
}

static int
parse_error(netdissect_options *ndo, const char *msg,
        const char *body_end, const kv_t *kv, size_t kv_len)
{
    uint64_t sync, version, errcode;
    uint32_t body_items;
    const char *p = msg;

    sync = version = errcode = 0;

    if (kv_len != 3) {
        return -1;
    }

    for (size_t n = 0; n < kv_len; n++) {
        switch (kv[n].key) {
        case IPROTO_SYNC:
            sync = kv[n].u.val;
            break;
        case IPROTO_SCHEMA_VERSION:
            version = kv[n].u.val;
            break;
        case IPROTO_REQUEST_TYPE:
            errcode = kv[n].u.val;
            break;
        default:
            return -1;
        }
    }

    ND_PRINT(" response: ERR: %s, SYNC: %" PRIu64 ", SCHEMA_VERSION: %" PRIu64,
            (errcode >= ARR_LEN(error_codes)) ? "unknown" :
            error_codes[errcode], sync, version);

    if (ndo->ndo_vflag == 0) {
        return 0;
    }

    /* Parse and print body. */
    if (mp_check(&p, body_end) != 0 || p != body_end) {
        ND_PRINT(" [|iproto]");
        return -1;
    }
    if (mp_typeof(*msg) != MP_MAP) {
        ND_PRINT_INVALID();
        return -1;
    }

    body_items = mp_decode_map(&msg);

    if (body_items == 1) { /* Versions <= 2.4.0 */
        uint64_t key;

        if (mp_typeof(*msg) != MP_UINT) {
            ND_PRINT_INVALID();
            return -1;
        }

        key = mp_decode_uint(&msg);

        if (key == IPROTO_ERROR_24) {
            const char *error;

            if (mp_typeof(*msg) != MP_STR) {
                ND_PRINT_INVALID();
                return -1;
            }

            error = get_string(ndo, &msg);
            if (error) {
                ND_PRINT("\n\tERROR: %s", error);
            }
        }
        return 0;
    }

    for (uint32_t n = 0; n < body_items; n++) {
        uint64_t key;

        if (mp_typeof(*msg) != MP_UINT) {
            ND_PRINT_INVALID();
            return -1;
        }

        key = mp_decode_uint(&msg);
        switch (key) {
        case IPROTO_ERROR_24:
            mp_next(&msg);
            break;
        case IPROTO_ERROR:
            if (print_error(ndo, &msg) == -1) {
                return -1;
            }
            break;
        }
    }

    return 0;
}

static int
parse_vote(netdissect_options *ndo, const char *msg,
        const char *body_end, const kv_t *kv, size_t kv_len)
{
    (void) msg;
    (void) body_end;
    (void) kv;
    (void) kv_len;

    ND_PRINT(" request: VOTE");
    return 0;
}

static const char
base64_chars[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static char *base64_encode(netdissect_options *ndo, const uint8_t *src,
        uint32_t src_len)
{
    size_t res_len;
    char *res;

    res_len = 4 * ((src_len + 2) / 3);
    res = nd_malloc(ndo, res_len + 1);
    if (!res) {
        return NULL;
    }

    for (size_t i = 0, j = 0; i < src_len; i += 3, j += 4) {
        size_t a = i < src_len ? src[i] : 0;
        size_t b = i + 1 < src_len ? src[i + 1] : 0;
        size_t c = i + 2 < src_len ? src[i + 2] : 0;
        size_t abc = (a << 0x10) + (b << 0x8) + c;

        res[j] = base64_chars[(abc >> 18) & 0x3F];
        res[j + 1] = base64_chars[(abc >> 12) & 0x3F];

        if (i + 1 < src_len)
            res[j + 2] = base64_chars[(abc >> 6) & 0x3F];
        else
            res[j + 2] = '=';

        if (i + 2 < src_len)
            res[j + 3] = base64_chars[abc & 0x3F];
        else
            res[j + 3] = '=';
    }

    return res;
}

/*
 * IPROTO_AUTH requires additional processing:
 * scramble is stored in binary format and needs to be encoded for printing.
 */
static int
parse_auth(netdissect_options *ndo, const char *msg,
        const char *body_end, const kv_t *kv, size_t kv_len)
{
    uint64_t sync = 0;
    uint32_t body_items;
    const char *p = msg;

    for (size_t n = 0; n < kv_len; n++) {
        switch (kv[n].key) {
        case IPROTO_SYNC:
            sync = kv[n].u.val;
            break;
        }
    }

    ND_PRINT(" request: AUTH, SYNC: %" PRIu64, sync);

    if (ndo->ndo_vflag == 0) {
        return 0;
    }

    /* Parse and print body. */
    if (mp_check(&p, body_end) != 0 || p != body_end) {
        ND_PRINT(" [|iproto]");
        return -1;
    }
    if (mp_typeof(*msg) != MP_MAP) {
        ND_PRINT_INVALID();
        return -1;
    }

    body_items = mp_decode_map(&msg);

    for (uint32_t n = 0; n < body_items; n++) {
        uint64_t key;

        if (mp_typeof(*msg) != MP_UINT) {
            ND_PRINT_INVALID();
            return -1;
        }

        key = mp_decode_uint(&msg);
        switch (key) {
        case IPROTO_TUPLE:
        {
            uint32_t items, scramble_len;
            const char *auth, *scramble;

            if (mp_typeof(*msg) != MP_ARRAY) {
                ND_PRINT_INVALID();
                return -1;
            }

            items = mp_decode_array(&msg);
            if (items != 2) {
                return -1;
            }

            if (mp_typeof(*msg) != MP_STR) {
                ND_PRINT_INVALID();
                return -1;
            }
            auth = get_string(ndo, &msg);
            if (auth) {
                ND_PRINT("\n\tAUTH: %s", auth);
            }

            if (mp_typeof(*msg) != MP_STR) {
                ND_PRINT_INVALID();
                return -1;
            }

            scramble = mp_decode_str(&msg, &scramble_len);
            if (scramble) {
                const char *scramble_encoded = base64_encode(ndo,
                        (const uint8_t *) scramble, scramble_len);
                if (scramble_encoded) {
                    ND_PRINT("\n\tSCRAMBLE: %s", scramble_encoded);
                }
            }
            break;
        }
        CASE_IPROTO_STR(USER_NAME);
        default:
            return -1;
        }
    }

    return 0;
}

/* IPROTO_RAFT body does not have unique key in enum iproto_key. */
static int
parse_raft(netdissect_options *ndo, const char *msg,
        const char *body_end, const kv_t *kv, size_t kv_len)
{
    uint32_t body_items;
    uint64_t sync, id;
    const char *p = msg;

    sync = id = 0;

    for (size_t n = 0; n < kv_len; n++) {
        switch (kv[n].key) {
        case IPROTO_SYNC:
            sync = kv[n].u.val;
            break;
        case IPROTO_GROUP_ID:
            id = kv[n].u.val;
            break;
        default:
            return -1;
        }
    }

    ND_PRINT(" request: RAFT, GROUP_ID: %" PRIu64 ", SYNC: %" PRIu64, id, sync);

    if (ndo->ndo_vflag == 0) {
        return 0;
    }

    /* Parse and print body. */
    if (mp_check(&p, body_end) != 0 || p != body_end) {
        ND_PRINT(" [|iproto]");
        return -1;
    }
    if (mp_typeof(*msg) != MP_MAP) {
        ND_PRINT_INVALID();
        return -1;
    }

    body_items = mp_decode_map(&msg);

    for (uint32_t n = 0; n < body_items; n++) {
        uint64_t key;

        if (mp_typeof(*msg) != MP_UINT) {
            ND_PRINT_INVALID();
            return -1;
        }

        key = mp_decode_uint(&msg);
        switch (key) {
            CASE_IPROTO_UINT(RAFT_TERM);
            CASE_IPROTO_UINT(RAFT_VOTE);
            CASE_IPROTO_UINT(RAFT_STATE);
            CASE_IPROTO_MAP(RAFT_VCLOCK);
        }
    }

    return 0;
}

static int parse_greeting(netdissect_options *ndo, const u_char *msg,
        u_int length)
{
    /* Try to detect a "greeting" message. */
    if (length < (sizeof(GR_NAME) - 1)) {
        return 0;
    }

    if (memcmp(msg, GR_NAME, sizeof(GR_NAME) - 1) != 0) {
        return 0;
    }

    ND_PRINT(": ");
    txtproto_print(ndo, msg, length, NULL, 0);

    return 1;
}

/*
 * +++++++++++++++++++++++++
 * |        Packet         |
 * +++++++++++++++++++++++++
 * |   size    |  MP_UINT  |
 * +++++++++++++++++++++++++
 * |  header   |  MP_MAP   |
 * +++++++++++++++++++++++++
 * |   body    |  MP_MAP   |
 * +++++++++++++++++++++++++
 *
 * size - size of the header plus the size of the body.
 */
static int
tarantool_parse(netdissect_options *ndo, const u_char *bp)
{
    const char *payload_begin = (const char *) bp;
    const char *payload = (const char *) bp;
    request_print_t print_req = NULL;
    const char *header_begin;
    uint64_t mp_len, hdr_len;
    uint32_t header_items;
    size_t kvs_len = 0;
    kv_t *kvs;

    if (mp_check((const char **) &bp, (const char *) ndo->ndo_snapend) != 0) {
        ND_PRINT(" [|iproto]");
        return -1;
    }

    if (mp_typeof(*payload) != MP_UINT) {
        ND_PRINT_INVALID();
        return -1;
    }

    mp_len = mp_decode_uint(&payload);
    if (payload + mp_len > (const char *) ndo->ndo_snapend) {
        ND_PRINT_INVALID();
        return -1;
    }
    header_begin = payload;
    hdr_len = payload - payload_begin;

    /* Parse header. */
    if (mp_typeof(*payload) != MP_MAP) {
        ND_PRINT_INVALID();
        return -1;
    }

    ND_PRINT(" size %" PRIu64 ":", mp_len + hdr_len);
    header_items = mp_decode_map(&payload);

    if (!header_items) {
        ND_PRINT_INVALID();
        return -1;
    }

    kvs = nd_malloc(ndo, header_items * sizeof(kv_t));
    if (!kvs) {
        return -1;
    }

    for (uint32_t n = 0; n < header_items; n++) {
        uint64_t key, val = 0;
        double val_d = 0;

        if (mp_typeof(*payload) != MP_UINT) {
            ND_PRINT_INVALID();
            return -1;
        }
        key = mp_decode_uint(&payload);

        switch (mp_typeof(*payload)) {
        case MP_UINT:
            val = mp_decode_uint(&payload);
            break;
        case MP_DOUBLE:
            val_d = mp_decode_double(&payload);
            break;
        default:
            ND_PRINT_INVALID();
            return -1;
        }

        if (key == IPROTO_REQUEST_TYPE) {
            struct request *res;
            struct request rkey = { .type = val };

            /* Error code is 0x8XXX */
            if (val >> 12 == 8) {
                uint32_t err = val & 0xfff;
                kvs[kvs_len].key = key;
                kvs[kvs_len].u.val = err;
                kvs_len++;
                rkey.type = IPROTO_TYPE_ERROR;
            }

            res = bsearch(&rkey, request_ops, ARR_LEN(request_ops),
                    sizeof(struct request), request_compar);
            if (res) {
                print_req = res->print;
            }

            continue; /* We do not need to store request type. */
        }

        kvs[kvs_len].key = key;
        if (val_d) {
            kvs[kvs_len].u.val_d = val_d;
        } else {
            kvs[kvs_len].u.val = val;
        }
        kvs_len++;
    }

    if (print_req) {
        const char *body_end = header_begin + mp_len;
        int rc = print_req(ndo, payload, body_end, kvs, kvs_len);

        if (rc == -1) {
            return -1;
        }

        return mp_len + hdr_len;
    }

    ND_PRINT(" UNKNOWN");
    return mp_len + hdr_len;
}

void
tarantool_print(netdissect_options *ndo, const u_char *bp, u_int length)
{
    int ret_len = 0;
    size_t mp_num = 1;

    /* Override default MP_EXT serialize and validate functions. */
    mp_snprint_ext = snprint_ext_custom;
    mp_check_ext_data = check_ext_data_custom;

    ndo->ndo_protocol = "iproto";

    /* Greeting message is not in MsgPack format. */
    if (parse_greeting(ndo, bp, length)) {
        return;
    }

    ND_PRINT(": IPROTO");
    while (length > 0) {
        ND_PRINT("\n\t%zu)", mp_num++);
        ret_len = tarantool_parse(ndo, bp);
        if (ret_len < 0) {
            return;
        }
        bp += ret_len;
        length -= ret_len;
    }
}
#endif
