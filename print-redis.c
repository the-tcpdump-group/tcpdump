/*
 * This file implements decoding of the REdis Serialization Protocol.
 *
 *
 * Copyright (c) 2015 The TCPDUMP project
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
 * Initial contribution by Andrew Darqui (andrew.darqui@gmail.com).
 */

#define NETDISSECT_REWORKED
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <tcpdump-stdinc.h>

#include <string.h>
#include <stdlib.h>

#include "interface.h"
#include "extract.h"

static char tstr[] = " [|RESP]";

/*
 * For information regarding RESP, see: http://redis.io/topics/protocol
 */

#define REDIS_RESP_SIMPLE_STRING    '+'
#define REDIS_RESP_ERROR            '-'
#define REDIS_RESP_INTEGER          ':'
#define REDIS_RESP_BULK_STRING      '$'
#define REDIS_RESP_ARRAY            '*'

#define redis_print_empty(ndo)      ND_PRINT((ndo, " empty"))
#define redis_print_null(ndo)       ND_PRINT((ndo, " null"))
#define redis_print_invalid(ndo)    ND_PRINT((ndo, " invalid"))

void       redis_print(netdissect_options *, register const u_char *, int);
static int redis_parse(netdissect_options *, register const u_char *, int);
static int redis_print_string_error_integer(netdissect_options *, register const u_char *, int);
static int redis_print_simple_string(netdissect_options *, register const u_char *, int);
static int redis_print_integer(netdissect_options *, register const u_char *, int);
static int redis_print_error(netdissect_options *, register const u_char *, int);
static int redis_print_bulk_string(netdissect_options *, register const u_char *, int);
static int redis_print_bulk_array(netdissect_options *, register const u_char *, int);
static int redis_print_inline(netdissect_options *, register const u_char *, int);

/*
 * MOVE_FORWARD:
 * Attempts to move our 'ptr' forward until a \r\n is found,
 * while also making sure we don't exceed the buffer 'len.
 * If we exceed, jump to trunc.
 */
#define MOVE_FORWARD(ptr, len) \
    while(*ptr != '\r' && *(ptr+1) != '\n') { ND_TCHECK2(*ptr, 2); ptr++; len--; }

/*
 * MOVE_FORWARD_CR_OR_LF
 * Attempts to move our 'ptr' forward until a \r or \n is found,
 * while also making sure we don't exceed the buffer 'len'.
 * If we exceed, jump to trunc.
 */
#define MOVE_FORWARD_CR_OR_LF(ptr, len) \
    while(*ptr != '\r' && *ptr != '\n') { ND_TCHECK(*ptr);  ptr++; len--; }

/*
 * CONSUME_CR_OR_LF
 * Consume all consecutive \r and \n bytes.
 * If we exceed 'len', jump to trunc.
 */
#define CONSUME_CR_OR_LF(ptr, len) \
    while (*ptr == '\r' || *ptr == '\n') { ND_TCHECK(*ptr); ptr++; len--; }

/*
 * INCBY
 * Attempts to increment our 'ptr' by 'increment' bytes.
 * If our increment exceeds the buffer length (len - increment),
 * bail out by jumping to the trunc goto tag.
 */
#define INCBY(ptr, increment, len) \
    { ND_TCHECK2(*ptr, increment); ptr+=increment; len-=increment; }

/*
 * INC1
 * Increment our ptr by 1 byte.
 * Most often used to skip an opcode (+-:*$ etc)
 */
#define INC1(ptr, len) INCBY(ptr, 1, len)

/*
 * INC2
 * Increment our ptr by 2 bytes.
 * Most often used to skip CRLF (\r\n).
 */
#define INC2(ptr, len) INCBY(ptr, 2, len)

/*
 * TESTRL
 * If ret_len is < 0, jump to the trunc tag which returns (-1)
 * and 'bubbles up' to printing tstr. Otherwise, return ret_len.
 */
#define TESTRL(rl) \
    if (rl < 0) { goto trunc; } else { return rl; }

/*
 * TESTRLVOID
 * Similar to TESTRL.
 * Used to simply return in a void function.
 */
#define TESTRLVOID(rl) \
    if (rl < 0) { goto trunc; } else { return; }

#define TESTRLVOID_NORETURN(rl) \
    if (rl < 0) { goto trunc; }

void
redis_print(netdissect_options *ndo, register const u_char *bp, int length)
{
    int ret_len = 0, ret_len_accum = 0;

    if(!bp || length <= 0)
        return;

    ND_PRINT((ndo, ": RESP"));
    do {
        /*
         * This block supports redis pipelining.
         * For example, multiple operations can be pipelined within the same string:
         * "*2\r\n\$4\r\nINCR\r\n\$1\r\nz\r\n*2\r\n\$4\r\nINCR\r\n\$1\r\nz\r\n*2\r\n\$4\r\nINCR\r\n\$1\r\nz\r\n"
         * or
         * "PING\r\nPING\r\nPING\r\n"*
         * In order to handle this case, we must try and parse 'bp' until
         * 'length' bytes have been processed or we reach a trunc condition.
         */
        ret_len = redis_parse(ndo, bp + ret_len_accum, length - ret_len_accum);
        TESTRLVOID_NORETURN(ret_len);
        ret_len_accum += ret_len;
    } while (ret_len > 0 && ret_len_accum < length);

    return;

trunc:
    ND_PRINT((ndo, "%s", tstr));
}

static int
redis_parse(netdissect_options *ndo, register const u_char *bp, int length)
{
    int ret_len = 0;
    u_char op = *bp;

    ND_TCHECK(*bp);

    switch(op) {
        case REDIS_RESP_SIMPLE_STRING:  ret_len = redis_print_simple_string(ndo, bp, length);   break;
        case REDIS_RESP_INTEGER:        ret_len = redis_print_integer(ndo, bp, length);         break;
        case REDIS_RESP_ERROR:          ret_len = redis_print_error(ndo, bp, length);           break;
        case REDIS_RESP_BULK_STRING:    ret_len = redis_print_bulk_string(ndo, bp, length);     break;
        case REDIS_RESP_ARRAY:          ret_len = redis_print_bulk_array(ndo, bp, length);      break;
        default:                        ret_len = redis_print_inline(ndo, bp, length);          break;
    }

    TESTRL(ret_len);

trunc:
    return (-1);
}

static int
redis_print_simple_string(netdissect_options *ndo, register const u_char *bp, int length) {
    return redis_print_string_error_integer(ndo, bp, length);
}

static int
redis_print_integer(netdissect_options *ndo, register const u_char *bp, int length) {
    return redis_print_string_error_integer(ndo, bp, length);
}

static int
redis_print_error(netdissect_options *ndo, register const u_char *bp, int length) {
    return redis_print_string_error_integer(ndo, bp, length);
}

static int
redis_print_string_error_integer(netdissect_options *ndo, register const u_char *bp, int length) {
    int length_cur = length, len, ret_len = 0;
    u_char *bp_ptr = (u_char *)bp;

    /*
     * MOVE_FORWARD moves past the string that follows the (+-;) opcodes
     * +OK\r\n
     * -ERR ...\r\n
     * :02912309\r\n
     */
    MOVE_FORWARD(bp_ptr, length_cur);
    len = (bp_ptr - bp);
    ND_TCHECK2(*bp, len);
    ND_PRINT((ndo, " \"%.*s\"", len-1, bp+1));
    ret_len = len /*<1byte>+<string>*/ + 2 /*<CRLF>*/;

    TESTRL(ret_len);

trunc:
    return (-1);
}

static int
redis_print_bulk_string(netdissect_options *ndo, register const u_char *bp, int length) {
    int length_cur = length, string_len;

    ND_TCHECK(*bp);

    // '$'
    INC1(bp, length_cur);
    ND_TCHECK(*bp);

    // <length>
    string_len = atoi((char *)bp);

    // move to \r\n
    MOVE_FORWARD(bp, length_cur);

    // \r\n
    INC2(bp, length_cur);

    if (string_len > 0) {
        /* Byte string of length string_len */
        ND_TCHECK2(*bp, string_len);
        ND_PRINT((ndo, " \"%.*s\"", string_len, bp));
    } else {
        switch(string_len) {
            case 0: redis_print_empty(ndo); break;
            case (-1): {
                /* This is the NULL response. It follows a different pattern: $-1\r\n */
                redis_print_null(ndo);
                TESTRL(length - length_cur);
                // returned ret_len or jumped to trunc
            }
            default: redis_print_invalid(ndo); break;
        }
    }

    // <string>
    INCBY(bp, string_len, length_cur);

    // \r\n
    INC2(bp, length_cur);

    TESTRL(length - length_cur);

trunc:
    return (-1);
}

static int
redis_print_bulk_array(netdissect_options *ndo, register const u_char *bp, int length) {
    int length_cur = length, array_len, i, ret_len = 0;

    ND_TCHECK(*bp);

    // '*'
    INC1(bp, length_cur);
    ND_TCHECK(*bp);

    // <array_length>
    array_len = atoi((char *)bp);

    // move to \r\n
    MOVE_FORWARD(bp, length_cur);

    // \r\n
    INC2(bp, length_cur);

    if (array_len > 0) {
        /* non empty array */
        for (i = 0; i < array_len; i++) {
            ret_len = redis_parse(ndo, bp + ret_len, length_cur - ret_len) + ret_len;
            if (ret_len < 0) {
                goto trunc;
            }
        }
    } else {
        /* empty or invalid */
        switch(array_len) {
            case 0:     redis_print_empty(ndo);   break;
            case (-1):  redis_print_null(ndo);    break;
            default:    redis_print_invalid(ndo); break;
        }
    }

    ret_len += (length - length_cur);

    TESTRL(ret_len);

trunc:
    return (-1);
}

static int
redis_print_inline(netdissect_options *ndo, register const u_char *bp, int length) {
    int length_cur = length, len;
    u_char *bp_ptr;

    /*
     * Inline commands are simply 'strings' followed by \r or \n or both.
     * Redis will do it's best to split/parse these string.
     * This feature of redis is implemented to support the ability of
     * command parsing from telnet/nc sessions etc.
     *
     * <string><\r||\n||\r\n...>
     */
    CONSUME_CR_OR_LF(bp, length_cur);
    bp_ptr = (u_char *)bp;
    MOVE_FORWARD_CR_OR_LF(bp_ptr, length_cur);
    len = (bp_ptr - bp);
    ND_TCHECK2(*bp, len);
    ND_PRINT((ndo, " \"%.*s\"", len, bp));
    CONSUME_CR_OR_LF(bp_ptr, length_cur);

    TESTRL(length - length_cur);

trunc:
    redis_print_invalid(ndo);
    return (-1);
}
