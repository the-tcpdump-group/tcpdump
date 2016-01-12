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

#include <netdissect-stdinc.h>
#include "netdissect.h"

#include <string.h>
#include <stdlib.h>

#include "extract.h"

static const char tstr[] = " [|RESP]";

/*
 * For information regarding RESP, see: http://redis.io/topics/protocol
 */

#define RESP_SIMPLE_STRING    '+'
#define RESP_ERROR            '-'
#define RESP_INTEGER          ':'
#define RESP_BULK_STRING      '$'
#define RESP_ARRAY            '*'

#define resp_print_empty(ndo)      ND_PRINT((ndo, " empty"))
#define resp_print_null(ndo)       ND_PRINT((ndo, " null"))
#define resp_print_invalid(ndo)    ND_PRINT((ndo, " invalid"))

void       resp_print(netdissect_options *, const u_char *, u_int);
static int resp_parse(netdissect_options *, register const u_char *, int);
static int resp_print_string_error_integer(netdissect_options *, register const u_char *, int);
static int resp_print_simple_string(netdissect_options *, register const u_char *, int);
static int resp_print_integer(netdissect_options *, register const u_char *, int);
static int resp_print_error(netdissect_options *, register const u_char *, int);
static int resp_print_bulk_string(netdissect_options *, register const u_char *, int);
static int resp_print_bulk_array(netdissect_options *, register const u_char *, int);
static int resp_print_inline(netdissect_options *, register const u_char *, int);

/*
 * MOVE_FORWARD:
 * Attempts to move our 'ptr' forward until a \r\n is found,
 * while also making sure we don't exceed the buffer 'len'.
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
    while(*ptr != '\r' && *ptr != '\n') { ND_TCHECK(*ptr); ptr++; len--; }

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
 * TEST_RET_LEN
 * If ret_len is < 0, jump to the trunc tag which returns (-1)
 * and 'bubbles up' to printing tstr. Otherwise, return ret_len.
 */
#define TEST_RET_LEN(rl) \
    if (rl < 0) { goto trunc; } else { return rl; }

/*
 * TEST_RET_LEN_NORETURN
 * If ret_len is < 0, jump to the trunc tag which returns (-1)
 * and 'bubbles up' to printing tstr. Otherwise, continue onward.
 */
#define TEST_RET_LEN_NORETURN(rl) \
    if (rl < 0) { goto trunc; }

/*
 * RESP_PRINT_SEGMENT
 * Prints a segment in the form of: ' "<stuff>"\n"
 */
#define RESP_PRINT_SEGMENT(_ndo, _bp, _len)            \
        ND_PRINT((_ndo, " \""));                       \
        fn_printn(_ndo, _bp, _len, _ndo->ndo_snapend); \
        fn_print_char(_ndo, '"');

void
resp_print(netdissect_options *ndo, const u_char *bp, u_int length)
{
    int ret_len = 0, length_cur = length;

    if(!bp || length <= 0)
        return;

    ND_PRINT((ndo, ": RESP"));
    while (length_cur > 0) {
        /*
         * This block supports redis pipelining.
         * For example, multiple operations can be pipelined within the same string:
         * "*2\r\n\$4\r\nINCR\r\n\$1\r\nz\r\n*2\r\n\$4\r\nINCR\r\n\$1\r\nz\r\n*2\r\n\$4\r\nINCR\r\n\$1\r\nz\r\n"
         * or
         * "PING\r\nPING\r\nPING\r\n"
         * In order to handle this case, we must try and parse 'bp' until
         * 'length' bytes have been processed or we reach a trunc condition.
         */
        ret_len = resp_parse(ndo, bp, length_cur);
        TEST_RET_LEN_NORETURN(ret_len);
        bp += ret_len;
        length_cur -= ret_len;
    }

    return;

trunc:
    ND_PRINT((ndo, "%s", tstr));
}

static int
resp_parse(netdissect_options *ndo, register const u_char *bp, int length)
{
    int ret_len = 0;
    u_char op = *bp;

    ND_TCHECK(*bp);

    switch(op) {
        case RESP_SIMPLE_STRING:  ret_len = resp_print_simple_string(ndo, bp, length);   break;
        case RESP_INTEGER:        ret_len = resp_print_integer(ndo, bp, length);         break;
        case RESP_ERROR:          ret_len = resp_print_error(ndo, bp, length);           break;
        case RESP_BULK_STRING:    ret_len = resp_print_bulk_string(ndo, bp, length);     break;
        case RESP_ARRAY:          ret_len = resp_print_bulk_array(ndo, bp, length);      break;
        default:                  ret_len = resp_print_inline(ndo, bp, length);          break;
    }

    TEST_RET_LEN(ret_len);

trunc:
    return (-1);
}

static int
resp_print_simple_string(netdissect_options *ndo, register const u_char *bp, int length) {
    return resp_print_string_error_integer(ndo, bp, length);
}

static int
resp_print_integer(netdissect_options *ndo, register const u_char *bp, int length) {
    return resp_print_string_error_integer(ndo, bp, length);
}

static int
resp_print_error(netdissect_options *ndo, register const u_char *bp, int length) {
    return resp_print_string_error_integer(ndo, bp, length);
}

static int
resp_print_string_error_integer(netdissect_options *ndo, register const u_char *bp, int length) {
    int length_cur = length, len, ret_len = 0;
    const u_char *bp_ptr = bp;

    /*
     * MOVE_FORWARD moves past the string that follows the (+-;) opcodes
     * +OK\r\n
     * -ERR ...\r\n
     * :02912309\r\n
     */
    MOVE_FORWARD(bp_ptr, length_cur);
    len = (bp_ptr - bp);
    ND_TCHECK2(*bp, len);
    RESP_PRINT_SEGMENT(ndo, bp+1, len-1);
    ret_len = len /*<1byte>+<string>*/ + 2 /*<CRLF>*/;

    TEST_RET_LEN(ret_len);

trunc:
    return (-1);
}

static int
resp_print_bulk_string(netdissect_options *ndo, register const u_char *bp, int length) {
    int length_cur = length, string_len;

    ND_TCHECK(*bp);

    /* opcode: '$' */
    INC1(bp, length_cur);
    ND_TCHECK(*bp);

    /* <length> */
    string_len = atoi((const char *)bp);

    /* move to \r\n */
    MOVE_FORWARD(bp, length_cur);

    /* \r\n */
    INC2(bp, length_cur);

    if (string_len > 0) {
        /* Byte string of length string_len */
        ND_TCHECK2(*bp, string_len);
        RESP_PRINT_SEGMENT(ndo, bp, string_len);
    } else {
        switch(string_len) {
            case 0: resp_print_empty(ndo); break;
            case (-1): {
                /* This is the NULL response. It follows a different pattern: $-1\r\n */
                resp_print_null(ndo);
                TEST_RET_LEN(length - length_cur);
                /* returned ret_len or jumped to trunc */
            }
            default: resp_print_invalid(ndo); break;
        }
    }

    /* <string> */
    INCBY(bp, string_len, length_cur);

    /* \r\n */
    INC2(bp, length_cur);

    TEST_RET_LEN(length - length_cur);

trunc:
    return (-1);
}

static int
resp_print_bulk_array(netdissect_options *ndo, register const u_char *bp, int length) {
    int length_cur = length, array_len, i, ret_len = 0;

    ND_TCHECK(*bp);

    /* opcode: '*' */
    INC1(bp, length_cur);
    ND_TCHECK(*bp);

    /* <array_length> */
    array_len = atoi((const char *)bp);

    /* move to \r\n */
    MOVE_FORWARD(bp, length_cur);

    /* \r\n */
    INC2(bp, length_cur);

    if (array_len > 0) {
        /* non empty array */
        for (i = 0; i < array_len; i++) {
            ret_len = resp_parse(ndo, bp, length_cur);

            TEST_RET_LEN_NORETURN(ret_len);

            bp += ret_len;
            length_cur -= ret_len;

            TEST_RET_LEN_NORETURN(length - length_cur);
        }
    } else {
        /* empty, null, or invalid */
        switch(array_len) {
            case 0:     resp_print_empty(ndo);   break;
            case (-1):  resp_print_null(ndo);    break;
            default:    resp_print_invalid(ndo); break;
        }
    }

    TEST_RET_LEN(length - length_cur);

trunc:
    return (-1);
}

static int
resp_print_inline(netdissect_options *ndo, register const u_char *bp, int length) {
    int length_cur = length, len;
    const u_char *bp_ptr;

    /*
     * Inline commands are simply 'strings' followed by \r or \n or both.
     * Redis will do it's best to split/parse these strings.
     * This feature of redis is implemented to support the ability of
     * command parsing from telnet/nc sessions etc.
     *
     * <string><\r||\n||\r\n...>
     */
    CONSUME_CR_OR_LF(bp, length_cur);
    bp_ptr = bp;
    MOVE_FORWARD_CR_OR_LF(bp_ptr, length_cur);
    len = (bp_ptr - bp);
    ND_TCHECK2(*bp, len);
    RESP_PRINT_SEGMENT(ndo, bp, len);
    CONSUME_CR_OR_LF(bp_ptr, length_cur);

    TEST_RET_LEN(length - length_cur);

trunc:
    return (-1);
}
