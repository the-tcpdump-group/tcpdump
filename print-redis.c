/*
 * Copyright (c) 2000 Ben Smithurst <ben@scientia.demon.co.uk>
 * All rights reserved.
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
 * print-redis.c -- github.com/adarqui
 */

#ifndef lint
static const char rcsid[] _U_ =
    "@(#) $Header: /tcpdump/master/tcpdump/print-redis.c,v 1.9 2003-11-16 09:36:40 guy Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <tcpdump-stdinc.h>

#include <stdio.h>
#include <string.h>

#include "redis.h"
#include "interface.h"
#include "extract.h"

/*
typedef struct LIST {
    void *data;
    struct LIST *next;
} list_t;
*/

#define MOVE_FORWARD(x, len) while(*x != '\r' && *(x+1) != '\n' && len >= 0) x++, len--
#define INC(x, y, len) if((len - y) < 0) { break; } else { x+=y; len-=y; }

void
redis_print(register const u_char *bp, int length)
{
/*

http://redis.io/topics/protocol

EXAMPLE:

*<number of arguments> CR LF
$<number of bytes of argument 1> CR LF
<argument data> CR LF
...
$<number of bytes of argument N> CR LF
<argument data> CR LF

*3
$3
SET
$5
mykey
$7
myvalue
*/

    int length_cur = length, i, argc = 0, len_arg, data_len;

    u_char *bp_ptr = bp, *str_args, *data_ptr;

    putchar('\n');
    while(1) {

	/* *<num_args>\r\n */
	if (*bp_ptr != '*') { break; }

	INC(bp_ptr, 1, length_cur);
	argc = atoi(bp_ptr);

	MOVE_FORWARD(bp_ptr, length_cur);

	INC(bp_ptr, 2, length_cur);

	for(i = 0; i < argc; i++) {

	    if(*bp_ptr != '$') { length_cur = 0; break; }
	    INC(bp_ptr, 1, length_cur);
	    data_len = atoi(bp_ptr);
	    MOVE_FORWARD(bp_ptr, length_cur);
	    INC(bp_ptr, 2, length_cur);
	    data_ptr = bp_ptr;
	    INC(bp_ptr, data_len, length_cur);

	    printf("%.*s,", data_len, data_ptr);
	    INC(bp_ptr, 2, length_cur);
	}

	if(length_cur <= 0) break;
    }

    puts("");
    return;
}
