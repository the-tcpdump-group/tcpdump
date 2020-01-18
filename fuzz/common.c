/*
 * Copyright (c) 2019
 *      Arista Networks, Inc.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include "netdissect-alloc.h"

netdissect_options *ndo;

/*
 * When fuzzing, we end up sometimes getting EINTR from printf,
 * so instead, we sprintf (to make sure that we format the args)
 * and then discard that string.
 */
static int
ndo_mysprintf(netdissect_options *ndo, const char *fmt, ...)
{
    va_list args;
    int ret;
    char buf[1000];

    va_start(args, fmt);
    ret = vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    return (ret);
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    ndo = calloc(1, sizeof(netdissect_options));
    ndo_set_function_pointers(ndo);
    if (!getenv("TCPDUMP_PRINT")) {
        /* If we're replicating, we do want to print so it's easier to
         * see where the failure is, but if we're fuzzing, we want to
         * just use sprintf to avoid the EINTR */
        ndo->ndo_printf = ndo_mysprintf;
    }
    ndo->program_name = "fuzztcpdump";
    ndo->ndo_nflag = 1;      // don't try to look up addresses
    ndo->ndo_vflag = 2;      // decode as much as we can
    return 0;
}

void
fuzz_common(int (*fuzzfunc)(const uint8_t *, size_t), const uint8_t *data, size_t size) {
    /*
     * longjmp-based truncation: if the infrastructure detects
     * truncation, it longjmps to here.
     */
    if (setjmp(ndo->ndo_truncated) == 0) {
	fuzzfunc(data, size);
    } else {
	ND_PRINT(" [|%s]", ndo->ndo_protocol);
	return;
    }
    if (getenv("REPLICATE_TRUNCATE")) {
	size_t i;
	uint8_t *data2;
	printf("original size %u\n", (unsigned)size);
	for (i = size - 1; i > 1; i--) {
	    printf("trying again with size %u\n", (unsigned)i);
	    data2 = malloc(i);
	    memcpy(data2, data, i);
	    fuzzfunc(data2, i);
	    free(data2);
	}
    }
    /*
     * If the printer allocated any memory, free it.
     */
    nd_free_all(ndo);
}
