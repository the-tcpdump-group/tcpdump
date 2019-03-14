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

#include "common.h"

extern netdissect_options *ndo;

int ip6_print_fuzz(const uint8_t *data, size_t size) {
    int fakelen = 10000;

    ndo->ndo_snapend = data + size;
    if (fakelen < size) {
        fakelen = size;
    }
    ip6_print(ndo, data, fakelen);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    fuzz_common(ip6_print_fuzz, data, size);
    return 0;
}
