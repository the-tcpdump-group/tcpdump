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
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>

int LLVMFuzzerInitialize( int *argc, char ***argv );
int LLVMFuzzerTestOneInput( const uint8_t *, size_t );

int
main( int argc, char **argv ) {
    FILE *f;
    uint8_t *data;
    size_t len;
    char *filename;
    LLVMFuzzerInitialize( &argc, &argv );
    if ( argc != 2 ) {
	fprintf( stderr, "Usage: %s <input file>\n", argv[ 0 ] );
	return 1;
    }
    filename = argv[ 1 ];
    f = fopen( filename, "r" );
    if ( f == NULL ) {
	fprintf( stderr, "%s: %s\n", filename, strerror( errno ) );
	return 1;
    }
    fseek( f, 0, SEEK_END );
    len = ftell( f );
    rewind( f );
    data = malloc( len );
    if ( data == NULL ) {
	fprintf( stderr, "could not allocate %u bytes to read %s\n", (unsigned)len, filename );
	return 1;
    }
    if ( fread( data, len, 1, f ) != 1 ) {
	fprintf( stderr, "failed to read all the data from %s\n", filename );
	return 1;
    }
    fclose( f );
    LLVMFuzzerTestOneInput( data, len );
}
