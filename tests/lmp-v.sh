#!/bin/sh

# The "verbose" Link Management Protocol test involves a float calculation that
# may produce a slightly different result depending on the architecture and the
# compiler (see GitHub issue #333). The reference output was produced using a
# GCC build and must reproduce correctly on any other GCC build regardless of
# the architecture.

if ! grep -qe '^CC = gcc$' ../Makefile
then
	printf '%-30s: TEST SKIPPED (compiler is not GCC)\n' 'lmp-v'
	exit 0
fi

./TESTonce lmp-v lmp.pcap lmp-v.out '-t -T lmp -v'
