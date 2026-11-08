#!/usr/bin/env perl
#
# usage:
#	setkey -D | perl thisfile > secrets.txt
#	tcpdump -n -E "file secrets.txt"
#

use strict;
use warnings FATAL => qw(uninitialized);

my ($src, $dst, $spi);

while (<>) {
	if (/^(\S+)\s+(\S+)/o) {
		$src = $1;
		$dst = $2;
	} elsif (/^\s+esp.*spi=(\d+)/o) {
		$spi = $1;
	} elsif (/^\s+E:\s+(\S+)\s+(.*)$/o) {
		my $algo = $1 . '-hmac96';
		my $secret = $2;
		$secret =~ s/\s+//go;
		printf "0x%x@%s %s:0x%s\n", $spi, $dst, $algo, $secret;
	}
}
