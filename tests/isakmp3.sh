#!/bin/sh

uudecode isakmp-identification-segfault.puu

echo -n test isakmp3...
if (../tcpdump -t -v -n -r isakmp-identification-segfault.pcap | diff - isakmp3.out)
then
	echo passed.
else
	echo failed.
fi

