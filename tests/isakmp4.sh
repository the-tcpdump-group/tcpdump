#!/bin/sh

uudecode isakmp4500.puu

echo -n test isakmp4...
../tcpdump -t -n -E "file esp-secrets.txt" -r isakmp4500.pcap >isakmp4500.new
if diff isakmp4500.new isakmp4500.out
then
	echo passed.
else
	echo failed.
fi

