#!/bin/sh

echo -n test mpls-ldp-hello ...
if (../tcpdump -t -n -v -r mpls-ldp-hello.pcap | diff - mpls-ldp-hello.out)
then
	echo passed.
else
	echo failed.
fi
	

