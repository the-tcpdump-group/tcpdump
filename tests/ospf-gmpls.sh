#!/bin/sh

echo -n test ospf-gmpls...
if (../tcpdump -t -n -v -r ospf-gmpls.pcap | diff - ospf-gmpls.out)
then
	echo passed.
else
	echo failed.
fi
	

