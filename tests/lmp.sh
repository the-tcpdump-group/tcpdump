#!/bin/sh

echo -n test lmp ...
if (../tcpdump -t -n -v -r lmp.pcap | diff - lmp.out)
then
	echo passed.
else
	echo failed.
fi
	

