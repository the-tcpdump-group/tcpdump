#!/bin/sh

uudecode eapon1.puu

echo -n test eapon1...
if (../tcpdump -r eapon1.pcap | diff - eapon1.out)
then
	echo passed.
else
	echo failed.
fi

