#!/bin/sh

uudecode 02-sunrise-sunset-esp.puu
echo -n test esp3...
if ( ../tcpdump -t -n -E "3des-cbc-hmac96:0x4043434545464649494a4a4c4c4f4f515152525454575758" -r 02-sunrise-sunset-esp.pcap | diff - esp1.out)
then
	echo passed.
else
	echo failed.
fi

