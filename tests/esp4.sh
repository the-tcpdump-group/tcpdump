#!/bin/sh

uudecode 08-sunrise-sunset-esp2.puu

echo -n test esp2...
if (../tcpdump -t -n -E "file esp-secrets.txt" -r 08-sunrise-sunset-esp2.pcap | diff - esp2.out)
then
	echo passed.
else
	echo failed.
fi

