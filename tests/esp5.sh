#!/bin/sh

uudecode 08-sunrise-sunset-aes.puu

echo -n test esp5...
if (../tcpdump -t -n -E "file esp-secrets.txt" -r 08-sunrise-sunset-aes.pcap | diff - esp5.out)
then
	echo passed.
else
	echo failed.
fi

