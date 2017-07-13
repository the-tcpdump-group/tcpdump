#!/bin/sh

exitcode=0

# NFLOG support depends on both DLT_NFLOG and working <pcap/nflog.h>

if grep '^#define HAVE_PCAP_NFLOG_H 1$' ../config.h >/dev/null
then
	./TESTonce nflog-e nflog.pcap nflog-e.out '-e'
	[ $? -eq 0 ] || exitcode=1
else
	printf '    %-35s: TEST SKIPPED (compiled w/o NFLOG)\n' 'nflog-e'
fi

exit $exitcode
