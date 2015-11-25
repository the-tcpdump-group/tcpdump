#!/bin/sh

# NFLOG support depends on both DLT_NFLOG and working <pcap/nflog.h>

if grep '^#define HAVE_PCAP_NFLOG_H 1$' ../config.h >/dev/null
then
  ./TESTonce nflog_print-vvv nflog_print.pcap nflog_print-vvv.out '-t -vvv'
else
	printf '    %-30s: TEST SKIPPED (compiled w/o NFLOG)\n' 'nflog_print'
fi
