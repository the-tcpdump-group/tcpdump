# Makefile for cygwin gcc
# Nate Lawson <nate@rootlabs.oom>

# Location of your pcap src tree, build it first
PCAP_DIR = ../../../winpcap

# OPTFLAGS = -g
OPTFLAGS = -O
# -O2 may break things. Use at your own risk.

CFLAGS = -I ${PCAP_DIR}/wpcap/libpcap/bpf \
	-I ${PCAP_DIR}/wpcap/libpcap \
	-I ${PCAP_DIR}/wpcap/libpcap/Win32/Include \
	-I ${PCAP_DIR}/wpcap/libpcap/Win32/Include/net \
	-I ../../Win32/Include -I ../../linux-Include \
	-I ../../lbl -I../.. \
	-DWIN32 -DHAVE_ADDRINFO_H -DHAVE_PCAP_FINDALLDEVS \
	-DHAVE_PCAP_DUMP_FLUSH -DINET6 -DSIZEOF_CHAR=1 \
	-DSIZEOF_SHORT=2 -DSIZEOF_INT=4 -mno-cygwin ${OPTFLAGS}
LDFLAGS = 
LIBS = -L ${PCAP_DIR}/WPCAP/LIB -lwpcap -lwsock32
OBJS = \
	../../addrtoname.o \
	../../bpf_dump.o \
	../../gmt2local.o \
	../../missing/inet_aton.o \
	../../missing/inet_ntop.o \
	../../missing/strlcpy.o \
	../../machdep.o \
	../../parsenfsfh.o \
	../../print-802_11.o \
	../../print-ah.o \
	../../print-arcnet.o \
	../../print-arp.o \
	../../print-ascii.o \
	../../print-atalk.o \
	../../print-atm.o \
	../../print-beep.o \
	../../print-bgp.o \
	../../print-bootp.o \
	../../print-cdp.o \
	../../print-chdlc.o \
	../../print-cip.o \
	../../print-cnfp.o \
	../../print-decnet.o \
	../../print-dhcp6.o \
	../../print-domain.o \
	../../print-dvmrp.o \
	../../print-egp.o \
	../../print-esp.o \
	../../print-ether.o \
	../../print-fddi.o \
	../../print-fr.o \
	../../print-frag6.o \
	../../print-gre.o \
	../../print-hsrp.o \
	../../print-icmp.o \
	../../print-icmp6.o \
	../../print-igmp.o \
	../../print-igrp.o \
	../../print-ip.o \
	../../print-ip6.o \
	../../print-ip6opts.o \
	../../print-ipcomp.o \
	../../print-ipfc.o \
	../../print-ipx.o \
	../../print-isakmp.o \
	../../print-isoclns.o \
	../../print-krb.o \
	../../print-l2tp.o \
	../../print-lane.o \
	../../print-ldp.o \
	../../print-llc.o \
	../../print-lwres.o \
	../../print-mobile.o \
	../../print-mobility.o \
	../../print-mpls.o \
	../../print-msdp.o \
	../../print-netbios.o \
	../../print-nfs.o \
	../../print-ntp.o \
	../../print-null.o \
	../../print-ospf.o \
	../../print-ospf6.o \
	../../print-pflog.o \
	../../print-pim.o \
	../../print-ppp.o \
	../../print-pppoe.o \
	../../print-pptp.o \
	../../print-radius.o \
	../../print-raw.o \
	../../print-rip.o \
	../../print-ripng.o \
	../../print-rsvp.o \
	../../print-rt6.o \
	../../print-rx.o \
	../../print-sctp.o \
	../../print-sl.o \
	../../print-sll.o \
	../../print-smb.o \
	../../print-snmp.o \
	../../print-stp.o \
	../../print-sunatm.o \
	../../print-sunrpc.o \
	../../print-tcp.o \
	../../print-telnet.o \
	../../print-tftp.o \
	../../print-timed.o \
	../../print-token.o \
	../../print-udp.o \
	../../print-vjc.o \
	../../print-vrrp.o \
	../../print-wb.o \
	../../print-zephyr.o \
	../../setsignal.o \
	../../smbutil.o \
	../../tcpdump.o \
	../../util.o \
	../../Win32/src/getopt.o \
	../../Win32/Src/w32_fzs.o

main: ${OBJS}
	${CC} ${CFLAGS} ${LDFLAGS} -o windump.exe ${OBJS} ${LIBS}

install: windump.exe
	cp windump.exe c:/windows

clean:
	rm -f ${OBJS} windump.exe

.c.o:
	${CC} ${CFLAGS} -o $*.o -c $<
