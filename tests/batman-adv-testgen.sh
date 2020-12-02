#!/bin/sh

# Prerequisites:
# - userspace tools: batctl, ip (iproute2), tcpdump, ping6, dhclient (ISC)
# - kernel: batman-adv compiled with BATMAN_V and multicast optimizations support
#           + veth + IPv6

setup() {
	local algo="$1"

	[ -z "$algo" ] && algo="BATMAN_IV"

	batctl routing_algo "$algo"
	ip link add bat0 type batadv
	ip link add bat1 type batadv
	ip link add bat2 type batadv

	batctl meshif bat0 gw client
	batctl meshif bat1 gw server

	batctl meshif bat0 orig_interval 5000
	batctl meshif bat1 orig_interval 5000
	batctl meshif bat2 orig_interval 5000

	ip link add vethbat0 type veth peer name vethbat1
	batctl meshif bat0 interface add vethbat0
	batctl meshif bat1 interface add vethbat1

	[ "$algo" = "BATMAN_V" ] && {
		batctl hardif vethbat0 elp_interval 2500
		batctl hardif vethbat1 elp_interval 2500
	}

	echo 1 > /proc/sys/net/ipv6/conf/vethbat0/disable_ipv6
	echo 1 > /proc/sys/net/ipv6/conf/vethbat1/disable_ipv6
	echo 1 > /proc/sys/net/ipv6/conf/bat0/disable_ipv6
	echo 1 > /proc/sys/net/ipv6/conf/bat1/disable_ipv6
	echo 1 > /proc/sys/net/ipv6/conf/bat2/disable_ipv6

	ip link set up dev vethbat0 address 02:00:00:00:00:01
	ip link set up dev vethbat1 address 02:00:00:00:00:02
	ip link set up dev bat0 address 02:00:00:00:01:01
	ip link set up dev bat1 address 02:00:00:00:01:02
}

teardown() {
	ip link del bat0
	ip link del bat1
	ip link del bat2

	ip link del vethbat0
}

testrun() {
	local file="$1"
	local tcpdpid
	local dhclpid

	echo 0 > /proc/sys/net/ipv6/conf/bat0/disable_ipv6
	echo 0 > /proc/sys/net/ipv6/conf/bat1/disable_ipv6
	sleep 30

	tcpdump -i vethbat0 -w "$file" &
	tcpdpid=$!
	sleep 5

	echo "~~~ Test 1 ~~~~"
	echo "Description: Multicast ICMPv6 Echo Request in batadv unicast packet"
	echo "pcap-filter: batadv 15 unicast and ip6 dst ff02::1 and icmp6 and icmp6[icmp6type] = icmp6-echo"
	echo ""
	ping6 -c 3 ff02::1%bat0
	sleep 2

	echo "~~~ Test 2 ~~~~"
	echo "Description: Multicast ICMPv6 Echo Request in batadv broadcast packet"
	echo "pcap-filter: batadv 15 bcast and ip6 dst ff02::1 and icmp6 and icmp6[icmp6type] = icmp6-echo"
	echo ""
	batctl meshif bat0 multicast_forceflood 1
	batctl meshif bat1 multicast_forceflood 1
	ping6 -c 3 ff02::1%bat0
	batctl meshif bat0 multicast_forceflood 0
	batctl meshif bat1 multicast_forceflood 0
	sleep 2

	echo "~~~ Test 3 ~~~~"
	echo "Description: Unicast ICMPv6 Echo Request in batadv unicast packet"
	echo "pcap-filter: batadv 15 unicast and ip6 dst fe80::ff:fe00:102 and icmp6 and icmp6[icmp6type] = icmp6-echo"
	echo ""
	ping6 -c 3 fe80::ff:fe00:102%bat0
	sleep 2

	echo "~~~ Test 4 ~~~~"
	echo "Description: Unicast ICMPv6 Echo Request in batadv unicast fragment packet"
	echo "pcap-filter: batadv 15 unicast_frag"
	echo ""
	ping6 -c 3 -M do -s 1452 fe80::ff:fe00:102%bat0
	sleep 5

	echo "~~~ Test 5 ~~~~"
	echo "Description: DHCPv4 Discover in batadv unicast 4addr packet"
	echo "pcap-filter: batadv 15 unicast_4addr and ip and udp dst port 67"
	echo ""
	dhclient -d -v -lf /dev/null -pf /dev/null bat0 &
	dhclpid=$!
	sleep 5

	kill $dhclpid
	sleep 5

	echo "~~~ Test 6 ~~~~"
	echo "Description: batadv translation table request/response in batadv unicast tvlv packet"
	echo "             triggered by an already running node which gets in range"
	echo "pcap-filter: batadv 15 unicast_tvlv"
	echo ""
	batctl meshif bat1 interface del vethbat1
	batctl meshif bat2 interface add vethbat1
	ip link set up dev bat2 address 02:00:00:00:01:03
	sleep 15

	echo "~~~ Test 7 ~~~"
	echo "Description: Periodic originator messages for BATMAN_IV from 02:00:00:00:01:01"
	echo "pcap-filter: batadv 15 iv_ogm && ether[22:2] = 0x0200 and ether[24:2] = 0x0000 and ether[26:2] = 0x0001"
	echo ""

	echo "~~~ Test 8 ~~~"
	echo "Description: Periodic originator messages for BATMAN_V from 02:00:00:00:01:02"
	echo "pcap-filter: batadv 15 ogm2 && ether[22:2] = 0x0200 and ether[24:2] = 0x0000 and ether[26:2] = 0x0002"
	echo ""

	echo "~~~ Test 9 ~~~"
	echo "Description: Periodic Echo-Location-Protocol messages for BATMAN_V from 02:00:00:00:01:02"
	echo "pcap-filter: batadv 15 elp && ether[16:2] = 0x0200 and ether[18:2] = 0x0000 and ether[20:2] = 0x0002"
	echo ""

	kill $tcpdpid
}

if [ $# -ge 1 ]; then
	cmd="$1"
	shift
else
	cmd=""
fi

case "$cmd" in
  setup)
	setup $@
	exit 0
	;;
  teardown)
	teardown
	exit 0
	;;
  testrun)
	testrun $@
	exit 0
	;;
esac

teardown
setup BATMAN_IV
testrun batman-adv-15-iv.pcap

teardown
setup BATMAN_V
testrun batman-adv-15-v.pcap
