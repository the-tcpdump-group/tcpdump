#!/bin/sh

srcdir=${SRCDIR-.}

exitcode=0
passed=`cat .passed`
failed=`cat .failed`

# Only attempt OpenSSL-specific tests when compiled with the library.

if grep '^#define HAVE_LIBCRYPTO 1$' ../config.h >/dev/null
then
	if ${srcdir}/tests/TESTonce esp1 ${srcdir}/tests/02-sunrise-sunset-esp.pcap ${srcdir}/tests/esp1.out '-E "0x12345678@192.1.2.45 3des-cbc-hmac96:0x4043434545464649494a4a4c4c4f4f515152525454575758"'
	then
		passed=`expr $passed + 1`
		echo $passed >.passed
	else
		failed=`expr $failed + 1`
		echo $failed >.failed
		exitcode=1
	fi
	if ${srcdir}/tests/TESTonce esp2 ${srcdir}/tests/08-sunrise-sunset-esp2.pcap ${srcdir}/tests/esp2.out '-E "0x12345678@192.1.2.45 3des-cbc-hmac96:0x43434545464649494a4a4c4c4f4f51515252545457575840,0xabcdabcd@192.0.1.1 3des-cbc-hmac96:0x434545464649494a4a4c4c4f4f5151525254545757584043"'
	then
		passed=`expr $passed + 1`
		echo $passed >.passed
	else
		failed=`expr $failed + 1`
		echo $failed >.failed
		exitcode=1
	fi
	if ${srcdir}/tests/TESTonce esp3 ${srcdir}/tests/02-sunrise-sunset-esp.pcap ${srcdir}/tests/esp1.out '-E "3des-cbc-hmac96:0x4043434545464649494a4a4c4c4f4f515152525454575758"'
	then
		passed=`expr $passed + 1`
		echo $passed >.passed
	else
		failed=`expr $failed + 1`
		echo $failed >.failed
		exitcode=1
	fi
	# Reading the secret(s) from a file does not work with Capsicum.
	if grep '^#define HAVE_CAPSICUM 1$' ../config.h >/dev/null
	then
		FORMAT='    %-35s: TEST SKIPPED (compiled w/Capsicum)\n'
		printf "$FORMAT" esp4
		printf "$FORMAT" esp5
		printf "$FORMAT" espudp1
		printf "$FORMAT" ikev2pI2
		printf "$FORMAT" isakmp4
	else
		if ${srcdir}/tests/TESTonce esp4 ${srcdir}/tests/08-sunrise-sunset-esp2.pcap ${srcdir}/tests/esp2.out "-E \"file ${srcdir}/tests/esp-secrets.txt\""
		then
			passed=`expr $passed + 1`
			echo $passed >.passed
		else
			failed=`expr $failed + 1`
			echo $failed >.failed
			exitcode=1
		fi
		if ${srcdir}/tests/TESTonce esp5 ${srcdir}/tests/08-sunrise-sunset-aes.pcap ${srcdir}/tests/esp5.out "-E \"file ${srcdir}/tests/esp-secrets.txt\""
		then
			passed=`expr $passed + 1`
			echo $passed >.passed
		else
			failed=`expr $failed + 1`
			echo $failed >.failed
			exitcode=1
		fi
		if ${srcdir}/tests/TESTonce espudp1 ${srcdir}/tests/espudp1.pcap ${srcdir}/tests/espudp1.out "-nnnn -E "\file ${srcdir}/tests/esp-secrets.txt\""
		then
			passed=`expr $passed + 1`
			echo $passed >.passed
		else
			failed=`expr $failed + 1`
			echo $failed >.failed
			exitcode=1
		fi
		if ${srcdir}/tests/TESTonce ikev2pI2 ${srcdir}/tests/ikev2pI2.pcap ${srcdir}/tests/ikev2pI2.out "-E \"file ${srcdir}/tests/ikev2pI2-secrets.txt\" -v -v -v -v"
		then
			passed=`expr $passed + 1`
			echo $passed >.passed
		else
			failed=`expr $failed + 1`
			echo $failed >.failed
			exitcode=1
		fi
		if ${srcdir}/tests/TESTonce isakmp4 ${srcdir}/tests/isakmp4500.pcap ${srcdir}/tests/isakmp4.out "-E \"${srcdir}/tests/file esp-secrets.txt\""
		then
			passed=`expr $passed + 1`
			echo $passed >.passed
		else
			failed=`expr $failed + 1`
			echo $failed >.failed
			exitcode=1
		fi
	fi
	if ${srcdir}/tests/TESTonce bgp-as-path-oobr-ssl ${srcdir}/tests/bgp-as-path-oobr.pcap ${srcdir}/tests/bgp-as-path-oobr-ssl.out '-vvv -e'
	then
		passed=`expr $passed + 1`
		echo $passed >.passed
	else
		failed=`expr $failed + 1`
		echo $failed >.failed
		exitcode=1
	fi
	if ${srcdir}/tests/TESTonce bgp-aigp-oobr-ssl ${srcdir}/tests/bgp-aigp-oobr.pcap ${srcdir}/tests/bgp-aigp-oobr-ssl.out '-vvv -e'
	then
		passed=`expr $passed + 1`
		echo $passed >.passed
	else
		failed=`expr $failed + 1`
		echo $failed >.failed
		exitcode=1
	fi
	FORMAT='    %-35s: TEST SKIPPED (compiled w/OpenSSL)\n'
	printf "$FORMAT" bgp-as-path-oobr-nossl
	printf "$FORMAT" bgp-aigp-oobr-nossl
else
	FORMAT='    %-35s: TEST SKIPPED (compiled w/o OpenSSL)\n'
	printf "$FORMAT" esp1
	printf "$FORMAT" esp2
	printf "$FORMAT" esp3
	printf "$FORMAT" esp4
	printf "$FORMAT" esp5
	printf "$FORMAT" espudp1
	printf "$FORMAT" ikev2pI2
	printf "$FORMAT" isakmp4
	printf "$FORMAT" bgp-as-path-oobr-ssl
	printf "$FORMAT" bgp-aigp-oobr-ssl
	if ${srcdir}/tests/TESTonce bgp-as-path-oobr-nossl ${srcdir}/tests/bgp-as-path-oobr.pcap ${srcdir}/tests/bgp-as-path-oobr-nossl.out '-vvv -e'
	then
		passed=`expr $passed + 1`
		echo $passed >.passed
	else
		failed=`expr $failed + 1`
		echo $failed >.failed
		exitcode=1
	fi
	if ${srcdir}/tests/TESTonce bgp-aigp-oobr-nossl ${srcdir}/tests/bgp-aigp-oobr.pcap ${srcdir}/tests/bgp-aigp-oobr-nossl.out '-vvv -e'
	then
		passed=`expr $passed + 1`
		echo $passed >.passed
	else
		failed=`expr $failed + 1`
		echo $failed >.failed
		exitcode=1
	fi
fi

exit $exitcode
