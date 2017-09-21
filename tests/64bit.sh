#!/bin/sh

exitcode=0
passed=`cat .passed`
failed=`cat .failed`

# Only attempt tests with times outside the range of 32-bit time_t
# when running on a 64-bit processor.

if file ../tcpdump | egrep '64|PA-RISC2.0' >/dev/null
then
	#
	# The file type of tcpdump contains the number 64 or the string
	# "PA-RISC2.0"; we'll assume that means it's a 64-bit executable.
	#
	if ./TESTonce ntp ntp.pcap ntp.out ""
	then
		passed=`expr $passed + 1`
		echo $passed >.passed
	else
		failed=`expr $failed + 1`
		echo $failed >.failed
		exitcode=1
	fi
	#
	# The file type of tcpdump contains the number 64 or the string
	# "PA-RISC2.0"; we'll assume that means it's a 64-bit executable.
	#
	if ./TESTonce ntp ntp.pcap ntp-v.out -v
	then
		passed=`expr $passed + 1`
		echo $passed >.passed
	else
		failed=`expr $failed + 1`
		echo $failed >.failed
		exitcode=1
	fi
else
	FORMAT='    %-35s: TEST SKIPPED (running 32-bit)\n'
	printf "$FORMAT" ntp

fi

exit $exitcode
