require 5.8.4; # Solaris 10
use strict;
use warnings FATAL => qw(uninitialized);
use Socket;
use Storable qw(store_fd fd_retrieve);
use subs qw(get_njobs);

# TESTrun helper functions (multiprocessing implementation).

my $njobs;
my $tmpid;
my @tests;
my $done;
my $todo;
my @tester_pids;
my @rsockets;

sub my_tmp_id () {
	return $tmpid;
}

# Iterate over the list of tests, pick tests that belong to the current job,
# run one test at a time and send the result into the provided socket.
sub tester_process_func ($$) {
	my $jobid = shift;
	my $wsocket = shift;
	$tmpid = sprintf 'job%03u', $jobid;
	for (my $i = $jobid; $i < $todo; $i += $njobs) {
		my $test = $tests[$i];
		my $result = $test->{func} ($test);
		$result->{label} = $test->{label};
		die 'store_fd() failed' unless defined store_fd $result, $wsocket;
	}
	close $wsocket;
	return EX_OK;
}

sub start_tests (@) {
	$njobs = get_njobs;
	print "INFO: Using $njobs tester process(es).\n";
	@tests = @_;
	$todo = scalar @tests;
	$done = 0;
	for (0 .. $njobs - 1) {
		die 'socketpair() failed' unless socketpair $rsockets[$_], my $wsocket,
			AF_UNIX, SOCK_STREAM, PF_UNSPEC;
		$tester_pids[$_] = fork;
		die 'fork() failed' unless defined $tester_pids[$_];
		exit tester_process_func $_, $wsocket unless $tester_pids[$_];
	}
}

# To order the results the same way as the tests, start at job 0 and continue
# round-robin until exactly $todo results have been collected.  All tester
# processes together do not send more than $todo results.  If a tester process
# hangs before sending all its results, this function will hang trying to
# receive.  If a tester process exits before sending all its results, this
# function will propagate a failure from fd_retrieve().  Every invocation of
# fd_retrieve() either receives exactly one result or fails.
sub get_next_result () {
	if ($done != $todo) {
		my $result = fd_retrieve $rsockets[$done++ % $njobs];
		die 'fd_retrieve() failed' unless defined $result;
		return $result;
	}
	close $_ foreach @rsockets;
	waitpid $_, 0 foreach @tester_pids;
	return undef;
}

1;
