require 5.10.1; # Debian 6
use strict;
use warnings FATAL => qw(uninitialized);
use threads;
use Thread::Queue;
# TESTlib.pm
use subs qw(get_njobs);

# TESTrun helper functions (multithreaded implementation).

my $njobs;
my $tmpid;
my @tests;
my @result_queues;
my @tester_threads;
my $next_to_dequeue;

sub my_tmp_id {
	return $tmpid;
}

# Iterate over the list of tests, pick tests that belong to the current job,
# run one test at a time and send the result to the job's results queue.
sub tester_thread_func {
	my $jobid = shift;
	$tmpid = sprintf 'job%03u', $jobid;
	for (my $i = $jobid; $i < scalar @tests; $i += $njobs) {
		my $test = $tests[$i];
		my $result = $test->{func} ($test);
		$result->{label} = $test->{label};
		$result_queues[$jobid]->enqueue ($result);
	}
	# Instead of detaching let the receiver join, this works around File::Temp
	# not cleaning up.
	# No Thread::Queue->end() in Perl 5.10.1, so use an undef to mark the end.
	$result_queues[$jobid]->enqueue (undef);
}

sub start_tests {
	$njobs = get_njobs;
	print "INFO: This Perl supports threads, using $njobs tester thread(s).\n";
	@tests = @_;
	for (0 .. $njobs - 1) {
		$result_queues[$_] = Thread::Queue->new;
		$tester_threads[$_] =  threads->create (\&tester_thread_func, $_);
	}
	$next_to_dequeue = 0;
}

# Here ordering of the results is the same as ordering of the tests because
# this function starts at job 0 and continues round-robin, which reverses the
# interleaving done in the thread function above; also because every attempt
# to dequeue blocks until it returns exactly one result.
sub get_next_result {
	for (0 .. $njobs - 1) {
		my $jobid = $next_to_dequeue;
		$next_to_dequeue = ($next_to_dequeue + 1) % $njobs;
		# Skip queues that have already ended.
		next unless defined $result_queues[$jobid];
		my $result = $result_queues[$jobid]->dequeue;
		# A test result?
		return $result if defined $result;
		# No, an end-of-queue marker.
		$result_queues[$jobid] = undef;
		$tester_threads[$jobid]->join;
	}
	# No results after one complete round, therefore done.
	return undef;
}

1;
