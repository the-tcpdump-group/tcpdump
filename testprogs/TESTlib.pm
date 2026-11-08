require 5.8.4; # Solaris 10
use strict;
use warnings FATAL => qw(uninitialized);
use Config;
use File::Temp qw(tempdir);
use File::Path qw(rmtree);
use List::Util qw(min max sum first);
use Time::HiRes;
use POSIX qw(WIFSIGNALED WTERMSIG);

# TESTrun helper functions (common to all projects).

# TESTst.pm or TESTmt.pm
use subs qw(
	get_next_result
	my_tmp_id
	start_tests
);

# The characters are inspired by PHPUnit format, but are not exactly the same.
use constant {
	CHAR_SKIPPED => 'S',
	CHAR_PASSED => '.',
	CHAR_FAILED => 'F',
	CHAR_TIMED_OUT => 'T',
};

my %osnames = (
	aix => 'AIX',
	darwin => 'macOS',
	dragonfly => 'DragonFly BSD',
	freebsd => 'FreeBSD',
	gnu => 'Hurd',
	haiku => 'Haiku',
	hpux => 'HP-UX',
	linux => 'Linux',
	midnightbsd => 'MidnightBSD',
	msys => 'Windows',
	netbsd => 'NetBSD',
	nto => 'QNX',
	openbsd => 'OpenBSD',
	solaris => 'illumos/Solaris',
);

my %helpers = (
	mp => 'use multiprocessing',
	mt => 'use multithreading',
	st => 'use the main thread only',
);

my %progress_modes = (
	bar => 'a horizontal progress bar',
	lines => 'a line for every 10%',
	map => 'a character for every test result',
	none => 'no output',
);

my $results_to_print;
my $results_printed;
my $passedcount;
my $skippedcount;
my $failedcount;
my $max_result_digits;
my $max_results_per_line;
my $points_printed;
my $progress_mode;
my $flush_after_newline;
my $tmpdir;
my %config;

sub get_lib_usage () {
	my $ret = "
TESTRUN_JOBS allows to specify the number of tester jobs (1 by default).

TESTRUN_HELPER allows to specify how to run the tests (auto-detect by default):
";
	$ret .= "* \"$_\" -- $helpers{$_}\n" foreach sort keys %helpers;
	$ret .= "
TESTRUN_PROGRESS allows to specify the progress reporting mode:
";
	$ret .= "* \"$_\" -- $progress_modes{$_}\n" foreach sort keys %progress_modes;
	return $ret;
}

sub init_tmpdir {
	my $prefix = shift;
	# No File::Temp->newdir() in Perl 5.8.4.
	$tmpdir = tempdir (
		"${prefix}_XXXXXXXX",
		TMPDIR => 1,
		CLEANUP => 0
	);
}

sub remove_tmpdir () {
	rmtree $tmpdir, 0, 1;
}

sub mytmpfile {
	# Do not use sprintf() in a busy loop.
	return $tmpdir . '/' . my_tmp_id . '-' . shift;
}

sub get_njobs {
	my $njobs;
	if (! defined $ENV{TESTRUN_JOBS}) {
		$njobs = 1;
	} elsif ($ENV{TESTRUN_JOBS} =~ /^\d+\z/) {
		$njobs = int ($ENV{TESTRUN_JOBS});
	} else {
		$njobs = 0;
	}
	die "ERROR: '$ENV{TESTRUN_JOBS}' is not a valid value for TESTRUN_JOBS" if ! $njobs;
	return $njobs;
}

sub get_env_enum ($@) {
	my $name = shift;
	my @valid = @_;
	my $ret = $ENV{$name};
	return $ret unless defined $ret;
	die "Invalid $name value '$ret'." unless defined first {$ret eq $_} @valid;
	return $ret;
}

sub get_helper_module () {
	# OSes where for more than one tester job "mp" performs notably better.
	# Tested negative: Haiku and QNX 8.0.
	# Not tested: AIX, GNU/Hurd, HP-UX and Windows.
	my @mpgood = qw(
		darwin
		dragonfly
		freebsd
		linux
		midnightbsd
		netbsd
		openbsd
		solaris
	);
	my $njobs = get_njobs;
	my $h = get_env_enum 'TESTRUN_HELPER', keys %helpers;
	if (defined $h) {
		# Use the validated value.
	} elsif ($njobs == 1) {
		# For one tester job "st" incurs the least overhead and is the best choice
		# on all OSes except Solaris 10.
		$h = 'st';
	} elsif (grep $^O eq $_, @mpgood) {
		$h = 'mp';
	} elsif ($njobs <= 4 && $Config{useithreads}) {
		# For more than one tester job "mt" performs better than "st", but quickly
		# degrades.
		$h = 'mt';
	} else {
		# The last-resort choice.
		$h = 'st';
	}
	return "TEST${h}.pm";
}

sub get_diff_flags {
	return defined $ENV{DIFF_FLAGS} ? $ENV{DIFF_FLAGS} :
	$^O eq 'hpux' ? '-c' :
	'-u';
}

# Parse config.h into a hash for later use.
sub read_config_h {
	my $config_h = shift;
	%config = ();
	open FH, '<', $config_h or die "failed opening '$config_h'";
	while (<FH>) {
		$config{$1} = $2 if /^
			[[:blank:]]*\#define
			[[:blank:]]+([0-9_A-Z]+)
			[[:blank:]]+([0-9]+|".*")
			[\r\n]*$/xo;
	}
	close FH or die "failed closing '$config_h'";
	return %config;
}

# This is a simpler version of the PHP function.
sub file_put_contents {
	my ($filename, $contents) = @_;
	open FH, '>', $filename or die "failed opening '$filename'";
	print FH $contents;
	close FH or die "failed closing '$filename'";
}

# Idem.
sub file_get_contents {
	my $filename = shift;
	open FH, '<', $filename or die "failed opening '$filename'";
	my $ret;
	die "failed reading '$filename'" unless defined read FH, $ret, -s FH;
	close FH or die "failed closing '$filename'";
	return $ret;
}

sub string_in_file {
	my ($string, $filename) = @_;
	my $ret = 0;
	open FH, '<', $filename or die "failed opening '$filename'";
	while (<FH>) {
		if (-1 != index $_, $string) {
			$ret = 1;
			last;
		}
	}
	close FH or die "failed closing '$filename'";
	return $ret;
}

sub skip_os {
	my $name = shift;
	my $bettername = $osnames{$name} || $name;
	return $^O eq $name ? "is $bettername" : '';
}

sub skip_os_not {
	my $name = shift;
	my $bettername = $osnames{$name} || $name;
	return $^O ne $name ? "is not $bettername" : '';
}

sub skip_config_def1 {
	my $symbol = shift;
	return (defined $config{$symbol} && $config{$symbol} eq '1') ?
		"$symbol==1" : '';
}

sub skip_config_not_def1 {
	my $symbol = shift;
	return (! defined $config{$symbol} || $config{$symbol} ne '1') ?
		"${symbol}!=1" : '';
}

sub result_skipped {
	return {
		char => CHAR_SKIPPED,
		skip => shift
	};
}

sub result_passed {
	return {
		char => CHAR_PASSED,
		T => shift
	};
}

sub result_failed {
	return {
		char => CHAR_FAILED,
		failure => {
			reason => shift,
			details => shift
		}
	};
}

sub result_timed_out {
	return {
		char => CHAR_TIMED_OUT,
		failure => {reason => shift}
	};
}

sub result_terminated ($$) {
	my $what = shift;
	my $status = shift;
	return result_failed (
		"$what terminated due to signal " . WTERMSIG $status
	) if WIFSIGNALED $status;
	return result_failed "$what terminated due to an unknown reason";
}

sub run_skip_test {
	my $test = shift;
	return result_skipped $test->{skip};
}

# <------------------------- $maxcols -------------------------->
# ............................................ 0000 / 0000 (000%)
#                          $max_result_digits >----< >----<
# <--------- $max_results_per_line ---------->
sub init_results_processing {
	my $maxcols = 80;
	$results_to_print = shift;
	# When using threads, STDOUT becomes line-buffered on TTYs, which is
	# not good for interactive progress monitoring.
	STDOUT->autoflush (1) if -t STDOUT;
	# When using threads, STDOUT becomes block-buffered on pipes, which is
	# not good for CI progress monitoring.
	$flush_after_newline = ! -t STDOUT;
	$results_printed = 0;
	$progress_mode = get_env_enum ('TESTRUN_PROGRESS', keys %progress_modes) ||
		(-t STDOUT ? 'bar' : 'lines');
	$max_result_digits = 1 + int (log ($results_to_print) / log (10));
	if ($progress_mode eq 'bar') {
		$points_printed = 0;
		print "0%     10%    20%    30%    40%    50%    60%    70%    80%    90%    100%\n";
		print "+------+------+------+------+------+------+------+------+------+------+\n";
	} elsif ($progress_mode eq 'lines') {
		$points_printed = 0;
	} elsif ($progress_mode eq 'map') {
		$max_results_per_line = $maxcols - 11 - 2 * $max_result_digits;
		printf "INFO: %s = skipped, %s = passed, %s = failed, %s = timed out\n",
			CHAR_SKIPPED, CHAR_PASSED, CHAR_FAILED, CHAR_TIMED_OUT;
	}
}

sub print_result_bar () {
	my $points = int (71 * $results_printed / $results_to_print);
	return if $points_printed == $points;
	print '%' x ($points - $points_printed);
	$points_printed = $points;
	print "\n" if $results_printed == $results_to_print;
}

# Produce a results map in PHPUnit output format.
sub print_result_char {
	print shift;
	my $results_dangling = $results_printed % $max_results_per_line;
	if ($results_dangling) {
		return if $results_printed < $results_to_print;
		# Complete the dangling line to keep the progress column aligned.
		print ' ' x ($max_results_per_line - $results_dangling);
	}
	printf " %*u / %*u (%3u%%)\n",
		$max_result_digits,
		$results_printed,
		$max_result_digits,
		$results_to_print,
		100 * $results_printed / $results_to_print;
	STDOUT->flush if $flush_after_newline;
}

sub print_result_line () {
	my $points = int (100 * $results_printed / $results_to_print);
	return if $points % 10 || $points_printed == $points;
	printf "%*u skipped, %*u failed, %*u passed (%3u%%)\n",
		$max_result_digits, $skippedcount,
		$max_result_digits, $failedcount,
		$max_result_digits, $passedcount,
		$points;
	STDOUT->flush if $flush_after_newline;
	$points_printed = $points;
}

sub print_result {
	printf "    %-40s: %s\n", @_;
}

sub test_and_report {
	my @tests = @_;

	my %seen_labels;
	foreach (@tests) {
		if (! defined $_->{label}) {
			my $count = scalar %seen_labels;
			die "ERROR: after $count tests 'label' is not defined for a test";
		}
		my $label = $_->{label};
		die "ERROR: Duplicate test label '$label'" if exists $seen_labels{$label};
		$seen_labels{$label} = 1;
		die "ERROR: 'func' is not defined for test '$label'" unless defined $_->{func};
	}
	undef %seen_labels;

	my $start = Time::HiRes::time;
	start_tests (@tests);
	init_results_processing scalar @tests;
	my $ret = 0;
	# key: test label, value: reason for skipping
	my %skipped;
	# key: test label, value: hash of
	# * reason (mandatory, string)
	# * details (optional, [multi-line] string)
	my %failed;
	$passedcount = 0;
	my %passed; # May stay empty even if $passedcount > 0.
	$skippedcount = 0;
	$failedcount = 0;

	# Ordering of the results is the same as ordering of the tests.  Print the
	# results map immediately and buffer any skipped/failed test details for the
	# post-map diagnostics.
	while (defined (my $result = get_next_result)) {
		if (defined $result->{skip}) {
			$skippedcount++;
			$skipped{$result->{label}} = $result->{skip};
		} elsif (defined $result->{failure}) {
			$failedcount++;
			$failed{$result->{label}} = $result->{failure};
		} else {
			$passedcount++;
			$passed{$result->{label}} = $result->{T} if defined $result->{T};
		}
		if (++$results_printed > $results_to_print) {
			die 'Internal error: unexpected results after 100%!';
		}
		# Now $results_printed includes the current result before it has been
		# printed, but each function below expects exactly that.
		if ($progress_mode eq 'bar') {
			print_result_bar;
		} elsif ($progress_mode eq 'map') {
			print_result_char $result->{char};
		} elsif ($progress_mode eq 'lines') {
			print_result_line;
		}
	}
	my $end = Time::HiRes::time;

	if (%passed) {
		print "Passed tests:\n";
		print_result $_, sprintf ('T=%.06fs', $passed{$_}) foreach (sort keys %passed);
		print "\n";
	}
	if (%skipped && defined first {$_} values %skipped) {
		print "Skipped tests:\n";
		foreach (sort keys %skipped) {
			print_result $_, $skipped{$_} if $skipped{$_} ne '';
		}
		print "\n";
	}
	if (%failed) {
		$ret = 1;
		print "Failed tests:\n";
		foreach (sort keys %failed) {
			print_result $_, $failed{$_}{reason};
			print $failed{$_}{details} if defined $failed{$_}{details};
		}
		print "\n";
	}

	# scalar (%hash) returns incorrect value on Perl 5.8.4.
	printf "INFO: %*u tests skipped\n", $max_result_digits, $skippedcount;
	printf "INFO: %*u tests failed\n", $max_result_digits, $failedcount;
	if (! scalar keys %passed) {
		# There isn't any test duration statistics.
		printf "INFO: %*u tests passed\n", $max_result_digits, $passedcount;
	} elsif ($passedcount != scalar keys %passed) {
		die sprintf ("Internal error: statistics bug (%u != %u)",
			$passedcount,
			scalar (keys %passed)
		);
	} else {
		printf "INFO: %*u tests passed: T min/avg/max = %.06f/%.06f/%.06fs\n",
			$max_result_digits,
			scalar (keys %passed),
			min (values %passed),
			sum (values %passed) / scalar (keys %passed),
			max (values %passed);
	}

	printf "INFO: Testing time = %.2f seconds.\n", $end - $start;
	printf "INFO: Executed test rate overall = %.2f per second.\n",
		($passedcount + $failedcount) / ($end - $start);
	printf (
		"INFO: Executed test rate per job = %.2f per second.\n",
		($passedcount + $failedcount) / ($end - $start) / get_njobs
	) if get_njobs > 1;

	if ($skippedcount + $failedcount + $passedcount != $results_to_print) {
		printf STDERR "Internal error: statistics bug (%u + %u + %u != %u)\n",
			$skippedcount,
			$failedcount,
			$passedcount,
			$results_to_print;
		$ret = 2;
	}
	return $ret;
}

1;
