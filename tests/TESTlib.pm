require 5.8.4; # Solaris 10
use strict;
use warnings FATAL => qw(uninitialized);
use Config;
use File::Temp qw(tempdir);
use List::Util qw(min max sum);

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
	msys => 'Windows',
	netbsd => 'NetBSD',
	openbsd => 'OpenBSD',
	solaris => 'illumos/Solaris',
);

my $results_to_print;
my $results_printed;
my $max_result_digits;
my $max_results_per_line;
my $flush_after_newline;
my $tmpdir;
my %config;

sub init_tmpdir {
	my $prefix = shift;
	# No File::Temp->newdir() in Perl 5.8.4.
	$tmpdir = tempdir (
		"${prefix}_XXXXXXXX",
		TMPDIR => 1,
		CLEANUP => 1
	);
}

sub mytmpfile {
	return sprintf '%s/%s-%s', $tmpdir, my_tmp_id, shift;
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
	my $ret = '';
	$ret .= $_ while (<FH>);
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

sub skip_config_undef {
	my $symbol = shift;
	return (! defined $config{$symbol} || $config{$symbol} ne '1') ?
		"${symbol}!=1" : '';
}

sub skip_config_have_decl {
	my ($name, $value) = @_;
	$name = 'HAVE_DECL_' . $name;
	# "Unlike the other 'AC_CHECK_*S' macros, when a symbol is not declared,
	# HAVE_DECL_symbol is defined to '0' instead of leaving HAVE_DECL_symbol
	# undeclared." -- GNU Autoconf manual.
	#
	# (This requires the CMake leg to do the same for the same symbol.)
	die "no $name in config.h" unless defined $config{$name};
	return int ($config{$name}) == $value ? "$name==$value" : '';
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
	if ($Config{useithreads}) {
		# When using threads, STDOUT becomes line-buffered on TTYs, which is
		# not good for interactive progress monitoring.
		STDOUT->autoflush (1) if -t STDOUT;
		$flush_after_newline = ! -t STDOUT;
	}
	$results_printed = 0;
	$max_result_digits = 1 + int (log ($results_to_print) / log (10));
	$max_results_per_line = $maxcols - 11 - 2 * $max_result_digits;
}

# Produce a results map in PHPUnit output format.
sub print_result_char {
	print shift;
	if (++$results_printed > $results_to_print) {
		die "Internal error: unexpected results after 100%!";
	}
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
	# When using threads, STDOUT becomes block-buffered on pipes, which is
	# not good for CI progress monitoring.
	STDOUT->flush if $flush_after_newline;
}

sub print_result {
	printf "    %-40s: %s\n", @_;
}

sub test_and_report {
	my @tests = @_;
	start_tests (@tests);
	init_results_processing scalar @tests;
	my $ret = 0;
	# key: test label, value: reason for skipping
	my %skipped;
	# key: test label, value: hash of
	# * reason (mandatory, string)
	# * details (optional, [multi-line] string)
	my %failed;
	my $passedcount = 0;
	my %passed; # May stay empty even if $passedcount > 0.

	printf "INFO: %s = skipped, %s = passed, %s = failed, %s = timed out\n",
		CHAR_SKIPPED, CHAR_PASSED, CHAR_FAILED, CHAR_TIMED_OUT;

	# Ordering of the results is the same as ordering of the tests.  Print the
	# results map immediately and buffer any skipped/failed test details for the
	# post-map diagnostics.
	while (defined (my $result = get_next_result)) {
		print_result_char ($result->{char});
		if (defined $result->{skip}) {
			$skipped{$result->{label}} = $result->{skip};
		} elsif (defined $result->{failure}) {
			$failed{$result->{label}} = $result->{failure};
		} else {
			$passedcount++;
			$passed{$result->{label}} = $result->{T} if defined $result->{T};
		}
	}

	print "\n";
	if (%passed) {
		print "Passed tests:\n";
		print_result $_, sprintf ('T=%.06fs', $passed{$_}) foreach (sort keys %passed);
		print "\n";
	}
	if (%skipped) {
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
	my $skippedcount = scalar keys %skipped;
	my $failedcount = scalar keys %failed;
	print "------------------------------------------------\n";
	printf "%4u tests skipped\n", $skippedcount;
	printf "%4u tests failed\n", $failedcount;
	if (! scalar keys %passed) {
		# There isn't any test duration statistics.
		printf "%4u tests passed\n", $passedcount;
	} elsif ($passedcount != scalar keys %passed) {
		die sprintf ("Internal error: statistics bug (%u != %u)",
			$passedcount,
			scalar (keys %passed)
		);
	} else {
		printf "%4u tests passed: T min/avg/max = %.06f/%.06f/%.06fs\n",
			scalar (keys %passed),
			min (values %passed),
			sum (values %passed) / scalar (keys %passed),
			max (values %passed);
	}

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
