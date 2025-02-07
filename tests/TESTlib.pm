require 5.8.4; # Solaris 10
use strict;
use warnings FATAL => qw(uninitialized);
use Config;
use File::Temp qw(tempdir);

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
	%config = {};
	my $re_define_uint = qr/^#define ([0-9_A-Z]+) ([0-9]+)$/;
	my $re_define_str = qr/^#define ([0-9_A-Z]+) "(.+)"$/;
	open (my $fh, '<', $config_h) || die "failed opening '$config_h'";
	while (<$fh>) {
		$config{$1} = $2 if /$re_define_uint/o || /$re_define_str/o;
	}
	close ($fh) || die "failed closing '$config_h'";
}

# This is a simpler version of the PHP function.
sub file_put_contents {
	my ($filename, $contents) = @_;
	open (my $fh, '>', $filename) || die "failed opening '$filename'";
	print $fh $contents;
	close ($fh) || die "failed closing '$filename'";
}

# Idem.
sub file_get_contents {
	my $filename = shift;
	open (my $fh, '<', $filename) || die "failed opening '$filename'";
	my $ret = '';
	$ret .= $_ while (<$fh>);
	close ($fh) || die "failed closing '$filename'";
	return $ret;
}

sub string_in_file {
	my ($string, $filename) = @_;
	my $ret = 0;
	open (my $fh, '<', $filename) || die "failed opening '$filename'";
	while (<$fh>) {
		if (-1 != index $_, $string) {
			$ret = 1;
			last;
		}
	}
	close ($fh) || die "failed closing '$filename'";
	return $ret;
}

sub skip_os {
	my $name = shift;
	return $^O eq $name ? "is $name" : '';
}

sub skip_os_not {
	my $name = shift;
	return $^O ne $name ? "is not $name" : '';
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
	# "Unlike the other ‘AC_CHECK_*S’ macros, when a symbol is not declared,
	# HAVE_DECL_symbol is defined to ‘0’ instead of leaving HAVE_DECL_symbol
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
	return {char => CHAR_PASSED};
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
		print ' ' for (1 .. $max_results_per_line - $results_dangling);
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
		}
	}

	print "\n";
	if (%skipped) {
		print "Skipped tests:\n";
		print_result $_, $skipped{$_} foreach (sort keys %skipped);
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
	printf "%4u tests passed\n", $passedcount;

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
