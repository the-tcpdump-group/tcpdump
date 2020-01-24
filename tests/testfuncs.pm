#!/usr/bin/perl

# expects to be run from the top directory, with "tests" subdirectory.

sub runtest {
    local($name, $input, $output, $options) = @_;
    my $r;

    $outputbase = basename($output);
    my $coredump = false;
    my $status = 0;
    my $linecount = 0;
    my $rawstderrlog = "tests/NEW/${outputbase}.raw.stderr";
    my $stderrlog = "tests/NEW/${outputbase}.stderr";
    my $diffstat = 0;
    my $errdiffstat = 0;
    
    if ($^O eq 'MSWin32') {
        $r = system "..\\windump -# -n -r $input $options 2>NUL | sed 's/\\r//' | tee tests/NEW/$outputbase | diff $output - >tests/DIFF/$outputbase.diff";
        # need to do same as below for Cygwin.
    }
    else {
        # we used to do this as a nice pipeline, but the problem is that $r fails to
        # to be set properly if the tcpdump core dumps.
        $r = system "$TCPDUMP 2>${rawstderrlog} -# -n -r $input $options >tests/NEW/${outputbase}";
        if($r == -1) {
            # failed to start due to error.
            $status = $!;
        }
        if($r != 0) {
            $coredump = false;
            $status = 0;
            # this means tcpdump failed.
            open(OUTPUT, ">>"."tests/NEW/$outputbase") || die "fail to open $outputbase\n";
            if( $r & 128 ) {
                $coredump = $r & 127;
            }
            if( WIFEXITED($r)) {
                $status = WEXITSTATUS($r);
            }
            
            if($coredump || $status) {
                printf OUTPUT "EXIT CODE %08x: dump:%d code: %d\n", $r, $coredump, $status;
            } else {
                printf OUTPUT "EXIT CODE %08x\n", $r;
            }
            close(OUTPUT);
            $r = 0;
        }
        if($r == 0) {
            $r = system "cat tests/NEW/$outputbase | diff $output - >tests/DIFF/$outputbase.diff";
            $diffstat = WEXITSTATUS($r);
        }
        
        # process the file, sanitize "reading from" line, and count lines
        $linecount = 0;
        open(ERRORRAW, "<" . $rawstderrlog);
        open(ERROROUT, ">" . $stderrlog);
        while(<ERRORRAW>) {
            next if /^$/;  # blank lines are boring
            if(/^(reading from file )(.*)(,.*)$/) {
                my $filename = basename($2);
                print ERROROUT "${1}${filename}${3}\n";
                next;
            }
            print ERROROUT;
            $linecount++;
        }
        close(ERROROUT);
        close(ERRORRAW);
        
        if ( -f "$output.stderr" ) {
            $nr = system "cat $stderrlog | diff $output.stderr - >tests/DIFF/$outputbase.stderr.diff";
            if($r == 0) {
                $r = $nr;
            }
            $errdiffstat = WEXITSTATUS($nr);
        }
        
        if($r == 0) {
            if($linecount == 0 && $status == 0) {
                unlink($stderrlog);
            } else {
                $errdiffstat = 1;
            }
        }
        
        #print sprintf("END: %08x\n", $r);
    }

    if($r == 0) {
        if($linecount == 0) {
            printf "    %-40s: passed\n", $name;
        } else {
            printf "    %-40s: passed with error messages:\n", $name;
            system "cat $stderrlog";
        }
        unlink "tests/DIFF/$outputbase.diff";
        return 0;
    }
    # must have failed!
    printf "    %-40s: TEST FAILED(exit core=%d/diffstat=%d,%d/r=%d)", $name, $coredump, $diffstat, $errdiffstat, $r;
    open FOUT, '>>tests/failure-outputs.txt';
    printf FOUT "\nFailed test: $name\n\n";
    close FOUT;
    if(-f "tests/DIFF/$outputbase.diff") {
        system "cat tests/DIFF/$outputbase.diff >> tests/failure-outputs.txt";
    }
    
    if($r == -1) {
        print " (failed to execute: $!)\n";
        return(30);
    }

    # this is not working right, $r == 0x8b00 when there is a core dump.
    # clearly, we need some platform specific perl magic to take this apart, so look for "core"
    # too.
    # In particular, on Solaris 10 SPARC an alignment problem results in SIGILL,
    # a core dump and $r set to 0x00008a00 ($? == 138 in the shell).
    if($r & 127 || -f "core") {
        my $with = ($r & 128) ? 'with' : 'without';
        if(-f "core") {
            $with = "with";
        }
        printf " (terminated with signal %u, %s coredump)", ($r & 127), $with;
        if($linecount == 0) {
            print "\n";
        } else {
            print " with error messages:\n";
            system "cat $stderrlog";
        }
        return(($r & 128) ? 10 : 20);
    }
    if($linecount == 0) {
        print "\n";
    } else {
        print " with error messages:\n";
        system "cat $stderrlog";
    }
}

1;
