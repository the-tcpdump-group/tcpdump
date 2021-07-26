#!/bin/sh -e

# This script executes the matrix loops, exclude tests and cleaning.
# It calls the build.sh script which runs one build with setup environment
# variables: BUILD_LIBPCAP, REMOTE, CC, CMAKE, CRYPTO and SMB.
# The matrix can be configured with environment variables
# MATRIX_BUILD_LIBPCAP, MATRIX_REMOTE, MATRIX_CC, MATRIX_CMAKE, MATRIX_CRYPTO
# and MATRIX_SMB.

: "${MATRIX_BUILD_LIBPCAP:=no yes}"
: "${MATRIX_REMOTE:=no}"
: "${MATRIX_CC:=gcc clang}"
: "${MATRIX_CMAKE:=no yes}"
: "${MATRIX_CRYPTO:=no yes}"
: "${MATRIX_SMB:=no yes}"

. ./build_common.sh
print_sysinfo
# Install directory prefix
if [ -z "$PREFIX" ]; then
    # shellcheck disable=SC2006
    PREFIX=`mktempdir tcpdump_build_matrix`
    echo "PREFIX set to '$PREFIX'"
    export PREFIX
fi
COUNT=0

build_tcpdump() {
    for CMAKE in $MATRIX_CMAKE; do
        export CMAKE
        for CRYPTO in $MATRIX_CRYPTO; do
            export CRYPTO
            for SMB in $MATRIX_SMB; do
                export SMB
                # shellcheck disable=SC2006
                COUNT=`increment $COUNT`
                echo_magenta "===== SETUP $COUNT: BUILD_LIBPCAP=$BUILD_LIBPCAP REMOTE=${REMOTE:-?} CC=$CC CMAKE=$CMAKE CRYPTO=$CRYPTO SMB=$SMB ====="
                # Run one build with setup environment variables:
                # BUILD_LIBPCAP, REMOTE, CC, CMAKE, CRYPTO and SMB
                run_after_echo ./build.sh
                echo 'Cleaning...'
                if [ "$CMAKE" = yes ]; then
                    run_after_echo rm -rf build
                else
                    run_after_echo make distclean
                fi
                run_after_echo rm -rf "$PREFIX"/bin/tcpdump*
                run_after_echo git status -suall
                # Cancel changes in configure
                run_after_echo git checkout configure
            done
        done
    done
}

touch .devel configure
for CC in $MATRIX_CC; do
    export CC
    # Exclude gcc on macOS (it is just an alias for clang).
    # shellcheck disable=SC2006
    if [ "$CC" = gcc ] && [ "`uname -s`" = Darwin ]; then
        echo '(skipped)'
        continue
    fi
    for BUILD_LIBPCAP in $MATRIX_BUILD_LIBPCAP; do
        export BUILD_LIBPCAP
        if [ "$BUILD_LIBPCAP" = yes ]; then
            for REMOTE in $MATRIX_REMOTE; do
                export REMOTE
                # Build libpcap with Autoconf.
                echo_magenta "Build libpcap (CMAKE=no REMOTE=$REMOTE)"
                (cd ../libpcap && CMAKE=no ./build.sh)
                # Set PKG_CONFIG_PATH for configure when building libpcap
                if [ "$CMAKE" != no ]; then
                    PKG_CONFIG_PATH="$PREFIX/lib/pkgconfig"
                    export PKG_CONFIG_PATH
                fi
                build_tcpdump
            done
        else
            echo_magenta 'Use system libpcap'
            purge_directory "$PREFIX"
            (cd ../libpcap; make distclean || echo '(Ignoring the make error.)')
            build_tcpdump
        fi
    done
done

run_after_echo rm -rf "$PREFIX"
echo_magenta "Tested setup count: $COUNT"
# vi: set tabstop=4 softtabstop=0 expandtab shiftwidth=4 smarttab autoindent :
