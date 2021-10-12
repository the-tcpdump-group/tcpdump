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
: "${MATRIX_CRYPTO:=no openssl wolfssl}"
: "${MATRIX_SMB:=no yes}"
# Set this variable to "yes" before calling this script to disregard all
# warnings in a particular environment (CI or a local working copy).  Set it
# to "yes" in this script or in build.sh when a matrix subset is known to be
# not warning-free because of the OS, the compiler or whatever other factor
# that the scripts can detect both in and out of CI.
: "${TCPDUMP_TAINTED:=no}"
# Some OSes have native make without parallel jobs support and sometimes have
# GNU Make available as "gmake".
: "${MAKE_BIN:=make}"

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
export TCPDUMP_TAINTED
export MAKE_BIN

build_tcpdump() {
    for CMAKE in $MATRIX_CMAKE; do
        export CMAKE
        for CRYPTO in $MATRIX_CRYPTO; do
            if [ "$CRYPTO" = "wolfssl" ]; then
                if [ ! -d "wolfssl_src" ]; then
                    echo "Building and installing wolfSSL"
                    run_after_echo git  clone --depth 1 --branch=master --quiet https://github.com/wolfSSL/wolfssl.git wolfssl_src
                    run_after_echo cd wolfssl_src
                    run_after_echo ./autogen.sh
                    run_after_echo ./configure --enable-tcpdump
                    run_after_echo make
                    run_after_echo make install
                    run_after_echo cd ..
                fi
            fi

            export CRYPTO
            for SMB in $MATRIX_SMB; do
                export SMB
                # shellcheck disable=SC2006
                COUNT=`increment $COUNT`
                echo_magenta "===== SETUP $COUNT: BUILD_LIBPCAP=$BUILD_LIBPCAP REMOTE=${REMOTE:-?} CC=$CC CMAKE=$CMAKE CRYPTO=$CRYPTO SMB=$SMB =====" >&2
                # Run one build with setup environment variables:
                # BUILD_LIBPCAP, REMOTE, CC, CMAKE, CRYPTO and SMB
                run_after_echo ./build.sh
                echo 'Cleaning...'
                if [ "$CMAKE" = yes ]; then
                    run_after_echo rm -rf build
                else
                    run_after_echo "$MAKE_BIN" distclean
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
    discard_cc_cache
    if gcc_is_clang_in_disguise; then
        echo '(skipped)'
        continue
    fi
    for BUILD_LIBPCAP in $MATRIX_BUILD_LIBPCAP; do
        export BUILD_LIBPCAP
        if [ "$BUILD_LIBPCAP" = yes ]; then
            for REMOTE in $MATRIX_REMOTE; do
                export REMOTE
                # Build libpcap with Autoconf.
                echo_magenta "Build libpcap (CMAKE=no REMOTE=$REMOTE)" >&2
                (cd ../libpcap && CMAKE=no ./build.sh)
                # Set PKG_CONFIG_PATH for configure when building libpcap
                if [ "$CMAKE" != no ]; then
                    PKG_CONFIG_PATH="$PREFIX/lib/pkgconfig"
                    export PKG_CONFIG_PATH
                fi
                build_tcpdump
            done
        else
            echo_magenta 'Use system libpcap' >&2
            purge_directory "$PREFIX"
            if [ -d ../libpcap ]; then
                (cd ../libpcap; "$MAKE_BIN" distclean || echo '(Ignoring the make error.)')
            fi
            build_tcpdump
        fi
    done
done

run_after_echo rm -rf "$PREFIX"
echo_magenta "Tested setup count: $COUNT" >&2
# vi: set tabstop=4 softtabstop=0 expandtab shiftwidth=4 smarttab autoindent :
