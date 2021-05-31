#!/usr/bin/env bash

# This script executes the matrix loops, exclude tests and cleaning.
# It calls the build.sh script which runs one build with setup environment
# variables: BUILD_LIBPCAP, REMOTE, CC, CMAKE, CRYPTO and SMB
# (default: BUILD_LIBPCAP=no, REMOTE=no, CC=gcc, CMAKE=no, CRYPTO=no, SMB=no).
# The matrix can be configured with environment variables
# MATRIX_BUILD_LIBPCAP, MATRIX_REMOTE, MATRIX_CC, MATRIX_CMAKE, MATRIX_CRYPTO
# and MATRIX_SMB
# (default: MATRIX_BUILD_LIBPCAP='no yes', MATRIX_REMOTE='no yes',
# MATRIX_CC='gcc clang', MATRIX_CMAKE='no yes', MATRIX_CRYPTO='no yes',
# MATRIX_SMB='no yes').

set -e

# ANSI color escape sequences
ANSI_MAGENTA="\\033[35;1m"
ANSI_RESET="\\033[0m"
uname -a
date
# Install directory prefix
if [ -z "$PREFIX" ]; then
    PREFIX=$(mktemp -d -t tcpdump_build_matrix_XXXXXXXX)
    echo "PREFIX set to '$PREFIX'"
    export PREFIX
fi
COUNT=0

travis_fold() {
    local action=${1:?}
    local name=${2:?}
    if [ "$TRAVIS" != true ]; then return; fi
    echo -ne "travis_fold:$action:$LABEL.script.$name\\r"
    sleep 1
}

# Display text in magenta
echo_magenta() {
    echo -ne "$ANSI_MAGENTA"
    echo "$@"
    echo -ne "$ANSI_RESET"
}

build_tcpdump() {
    for CC in ${MATRIX_CC:-gcc clang}; do
        export CC
        # Exclude gcc on macOS (it is just an alias for clang).
        if [ "$CC" = gcc ] && [ "$(uname -s)" = Darwin ]; then
            echo '(skipped)'
            continue
        fi
        for CMAKE in ${MATRIX_CMAKE:-no yes}; do
            export CMAKE
            for CRYPTO in ${MATRIX_CRYPTO:-no yes}; do
                export CRYPTO
                for SMB in ${MATRIX_SMB:-no yes}; do
                    export SMB
                    COUNT=$((COUNT+1))
                    echo_magenta "===== SETUP $COUNT: BUILD_LIBPCAP=$BUILD_LIBPCAP REMOTE=${REMOTE:-?} CC=$CC CMAKE=$CMAKE CRYPTO=$CRYPTO SMB=$SMB ====="
                    # LABEL is needed to build the travis fold labels
                    LABEL="$BUILD_LIBPCAP.$REMOTE.$CC.$CMAKE.$CRYPTO.$SMB"
                    # Run one build with setup environment variables:
                    # BUILD_LIBPCAP, REMOTE, CC, CMAKE, CRYPTO and SMB
                    ./build.sh
                    echo 'Cleaning...'
                    travis_fold start cleaning
                    if [ "$CMAKE" = yes ]; then rm -rf build; else make distclean; fi
                    rm -rf "$PREFIX"/bin/tcpdump*
                    git status -suall
                    # Cancel changes in configure
                    git checkout configure
                    travis_fold end cleaning
                done
            done
        done
    done
}

touch .devel configure
for BUILD_LIBPCAP in ${MATRIX_BUILD_LIBPCAP:-no yes}; do
    export BUILD_LIBPCAP
    if [ "$BUILD_LIBPCAP" = yes ]; then
        for REMOTE in ${MATRIX_REMOTE:-no}; do
            export REMOTE
            # Build libpcap with Autoconf.
            echo_magenta "Build libpcap (CMAKE=no REMOTE=$REMOTE)"
            (cd ../libpcap && CMAKE=no ./build.sh)
            # Set PKG_CONFIG_PATH for configure when building libpcap
            if [ "$CMAKE" != no ]; then
                export PKG_CONFIG_PATH="$PREFIX/lib/pkgconfig"
            fi
            build_tcpdump
        done
    else
        echo_magenta 'Use system libpcap'
        rm -rf "${PREFIX:?}"/*
        make -C ../libpcap distclean || :
        build_tcpdump
    fi
done

rm -rf "$PREFIX"
echo_magenta "Tested setup count: $COUNT"
# vi: set tabstop=4 softtabstop=0 expandtab shiftwidth=4 smarttab autoindent :
