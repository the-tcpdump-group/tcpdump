#!/usr/bin/env bash

# This script runs one build with setup environment variables: BUILD_LIBPCAP,
# REMOTE, CC, CMAKE, CRYPTO and SMB
# (default: BUILD_LIBPCAP=no, REMOTE=no, CC=gcc, CMAKE=no, CRYPTO=no, SMB=no).

set -e

# BUILD_LIBPCAP: no or yes
BUILD_LIBPCAP=${BUILD_LIBPCAP:-no}
# REMOTE: no or yes
REMOTE=${REMOTE:-no}
# CC: gcc or clang
CC=${CC:-gcc}
# GCC and Clang recognize --version and print to stdout. Sun compilers
# recognize -V and print to stderr.
"$CC" --version 2>/dev/null || "$CC" -V || :
# CMAKE: no or yes
CMAKE=${CMAKE:-no}
# CRYPTO: no or yes
CRYPTO=${CRYPTO:-no}
# SMB: no or yes
SMB=${SMB:-no}
# Install directory prefix
if [ -z "$PREFIX" ]; then
    PREFIX=$(mktemp -d -t tcpdump_build_XXXXXXXX)
    echo "PREFIX set to '$PREFIX'"
fi
# For TESTrun
export TCPDUMP_BIN="$PREFIX/bin/tcpdump"

travis_fold() {
    local action=${1:?}
    local name=${2:?}
    if [ "$TRAVIS" != true ]; then return; fi
    echo -ne "travis_fold:$action:$LABEL.script.$name\\r"
    sleep 1
}

# Run a command after displaying it
run_after_echo() {
    echo -n '$ '
    echo "$@"
    # shellcheck disable=SC2068
    $@
}

# LABEL is needed to build the travis fold labels
LABEL="$BUILD_LIBPCAP.$REMOTE.$CC.$CMAKE.$CRYPTO.$SMB"
if [ "$CMAKE" = no ]; then
    echo '$ ./configure [...]'
    travis_fold start configure
    if [ "$BUILD_LIBPCAP" = yes ]; then
        echo "Using PKG_CONFIG_PATH=$PKG_CONFIG_PATH"
        ./configure --with-crypto="$CRYPTO" --enable-smb="$SMB" --prefix="$PREFIX"
        export LD_LIBRARY_PATH="$PREFIX/lib"
    else
        ./configure --disable-local-libpcap --with-crypto="$CRYPTO" --enable-smb="$SMB" --prefix="$PREFIX"
    fi
    travis_fold end configure
else
    rm -rf build
    mkdir build
    cd build
    echo '$ cmake [...]'
    travis_fold start cmake
    if [ "$BUILD_LIBPCAP" = yes ]; then
        cmake -DWITH_CRYPTO="$CRYPTO" -DENABLE_SMB="$SMB" -DCMAKE_PREFIX_PATH="$PREFIX" -DCMAKE_INSTALL_PREFIX="$PREFIX" ..
        export LD_LIBRARY_PATH="$PREFIX/lib"
    else
        cmake -DWITH_CRYPTO="$CRYPTO" -DENABLE_SMB="$SMB" -DCMAKE_INSTALL_PREFIX="$PREFIX" ..
    fi
    travis_fold end cmake
fi
run_after_echo "make -s clean"
run_after_echo "make -s CFLAGS=-Werror"
echo '$ make install'
travis_fold start make_install
make install
travis_fold end make_install
run_after_echo "$TCPDUMP_BIN --version"
run_after_echo "$TCPDUMP_BIN -h"
run_after_echo "$TCPDUMP_BIN -D"
system=$(uname -s)
if [ "$system" = Linux ]; then
    run_after_echo "ldd $TCPDUMP_BIN"
fi
if [ "$TRAVIS" = true ]; then
    if [ -n "$LD_LIBRARY_PATH" ]; then
        run_after_echo "sudo LD_LIBRARY_PATH=$LD_LIBRARY_PATH $TCPDUMP_BIN -J"
        run_after_echo "sudo LD_LIBRARY_PATH=$LD_LIBRARY_PATH $TCPDUMP_BIN -L"
    else
        run_after_echo "sudo $TCPDUMP_BIN -J"
        run_after_echo "sudo $TCPDUMP_BIN -L"
    fi
fi
if [ "$BUILD_LIBPCAP" = yes ]; then
    run_after_echo "make check"
fi
if [ "$CMAKE" = no ]; then
    system=$(uname -s)
    if [ "$system" = Darwin ] || [ "$system" = Linux ]; then
        run_after_echo "make releasetar"
    fi
fi
if [ "$TRAVIS" = true ]; then
    if [ "$TRAVIS_OS_NAME" = linux ] && [ "$TRAVIS_CPU_ARCH" != ppc64le ] && [ "$TRAVIS_CPU_ARCH" != s390x ] && [ "$TRAVIS_CPU_ARCH" != arm64 ]; then
        if [ -n "$LD_LIBRARY_PATH" ]; then
            run_after_echo "sudo LD_LIBRARY_PATH=$LD_LIBRARY_PATH $TCPDUMP_BIN -#n -c 10"
        else
            run_after_echo "sudo $TCPDUMP_BIN -#n -c 10"
        fi
    fi
fi
# The DEBUG_BUILD variable is not set by default to avoid Travis error message:
# "The job exceeded the maximum log length, and has been terminated."
# Setting it needs to reduce the matrix cases.
if [ "$TRAVIS" = true ] && [ -n "$DEBUG_BUILD" ] ; then
    echo '$ cat Makefile [...]'
    travis_fold start cat_makefile
    sed '/DO NOT DELETE THIS LINE -- mkdep uses it/q' < Makefile
    travis_fold end cat_makefile
    echo '$ cat config.h'
    travis_fold start cat_config_h
    cat config.h
    travis_fold end cat_config_h
    if [ "$CMAKE" = no ]; then
        echo '$ cat config.log'
        travis_fold start cat_config_log
        cat config.log
        travis_fold end cat_config_log
    fi
fi
if [ "$DELETE_PREFIX" = yes ]; then
    rm -rf "$PREFIX"
fi
# vi: set tabstop=4 softtabstop=0 expandtab shiftwidth=4 smarttab autoindent :
