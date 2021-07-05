#!/bin/sh -e

# This script runs one build with setup environment variables: BUILD_LIBPCAP,
# REMOTE, CC, CMAKE, CRYPTO and SMB
# (default: BUILD_LIBPCAP=no, REMOTE=no, CC=gcc, CMAKE=no, CRYPTO=no, SMB=no).

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

# Run a command after displaying it
run_after_echo() {
    printf '$ '
    echo "$@"
    # shellcheck disable=SC2068
    $@
}

if [ "$CMAKE" = no ]; then
    echo '$ ./configure [...]'
    if [ "$BUILD_LIBPCAP" = yes ]; then
        echo "Using PKG_CONFIG_PATH=$PKG_CONFIG_PATH"
        ./configure --with-crypto="$CRYPTO" --enable-smb="$SMB" --prefix="$PREFIX"
        export LD_LIBRARY_PATH="$PREFIX/lib"
    else
        ./configure --disable-local-libpcap --with-crypto="$CRYPTO" --enable-smb="$SMB" --prefix="$PREFIX"
    fi
else
    rm -rf build
    mkdir build
    cd build
    echo '$ cmake [...]'
    if [ "$BUILD_LIBPCAP" = yes ]; then
        cmake -DWITH_CRYPTO="$CRYPTO" -DENABLE_SMB="$SMB" -DCMAKE_PREFIX_PATH="$PREFIX" -DCMAKE_INSTALL_PREFIX="$PREFIX" ..
        export LD_LIBRARY_PATH="$PREFIX/lib"
    else
        cmake -DWITH_CRYPTO="$CRYPTO" -DENABLE_SMB="$SMB" -DCMAKE_INSTALL_PREFIX="$PREFIX" ..
    fi
fi
run_after_echo "make -s clean"
run_after_echo "make -s CFLAGS=-Werror"
echo '$ make install'
make install
run_after_echo "$TCPDUMP_BIN --version"
run_after_echo "$TCPDUMP_BIN -h"
run_after_echo "$TCPDUMP_BIN -D"
system=$(uname -s)
case "$system" in
Linux|FreeBSD|NetBSD|OpenBSD)
    run_after_echo "ldd $TCPDUMP_BIN"
    ;;
Darwin)
    run_after_echo "otool -L $TCPDUMP_BIN"
    ;;
esac
if [ "$BUILD_LIBPCAP" = yes ]; then
    run_after_echo "make check"
fi
if [ "$CMAKE" = no ]; then
    system=$(uname -s)
    if [ "$system" = Darwin ] || [ "$system" = Linux ]; then
        run_after_echo "make releasetar"
    fi
fi
# Beware that setting MATRIX_DEBUG will produce A LOT of additional output
# here and in any nested libpcap builds. Multiplied by the matrix size, the
# full output log size might exceed limits of some CI systems (as previously
# happened with Travis CI). Use with caution on a reduced matrix.
if [ "$MATRIX_DEBUG" = true ]; then
    echo '$ cat Makefile [...]'
    sed '/DO NOT DELETE THIS LINE -- mkdep uses it/q' < Makefile
    echo '$ cat config.h'
    cat config.h
    if [ "$CMAKE" = no ]; then
        echo '$ cat config.log'
        cat config.log
    fi
fi
if [ "$DELETE_PREFIX" = yes ]; then
    rm -rf "$PREFIX"
fi
# vi: set tabstop=4 softtabstop=0 expandtab shiftwidth=4 smarttab autoindent :
