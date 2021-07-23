#!/bin/sh -e

# This script runs one build with setup environment variables: BUILD_LIBPCAP,
# REMOTE, CC, CMAKE, CRYPTO and SMB.

: "${BUILD_LIBPCAP:=no}"
: "${REMOTE:=no}"
: "${CC:=gcc}"
: "${CMAKE:=no}"
: "${CRYPTO:=no}"
: "${SMB:=no}"

. ./build_common.sh
# Install directory prefix
if [ -z "$PREFIX" ]; then
    PREFIX=`mktempdir tcpdump_build`
    echo "PREFIX set to '$PREFIX'"
fi
# For TESTrun
TCPDUMP_BIN="$PREFIX/bin/tcpdump"
export TCPDUMP_BIN

print_cc_version
if [ "$CMAKE" = no ]; then
    if [ "$BUILD_LIBPCAP" = yes ]; then
        echo "Using PKG_CONFIG_PATH=$PKG_CONFIG_PATH"
        run_after_echo ./configure --with-crypto="$CRYPTO" \
            --enable-smb="$SMB" --prefix="$PREFIX"
        LD_LIBRARY_PATH="$PREFIX/lib"
        export LD_LIBRARY_PATH
    else
        run_after_echo ./configure --with-crypto="$CRYPTO" \
            --enable-smb="$SMB" --prefix="$PREFIX" --disable-local-libpcap
    fi
else
    run_after_echo rm -rf build
    run_after_echo mkdir build
    run_after_echo cd build
    if [ "$BUILD_LIBPCAP" = yes ]; then
        run_after_echo cmake -DWITH_CRYPTO="$CRYPTO" -DENABLE_SMB="$SMB" \
            -DCMAKE_INSTALL_PREFIX="$PREFIX" -DCMAKE_PREFIX_PATH="$PREFIX" ..
        LD_LIBRARY_PATH="$PREFIX/lib"
        export LD_LIBRARY_PATH
    else
        run_after_echo cmake -DWITH_CRYPTO="$CRYPTO" -DENABLE_SMB="$SMB" \
            -DCMAKE_INSTALL_PREFIX="$PREFIX" ..
    fi
fi
run_after_echo make -s clean
# The norm is to compile without any warnings, but tcpdump builds on some OSes
# are not warning-free for one or another reason. If you manage to fix one of
# these cases, please remember to raise the bar here so if the warnings appear
# again, it will trigger an error.
case `uname -s` in
    AIX)
        CFLAGS=
        ;;
    SunOS)
        case `uname -r` in
        5.10|5.11)
            CFLAGS=-Werror
            ;;
        *)
            CFLAGS=
            ;;
        esac
        ;;
    *)
        CFLAGS=-Werror
        ;;
esac
run_after_echo make -s ${CFLAGS:+CFLAGS="$CFLAGS"}
run_after_echo make install
run_after_echo "$TCPDUMP_BIN" --version
run_after_echo "$TCPDUMP_BIN" -h
run_after_echo "$TCPDUMP_BIN" -D
print_so_deps "$TCPDUMP_BIN"
if [ "$CIRRUS_CI" = true ]; then
    run_after_echo sudo \
        ${LD_LIBRARY_PATH:+LD_LIBRARY_PATH="$LD_LIBRARY_PATH"} \
        "$TCPDUMP_BIN" -J
    run_after_echo sudo \
        ${LD_LIBRARY_PATH:+LD_LIBRARY_PATH="$LD_LIBRARY_PATH"} \
        "$TCPDUMP_BIN" -L
fi
if [ "$BUILD_LIBPCAP" = yes ]; then
    run_after_echo make check
fi
if [ "$CMAKE" = no ]; then
    run_after_echo make releasetar
fi
if [ "$CIRRUS_CI" = true ]; then
    run_after_echo sudo \
        ${LD_LIBRARY_PATH:+LD_LIBRARY_PATH="$LD_LIBRARY_PATH"} \
        "$TCPDUMP_BIN" -#n -c 10
fi
handle_matrix_debug
if [ "$DELETE_PREFIX" = yes ]; then
    run_after_echo rm -rf "$PREFIX"
fi
# vi: set tabstop=4 softtabstop=0 expandtab shiftwidth=4 smarttab autoindent :
