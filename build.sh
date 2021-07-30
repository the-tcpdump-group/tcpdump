#!/bin/sh -e

# This script runs one build with setup environment variables: BUILD_LIBPCAP,
# REMOTE, CC, CMAKE, CRYPTO and SMB.

: "${BUILD_LIBPCAP:=no}"
: "${REMOTE:=no}"
: "${CC:=gcc}"
: "${CMAKE:=no}"
: "${CRYPTO:=no}"
: "${SMB:=no}"
: "${TCPDUMP_TAINTED:=no}"

. ./build_common.sh
# Install directory prefix
if [ -z "$PREFIX" ]; then
    # shellcheck disable=SC2006
    PREFIX=`mktempdir tcpdump_build`
    echo "PREFIX set to '$PREFIX'"
fi
# For TESTrun
TCPDUMP_BIN="$PREFIX/bin/tcpdump"
export TCPDUMP_BIN

print_cc_version

# The norm is to compile without any warnings, but tcpdump builds on some OSes
# are not warning-free for one or another reason.  If you manage to fix one of
# these cases, please remember to remove respective exemption below to help any
# later warnings in the same matrix subset trigger an error.
# shellcheck disable=SC2006
case `os_id`/"$CMAKE" in
FreeBSD-*/yes)
    # tcpdump.c:2290:3: error: implicit declaration of function 'bpf_dump'
    #   [-Werror=implicit-function-declaration]
    [ "$BUILD_LIBPCAP" = yes ] && TCPDUMP_TAINTED=yes
    case `cc_id` in
    clang-*)
        # tcpdump.c:2434:32: error: '_Generic' is a C11 extension
        #   [-Werror,-Wc11-extensions]
        # tcpdump.c:2439:26: error: '_Generic' is a C11 extension
        #   [-Werror,-Wc11-extensions]
        # tcpdump.c:2443:9: error: '_Generic' is a C11 extension
        #   [-Werror,-Wc11-extensions]
        # tcpdump.c:244:16: error: no previous extern declaration for non-static variable
        #   'capdns' [-Werror,-Wmissing-variable-declarations]
        TCPDUMP_TAINTED=yes
        ;;
    esac
    ;;
esac
# shellcheck disable=SC2006
[ "$TCPDUMP_TAINTED" != yes ] && CFLAGS=`cc_werr_cflags`

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
            ${CFLAGS:+-DEXTRA_CFLAGS="$CFLAGS"} \
            -DCMAKE_INSTALL_PREFIX="$PREFIX" -DCMAKE_PREFIX_PATH="$PREFIX" ..
        LD_LIBRARY_PATH="$PREFIX/lib"
        export LD_LIBRARY_PATH
    else
        run_after_echo cmake -DWITH_CRYPTO="$CRYPTO" -DENABLE_SMB="$SMB" \
             ${CFLAGS:+-DEXTRA_CFLAGS="$CFLAGS"} \
            -DCMAKE_INSTALL_PREFIX="$PREFIX" ..
    fi
fi
run_after_echo make -s clean
if [ "$CMAKE" = no ]; then
    run_after_echo make -s ${CFLAGS:+CFLAGS="$CFLAGS"}
else
    # The "-s" flag is a no-op and CFLAGS is set using -DEXTRA_CFLAGS above.
    run_after_echo make
fi
run_after_echo make install
print_so_deps "$TCPDUMP_BIN"
run_after_echo "$TCPDUMP_BIN" -h
run_after_echo "$TCPDUMP_BIN" -D
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
