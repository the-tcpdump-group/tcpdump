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
: "${MAKE_BIN:=make}"

. ./build_common.sh
# Install directory prefix
if [ -z "$PREFIX" ]; then
    # shellcheck disable=SC2006
    PREFIX=`mktempdir tcpdump_build`
    echo "PREFIX set to '$PREFIX'"
fi
TCPDUMP_BIN="$PREFIX/bin/tcpdump"
# For TESTrun
export TCPDUMP_BIN

print_cc_version

# The norm is to compile without any warnings, but tcpdump builds on some OSes
# are not warning-free for one or another reason.  If you manage to fix one of
# these cases, please remember to remove respective exemption below to help any
# later warnings in the same matrix subset trigger an error.

# shellcheck disable=SC2006
case `cc_id`/`os_id` in
clang-9.*/SunOS-5.11)
    # (OpenIndiana)
    # tcpdump.c:2312:51: warning: this function declaration is not a prototype
    #   [-Wstrict-prototypes]
    # tcpdump.c:2737:11: warning: this function declaration is not a prototype
    #   [-Wstrict-prototypes]
    [ "`uname -o`" = illumos ] && TCPDUMP_TAINTED=yes
    ;;
esac

# shellcheck disable=SC2006
[ "$TCPDUMP_TAINTED" != yes ] && CFLAGS=`cc_werr_cflags`

# Determine if and how to enable crypto support.
configure_crypto_option="--with-crypto=no"
cmake_crypto_option="-DWITH_CRYPTO=no"
if [ "$CRYPTO" = "wolfssl" ]; then
    configure_crypto_option="--with-wolfssl=yes"
    cmake_crypto_option="-DWITH_WOLFSSL=yes"
elif [ "$CRYPTO" = "openssl" -o "$CRYPTO" = "yes" ]; then
    configure_crypto_option="--with-crypto=yes"
    cmake_crypto_option="-DWITH_CRYPTO=yes"
fi

if [ "$CMAKE" = no ]; then
    if [ "$BUILD_LIBPCAP" = yes ]; then
        echo "Using PKG_CONFIG_PATH=$PKG_CONFIG_PATH"
        run_after_echo ./configure $configure_crypto_option \
            --enable-smb="$SMB" --prefix="$PREFIX"
        LD_LIBRARY_PATH="$PREFIX/lib"
        export LD_LIBRARY_PATH
    else
        run_after_echo ./configure $configure_crypto_option \
            --enable-smb="$SMB" --prefix="$PREFIX" --disable-local-libpcap
    fi
else
    run_after_echo rm -rf build
    run_after_echo mkdir build
    run_after_echo cd build
    if [ "$BUILD_LIBPCAP" = yes ]; then
        run_after_echo cmake $cmake_crypto_option -DENABLE_SMB="$SMB" \
            ${CFLAGS:+-DEXTRA_CFLAGS="$CFLAGS"} \
            -DCMAKE_INSTALL_PREFIX="$PREFIX" -DCMAKE_PREFIX_PATH="$PREFIX" ..
        LD_LIBRARY_PATH="$PREFIX/lib"
        export LD_LIBRARY_PATH
    else
        run_after_echo cmake $cmake_crypto_option -DENABLE_SMB="$SMB" \
             ${CFLAGS:+-DEXTRA_CFLAGS="$CFLAGS"} \
            -DCMAKE_INSTALL_PREFIX="$PREFIX" ..
    fi
fi
run_after_echo "$MAKE_BIN" -s clean
if [ "$CMAKE" = no ]; then
    run_after_echo "$MAKE_BIN" -s ${CFLAGS:+CFLAGS="$CFLAGS"}
else
    # The "-s" flag is a no-op and CFLAGS is set using -DEXTRA_CFLAGS above.
    run_after_echo "$MAKE_BIN"
fi
run_after_echo "$MAKE_BIN" install
print_so_deps "$TCPDUMP_BIN"
run_after_echo "$TCPDUMP_BIN" -h
# The "-D" flag depends on HAVE_PCAP_FINDALLDEVS and it would not be difficult
# to run the command below only if the macro is defined.  That said, it seems
# more useful to run it anyway: every system that currently runs this script
# has pcap_findalldevs(), thus if the macro isn't defined, it means something
# went wrong in the build process (as was observed with GCC, CMake and the
# system libpcap on Solaris 11).
run_after_echo "$TCPDUMP_BIN" -D
if [ "$CIRRUS_CI" = true ]; then
    # Likewise for the "-J" flag and HAVE_PCAP_SET_TSTAMP_TYPE.
    run_after_echo sudo \
        ${LD_LIBRARY_PATH:+LD_LIBRARY_PATH="$LD_LIBRARY_PATH"} \
        "$TCPDUMP_BIN" -J
    run_after_echo sudo \
        ${LD_LIBRARY_PATH:+LD_LIBRARY_PATH="$LD_LIBRARY_PATH"} \
        "$TCPDUMP_BIN" -L
fi
if [ "$BUILD_LIBPCAP" = yes ]; then
    run_after_echo "$MAKE_BIN" check
fi
if [ "$CMAKE" = no ]; then
    run_after_echo "$MAKE_BIN" releasetar
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
