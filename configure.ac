dnl Copyright (c) 1994, 1995, 1996, 1997
dnl	The Regents of the University of California.  All rights reserved.
dnl
dnl Process this file with autoconf to produce a configure script.
dnl

#
# See
#
#	https://ftp.gnu.org/gnu/config/README
#
# for the URLs to use to fetch new versions of config.guess and
# config.sub.
#

AC_PREREQ([2.69])
AC_INIT(
	[tcpdump],
	[m4_esyscmd_s(cat VERSION)],
	[https://github.com/the-tcpdump-group/tcpdump/issues],
	[tcpdump],
	[https://www.tcpdump.org/])
AC_CONFIG_SRCDIR(tcpdump.c)

AC_CANONICAL_HOST

AC_LBL_C_INIT_BEFORE_CC(V_INCLS)
#
# Try to enable as many C99 features as we can.
# At minimum, we want C++/C99-style // comments.
#
AC_PROG_CC_C99
if test "$ac_cv_prog_cc_c99" = "no"; then
	AC_MSG_WARN([The C compiler does not support C99; there may be compiler errors])
fi
AC_LBL_C_INIT(V_CCOPT, V_INCLS)

#
# Test for ONC RPC headers.
#
# XXX - we should supply copies of these, as I think Sun released them
# under a sufficiently permissive license, and that would be one less
# place where we rely on OS headers, rather than our own headers, for
# a protocol that is specified independent of any particular OS.
#
AC_CHECK_HEADERS(rpc/rpc.h rpc/rpcent.h)

# On Linux, if Autoconf version >= 2.72 and GNU C Library version >= 2.34,
# uncomment AC_SYS_YEAR2038_RECOMMENDED to ensure time_t is Y2038-safe.
# (Can be done by autogen.sh)
# AC_SYS_YEAR2038_RECOMMENDED
#
# Get the size of a void *, to know whether this is a 32-bit or 64-bit build.
#
AC_CHECK_SIZEOF([void *])

#
# Get the size of a time_t, to know whether it's 32-bit or 64-bit.
#
AC_CHECK_SIZEOF([time_t],,[#include <time.h>])

case "$host_os" in

darwin*)
	AC_ARG_ENABLE(universal,
	AS_HELP_STRING([--disable-universal],[don't build universal on macOS]))
	if test "$enable_universal" != "no"; then
		case "$host_os" in

		darwin9.*)
			#
			# Leopard.  Build for x86 and 32-bit PowerPC, with
			# x86 first.  (That's what Apple does.)
			#
			V_CCOPT="$V_CCOPT -arch i386 -arch ppc"
			LDFLAGS="$LDFLAGS -arch i386 -arch ppc"
			;;

		darwin10.*)
			#
			# Snow Leopard.  Build for x86-64 and x86, with
			# x86-64 first.  (That's what Apple does.)
			#
			V_CCOPT="$V_CCOPT -arch x86_64 -arch i386"
			LDFLAGS="$LDFLAGS -arch x86_64 -arch i386"
			;;
		esac
	fi
	;;
esac

#
# Do we have pkg-config?
#
PKG_PROG_PKG_CONFIG

#
# Do we have the brew command from Homebrew?
#
case "$host_os" in
darwin*|linux*)
	AC_PATH_PROG([BREW], [brew])
	;;
esac

AC_ARG_WITH([smi],
   [AS_HELP_STRING([--with-smi],
     [link with libsmi (allows to load MIBs on the fly to decode SNMP packets) [default=yes, if available]])],
   [],
   [with_smi=yes])

if test "x$with_smi" != "xno" ; then
	AC_CHECK_HEADER(smi.h,
	[
		#
		# OK, we found smi.h.  Do we have libsmi with smiInit?
		#
		AC_CHECK_LIB(smi, smiInit,
		[
			#
			# OK, we have libsmi with smiInit.  Can we use it?
			#
			AC_MSG_CHECKING([whether to enable libsmi])
			savedlibs="$LIBS"
			LIBS="-lsmi $LIBS"
			AC_RUN_IFELSE([AC_LANG_SOURCE([[
/* libsmi available check */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <smi.h>
int main()
{
  int current, revision, age, n;
  const int required = 2;
  if (smiInit(""))
    exit(1);
  if (strcmp(SMI_LIBRARY_VERSION, smi_library_version))
    exit(2);
  n = sscanf(smi_library_version, "%d:%d:%d", &current, &revision, &age);
  if (n != 3)
    exit(3);
  if (required < current - age || required > current)
    exit(4);
  exit(0);
}
				]])
				],
				[
					AC_MSG_RESULT(yes)
					AC_DEFINE(USE_LIBSMI, 1,
					    [Define if you enable support for libsmi])
				],
				[
					dnl autoconf documentation says that
					dnl $? contains the exit value.
					dnl reality is that it does not.
					dnl We leave this in just in case
					dnl autoconf ever comes back to
					dnl match the documentation.
					case $? in
					  1) AC_MSG_RESULT(no - smiInit failed) ;;
					  2) AC_MSG_RESULT(no - header/library version mismatch) ;;
					  3) AC_MSG_RESULT(no - can't determine library version) ;;
					  4) AC_MSG_RESULT(no - too old) ;;
					  *) AC_MSG_RESULT(no) ;;
					esac
					LIBS="$savedlibs"
				],
				[
					AC_MSG_RESULT(not when cross-compiling)
					LIBS="$savedlibs"
				]
			)
		])
	])
fi

AC_MSG_CHECKING([whether to enable the instrument functions code])
AC_ARG_ENABLE([instrument-functions],
   [AS_HELP_STRING([--enable-instrument-functions],
     [enable instrument functions code [default=no]])],
   [],
   [enableval=no])
case "$enableval" in
yes)	AC_MSG_RESULT(yes)
	AC_CHECK_LIB([bfd], [bfd_init],
	    [true],
	    [AC_MSG_ERROR(
	       [--enable-instrument-functions was given, but test for library libbfd failed. Please install the 'binutils-dev' package.])],
	    [])
	AC_DEFINE(ENABLE_INSTRUMENT_FUNCTIONS, 1,
	    [define if you want to build the instrument functions code])
	LOCALSRC="$LOCALSRC instrument-functions.c"
	# Add '-finstrument-functions' instrumentation option to generate
	# instrumentation calls for entry and exit to functions.
	# Try to avoid Address Space Layout Randomization (ALSR).
	CFLAGS="$CFLAGS -O0 -ggdb -finstrument-functions -fno-stack-protector -fno-pic"
	LDFLAGS="$LDFLAGS -O0 -ggdb -fno-stack-protector -no-pie"
	LIBS="$LIBS -lbfd"
	;;
*)	AC_MSG_RESULT(no)
	;;
esac

AC_MSG_CHECKING([whether to enable the possibly-buggy SMB printer])
AC_ARG_ENABLE([smb],
   [AS_HELP_STRING([--enable-smb],
     [enable possibly-buggy SMB printer [default=no]])],
   [],
   [enableval=no])
case "$enableval" in
yes)	AC_MSG_RESULT(yes)
	AC_DEFINE(ENABLE_SMB, 1,
	    [define if you want to build the possibly-buggy SMB printer])
	LOCALSRC="print-smb.c smbutil.c $LOCALSRC"
	;;
*)	AC_MSG_RESULT(no)
	;;
esac

AC_MSG_CHECKING([whether to drop root privileges by default])
AC_ARG_WITH(
	[user],
	[AS_HELP_STRING([--with-user=USERNAME],
		[drop privileges by default to USERNAME]
	)],
	[],
	[withval=no])
AS_CASE(["$withval"],
	[no], [AC_MSG_RESULT(no)],
	[''|yes], [AC_MSG_ERROR([--with-user requires a username])],
	[
		AC_DEFINE_UNQUOTED(WITH_USER, "$withval",
		    [define if should drop privileges by default])
		AC_MSG_RESULT([yes, to user "$withval"])
	]
)

AC_MSG_CHECKING([whether to chroot])
AC_ARG_WITH(
	[chroot],
	[AS_HELP_STRING([--with-chroot=DIRECTORY],
		[when dropping privileges, chroot to DIRECTORY]
	)],
	[],
	[withval=no]
)
AS_CASE(["$withval"],
	[no], [AC_MSG_RESULT(no)],
	[''|yes], [AC_MSG_ERROR([--with-chroot requires a directory])],
	[
		AC_DEFINE_UNQUOTED(WITH_CHROOT, "$withval",
		    [define if should chroot when dropping privileges])
		AC_MSG_RESULT([yes, to directory "$withval"])
	]
)

AC_ARG_WITH(sandbox-capsicum,
	AS_HELP_STRING([--with-sandbox-capsicum],
		       [use Capsicum security functions @<:@default=yes, if available@:>@]))

# Capsicum is available on FreeBSD only.
expr "$host_os" : freebsd >/dev/null || with_sandbox_capsicum=no

#
# Check whether various functions are available.  If any are, set
# ac_lbl_capsicum_function_seen to yes; if any are not, set
# ac_lbl_capsicum_function_not_seen to yes.
#
# We don't check cap_rights_init(), as it's a macro, wrapping another
# function, in at least some versions of FreeBSD, and AC_CHECK_FUNCS()
# doesn't handle that.
#
# All of the ones we check for must be available in order to enable
# capsicum sandboxing.
#
# XXX - do we need to check for all of them, or are there some that, if
# present, imply others are present?
#
if test -z "$with_sandbox_capsicum" || test "$with_sandbox_capsicum" != "no" ; then
	#
	# First, make sure we have the required header.
	#
	AC_CHECK_HEADER(sys/capsicum.h,
	[
		#
		# We do; now make sure we have the required functions.
		#
		AC_CHECK_FUNCS(cap_enter cap_rights_limit cap_ioctls_limit openat,
		    ac_lbl_capsicum_function_seen=yes,
		    ac_lbl_capsicum_function_not_seen=yes)
	])
	AC_CHECK_LIB(casper, cap_init, LIBS="$LIBS -lcasper")
	AC_CHECK_LIB(cap_dns, cap_gethostbyaddr, LIBS="$LIBS -lcap_dns")
fi
AC_MSG_CHECKING([whether to sandbox using capsicum])
if test "x$ac_lbl_capsicum_function_seen" = "xyes" -a "x$ac_lbl_capsicum_function_not_seen" != "xyes"; then
	AC_DEFINE(HAVE_CAPSICUM, 1, [capsicum support available])
	AC_MSG_RESULT(yes)
else
	AC_MSG_RESULT(no)
fi
AC_MSG_CHECKING([whether to sandbox using Casper library])
if test "x$ac_cv_lib_casper_cap_init" = "xyes" -a "x$ac_cv_lib_cap_dns_cap_gethostbyaddr" = "xyes"; then
	AC_DEFINE(HAVE_CASPER, 1, [Casper support available])
	AC_MSG_RESULT(yes)
else
	AC_MSG_RESULT(no)
fi

#
# XXX - we used to check this before checking whether to check the OS's
# IPv6, support because, on some platforms (such as SunOS 5.x), the test
# program requires the extra networking libraries.  We no longer
# test for IPv6 support, we just assume it's present with the
# standard API, so perhaps this can be moved.
#
AC_LBL_LIBRARY_NET

AC_REPLACE_FUNCS(strlcat strlcpy strsep getservent getopt_long)
AC_CHECK_FUNCS(fork vfork)

#
# It became apparent at some point that using a suitable C99 compiler does not
# automatically mean snprintf(3) implementation in the libc supports all the
# modifiers and specifiers used in the project, so let's test that before the
# build, not after.
#
# Testing the sizeof_t length modifier takes making an snprintf() call and
# comparing the actual result with the expected result.  If this fails, it will
# most likely happen at run time, not compile time.
#
# Testing the 64-bit conversion specifiers in addition to that requires the
# <inttypes.h> header to be present and the macros to be defined, so if this
# fails, it will more likely happen at compile time.
#
AC_MSG_CHECKING([whether snprintf is suitable])
AC_RUN_IFELSE(
    [
        AC_LANG_SOURCE([[
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <sys/types.h>

#if defined(_WIN32) && !defined(_SSIZE_T_DEFINED)
/*
 * On UN*Xes, this is a signed integer type of the same size as size_t.
 *
 * It's not defined by Visual Studio; we assume that ptrdiff_t will
 * be a type that is a signed integer type of the same size as size_t.
 */
typedef ptrdiff_t ssize_t;
#endif

/*
 * Avoid trying to cast negative values to unsigned types, or doing
 * shifts of signed types, in order not to have the test program fail
 * if we're building with undefined-behavior sanitizers enabled.
 */
int main()
{
  char buf[100];
  unsigned int ui = sizeof(buf);
  int i = sizeof(buf);
  int64_t i64 = INT64_C(0x100000000);
  uint64_t ui64 = UINT64_C(0x100000000);

  snprintf(buf, sizeof(buf), "%zu", (size_t)ui);
  if (strncmp(buf, "100", sizeof(buf)))
    return 1;

  snprintf(buf, sizeof(buf), "%zd", (ssize_t)(-i));
  if (strncmp(buf, "-100", sizeof(buf)))
    return 2;

  snprintf(buf, sizeof(buf), "%" PRId64, -i64);
  if (strncmp(buf, "-4294967296", sizeof(buf)))
    return 3;

  snprintf(buf, sizeof(buf), "0o%" PRIo64, ui64);
  if (strncmp(buf, "0o40000000000", sizeof(buf)))
    return 4;

  snprintf(buf, sizeof(buf), "0x%" PRIx64, ui64);
  if (strncmp(buf, "0x100000000", sizeof(buf)))
    return 5;

  snprintf(buf, sizeof(buf), "%" PRIu64, ui64);
  if (strncmp(buf, "4294967296", sizeof(buf)))
    return 6;

  return 0;
}
        ]])
    ],
    [
        AC_MSG_RESULT(yes)
    ],
    [
        AC_MSG_RESULT(no)
        AC_MSG_ERROR(
[The snprintf(3) implementation in this libc is not suitable,
tcpdump would not work correctly even if it managed to compile.])
    ],
    [
        AC_MSG_RESULT(not while cross-compiling)
    ]
)

AC_CHECK_LIB(rpc, main)		dnl It's unclear why we might need -lrpc

dnl Some platforms may need -lnsl for getrpcbynumber.
AC_SEARCH_LIBS(getrpcbynumber, nsl,
    AC_DEFINE(HAVE_GETRPCBYNUMBER, 1, [define if you have getrpcbynumber()]))

AC_LBL_LIBPCAP(V_PCAPDEP, V_INCLS)

#
# Check for these after AC_LBL_LIBPCAP, so we link with the appropriate
# libraries (e.g., "-lsocket -lnsl" on Solaris).
#
# You are in a twisty little maze of UN*Xes, all different.
# Some might not have ether_ntohost().
# Some might have it and declare it in <net/ethernet.h>.
# Some might have it and declare it in <netinet/ether.h>
# Some might have it and declare it in <sys/ethernet.h>.
# Some might have it and declare it in <arpa/inet.h>.
# Some might have it and declare it in <netinet/if_ether.h>.
# Some might have it and not declare it in any header file.
#
# Before you is a C compiler.
#
AC_CHECK_FUNCS(ether_ntohost, [
	#
	# OK, we have ether_ntohost().  Is it declared in <net/ethernet.h>?
	#
	# This test fails if we don't have <net/ethernet.h> or if we do
	# but it doesn't declare ether_ntohost().
	#
	AC_CHECK_DECL(ether_ntohost,
	    [
		AC_DEFINE(NET_ETHERNET_H_DECLARES_ETHER_NTOHOST,1,
		    [Define to 1 if net/ethernet.h declares `ether_ntohost'])
	    ],,
	    [
#include <net/ethernet.h>
	    ])
	#
	# Did that succeed?
	#
	if test "$ac_cv_have_decl_ether_ntohost" != yes; then
		#
		# No, how about <netinet/ether.h>, as on Linux?
		#
		# This test fails if we don't have <netinet/ether.h>
		# or if we do but it doesn't declare ether_ntohost().
		#
		# Unset ac_cv_have_decl_ether_ntohost so we don't
		# treat the previous failure as a cached value and
		# suppress the next test.
		#
		unset ac_cv_have_decl_ether_ntohost
		AC_CHECK_DECL(ether_ntohost,
		    [
			AC_DEFINE(NETINET_ETHER_H_DECLARES_ETHER_NTOHOST,1,
			    [Define to 1 if netinet/ether.h declares `ether_ntohost'])
		    ],,
		    [
#include <netinet/ether.h>
		    ])
	fi
	#
	# Did that succeed?
	#
	if test "$ac_cv_have_decl_ether_ntohost" != yes; then
		#
		# No, how about <sys/ethernet.h>, as on Solaris 10
		# and later?
		#
		# This test fails if we don't have <sys/ethernet.h>
		# or if we do but it doesn't declare ether_ntohost().
		#
		# Unset ac_cv_have_decl_ether_ntohost so we don't
		# treat the previous failure as a cached value and
		# suppress the next test.
		#
		unset ac_cv_have_decl_ether_ntohost
		AC_CHECK_DECL(ether_ntohost,
		    [
			AC_DEFINE(SYS_ETHERNET_H_DECLARES_ETHER_NTOHOST,1,
			    [Define to 1 if sys/ethernet.h declares `ether_ntohost'])
		    ],,
		    [
#include <sys/ethernet.h>
		    ])
	fi
	#
	# Did that succeed?
	#
	if test "$ac_cv_have_decl_ether_ntohost" != yes; then
		#
		# No, how about <arpa/inet.h>, as in AIX?
		#
		# This test fails if we don't have <arpa/inet.h>
		# (if we have ether_ntohost(), we should have
		# networking, and if we have networking, we should
		# have <arpa/inet.h>) or if we do but it doesn't
		# declare ether_ntohost().
		#
		# Unset ac_cv_have_decl_ether_ntohost so we don't
		# treat the previous failure as a cached value and
		# suppress the next test.
		#
		unset ac_cv_have_decl_ether_ntohost
		AC_CHECK_DECL(ether_ntohost,
		    [
			AC_DEFINE(ARPA_INET_H_DECLARES_ETHER_NTOHOST,1,
			    [Define to 1 if arpa/inet.h declares `ether_ntohost'])
		    ],,
		    [
#include <arpa/inet.h>
		    ])
	fi
	#
	# Did that succeed?
	#
	if test "$ac_cv_have_decl_ether_ntohost" != yes; then
		#
		# No, how about <netinet/if_ether.h>?
		# On some platforms, it requires <net/if.h> and
		# <netinet/in.h>, and we always include it with
		# both of them, so test it with both of them.
		#
		# This test fails if we don't have <netinet/if_ether.h>
		# and the headers we include before it, or if we do but
		# <netinet/if_ether.h> doesn't declare ether_hostton().
		#
		# Unset ac_cv_have_decl_ether_ntohost so we don't
		# treat the previous failure as a cached value and
		# suppress the next test.
		#
		unset ac_cv_have_decl_ether_ntohost
		AC_CHECK_DECL(ether_ntohost,
		    [
			AC_DEFINE(NETINET_IF_ETHER_H_DECLARES_ETHER_NTOHOST,1,
			    [Define to 1 if netinet/if_ether.h declares `ether_ntohost'])
		    ],,
		    [
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
		    ])
	fi
	#
	# After all that, is ether_ntohost() declared?
	#
	if test "$ac_cv_have_decl_ether_ntohost" = yes; then
		#
		# Yes.
		#
		AC_DEFINE(HAVE_DECL_ETHER_NTOHOST, 1,
		    [Define to 1 if you have the declaration of `ether_ntohost'])
	else
		#
		# No, we'll have to declare it ourselves.
		# Do we have "struct ether_addr" if we include
		# <netinet/if_ether.h>?
		#
		AC_CHECK_TYPES(struct ether_addr,,,
		    [
			#include <sys/types.h>
			#include <sys/socket.h>
			#include <net/if.h>
			#include <netinet/in.h>
			#include <netinet/if_ether.h>
		    ])
	fi
    AC_CACHE_CHECK(for buggy ether_ntohost, ac_cv_buggy_ether_ntohost, [
	AC_RUN_IFELSE([AC_LANG_SOURCE([[
  #include <netdb.h>
  #if defined(NET_ETHERNET_H_DECLARES_ETHER_NTOHOST)
    /*
     * OK, just include <net/ethernet.h>.
     */
    #include <net/ethernet.h>
  #elif defined(NETINET_ETHER_H_DECLARES_ETHER_NTOHOST)
    /*
     * OK, just include <netinet/ether.h>
     */
    #include <netinet/ether.h>
  #elif defined(SYS_ETHERNET_H_DECLARES_ETHER_NTOHOST)
    /*
     * OK, just include <sys/ethernet.h>
     */
    #include <sys/ethernet.h>
  #elif defined(ARPA_INET_H_DECLARES_ETHER_NTOHOST)
    /*
     * OK, just include <arpa/inet.h>
     */
    #include <arpa/inet.h>
  #elif defined(NETINET_IF_ETHER_H_DECLARES_ETHER_NTOHOST)
    /*
     * OK, include <netinet/if_ether.h>, after all the other stuff we
     * need to include or define for its benefit.
     */
    #define NEED_NETINET_IF_ETHER_H
  #else
    /*
     * We'll have to declare it ourselves.
     * If <netinet/if_ether.h> defines struct ether_addr, include
     * it.  Otherwise, define it ourselves.
     */
    #ifdef HAVE_STRUCT_ETHER_ADDR
      #define NEED_NETINET_IF_ETHER_H
    #else /* HAVE_STRUCT_ETHER_ADDR */
	struct ether_addr {
		/* Beware FreeBSD calls this "octet". */
		unsigned char ether_addr_octet[MAC_ADDR_LEN];
	};
    #endif /* HAVE_STRUCT_ETHER_ADDR */
  #endif /* what declares ether_ntohost() */

  #ifdef NEED_NETINET_IF_ETHER_H
    /*
     * Include diag-control.h before <net/if.h>, which too defines a macro
     * named ND_UNREACHABLE.
     */
    #include "diag-control.h"
    #include <net/if.h>		/* Needed on some platforms */
    #include <netinet/in.h>	/* Needed on some platforms */
    #include <netinet/if_ether.h>
  #endif /* NEED_NETINET_IF_ETHER_H */

  #ifndef HAVE_DECL_ETHER_NTOHOST
    /*
     * No header declares it, so declare it ourselves.
     */
    extern int ether_ntohost(char *, const struct ether_addr *);
  #endif /* !defined(HAVE_DECL_ETHER_NTOHOST) */
  #include <stdlib.h>
  #include <sys/types.h>
  #include <sys/param.h>
  #include <sys/socket.h>

  int
  main(int argc, char **argv)
  {
    u_char ea[6] = { 0xff, 0xff, 0xff, 0xff, 0xff };
    char name[MAXHOSTNAMELEN];

    ether_ntohost(name, (struct ether_addr *)ea);
    exit(0);
  }
	]])
	], [ac_cv_buggy_ether_ntohost=no],
	   [ac_cv_buggy_ether_ntohost=yes],
	   [ac_cv_buggy_ether_ntohost="not while cross-compiling"])])
    if test "$ac_cv_buggy_ether_ntohost" = "no"; then
	AC_DEFINE(USE_ETHER_NTOHOST, 1,
	    [define if you have ether_ntohost() and it works])
    fi
])

#
# Do we have the new open API?  Check for pcap_create, and assume that,
# if we do, we also have pcap_activate() and the other new routines
# introduced in libpcap 1.0.
#
# We require those routines, so fail if we don't find it.
#
AC_CHECK_FUNC(pcap_create,,
    [AC_MSG_ERROR([libpcap is too old; 1.0 or later is required])])

#
# OK, do we have pcap_set_tstamp_type?  If so, assume we have
# pcap_list_tstamp_types and pcap_free_tstamp_types as well.
#
AC_CHECK_FUNCS(pcap_set_tstamp_type)
#
# And do we have pcap_set_tstamp_precision?  If so, we assume
# we also have pcap_open_offline_with_tstamp_precision.
#
AC_CHECK_FUNCS(pcap_set_tstamp_precision)

#
# Check for a miscellaneous collection of functions which we use
# if we have them.
#
AC_CHECK_FUNCS(pcap_set_immediate_mode pcap_dump_ftell64)
#
# See the comment in AC_LBL_LIBPCAP in aclocal.m4 for the reason
# why we don't check for remote-capture APIs if we're building
# with the system libpcap on macOS.
#
if test "$_dont_check_for_remote_apis" != "yes"; then
	AC_CHECK_FUNCS(pcap_open pcap_findalldevs_ex)
fi

#
# Check for special debugging functions
#
AC_CHECK_FUNCS(pcap_set_parser_debug)
if test "$ac_cv_func_pcap_set_parser_debug" = "no" ; then
	#
	# OK, we don't have pcap_set_parser_debug() to set the libpcap
	# filter expression parser debug flag; can we directly set the
	# flag?
	AC_MSG_CHECKING(whether pcap_debug is defined by libpcap)
	AC_LINK_IFELSE([AC_LANG_PROGRAM([[]], [[
		extern int pcap_debug;

		return pcap_debug;
	   ]])
	   ],
	   [ac_lbl_cv_pcap_debug_defined=yes],
	   [ac_lbl_cv_pcap_debug_defined=no])
	if test "$ac_lbl_cv_pcap_debug_defined" = yes ; then
		AC_MSG_RESULT(yes)
		AC_DEFINE(HAVE_PCAP_DEBUG, 1, [define if libpcap has pcap_debug])
	else
		AC_MSG_RESULT(no)
		#
		# OK, what about "yydebug"?
		#
		AC_MSG_CHECKING(whether yydebug is defined by libpcap)
		AC_LINK_IFELSE([AC_LANG_PROGRAM([[]], [[
			extern int yydebug;

			return yydebug;
		   ]])
		   ],
		   [ac_lbl_cv_yydebug_defined=yes],
		   [ac_lbl_cv_yydebug_defined=no])
		if test "$ac_lbl_cv_yydebug_defined" = yes ; then
			AC_MSG_RESULT(yes)
			AC_DEFINE(HAVE_YYDEBUG, 1, [define if libpcap has yydebug])
		else
			AC_MSG_RESULT(no)
		fi
	fi
fi
AC_CHECK_FUNCS(pcap_set_optimizer_debug)

#
# bpf_dump() moved from tcpdump to libpcap in libpcap 0.6, but some
# versions of libpcap didn't pick that change up; the OpenBSD libpcap
# picked up most of the new APIs from versions up to 1.0, but didn't
# pick up bpf_dump(), so we need to provide it if it's absent.
#
AC_REPLACE_FUNCS(bpf_dump)	dnl moved to libpcap in 0.6

#
# Assume V7/BSD convention for man pages (file formats in section 5,
# miscellaneous info in section 7).
#
MAN_FILE_FORMATS=5
MAN_MISC_INFO=7
case "$host_os" in

hpux*)
	#
	# Use System V conventions for man pages.
	#
	MAN_FILE_FORMATS=4
	MAN_MISC_INFO=5
	;;

solaris*)
	#
	# Use System V conventions for man pages.
	#
	MAN_FILE_FORMATS=4
	MAN_MISC_INFO=5
	;;
esac

savedcppflags="$CPPFLAGS"
CPPFLAGS="$CPPFLAGS $V_INCLS"

#
# Check whether we have pcap/pcap-inttypes.h.
# If we do, we use that to get the C99 types defined.
#
AC_CHECK_HEADERS(pcap/pcap-inttypes.h)

CPPFLAGS="$savedcppflags"

#
# Define the old BSD specified-width types in terms of the C99 types;
# we may need them with libpcap include files.
#
AC_CHECK_TYPE([u_int8_t], ,
	[AC_DEFINE([u_int8_t], [uint8_t],
	[Define to `uint8_t' if u_int8_t not defined.])],
	[AC_INCLUDES_DEFAULT
#include <sys/types.h>
])
AC_CHECK_TYPE([u_int16_t], ,
	[AC_DEFINE([u_int16_t], [uint16_t],
	[Define to `uint16_t' if u_int16_t not defined.])],
	[AC_INCLUDES_DEFAULT
#include <sys/types.h>
])
AC_CHECK_TYPE([u_int32_t], ,
	[AC_DEFINE([u_int32_t], [uint32_t],
	[Define to `uint32_t' if u_int32_t not defined.])],
	[AC_INCLUDES_DEFAULT
#include <sys/types.h>
])
AC_CHECK_TYPE([u_int64_t], ,
	[AC_DEFINE([u_int64_t], [uint64_t],
	[Define to `uint64_t' if u_int64_t not defined.])],
	[AC_INCLUDES_DEFAULT
#include <sys/types.h>
])

AC_PROG_RANLIB
AC_CHECK_TOOL([AR], [ar])

AC_LBL_DEVEL(V_CCOPT)

# Check for OpenSSL/libressl libcrypto
AC_MSG_CHECKING(whether to use OpenSSL/libressl libcrypto)
# Specify location for both includes and libraries.
want_libcrypto=ifavailable
AC_ARG_WITH(crypto,
    AS_HELP_STRING([--with-crypto]@<:@=DIR@:>@,
		   [use OpenSSL/libressl libcrypto (located in directory DIR, if specified) @<:@default=yes, if available@:>@]),
[
	if test $withval = no
	then
		# User doesn't want to link with libcrypto.
		want_libcrypto=no
		AC_MSG_RESULT(no)
	elif test $withval = yes
	then
		# User wants to link with libcrypto but hasn't specified
		# a directory.
		want_libcrypto=yes
		AC_MSG_RESULT(yes)
	else
		# User wants to link with libcrypto and has specified
		# a directory, so use the provided value.
		want_libcrypto=yes
		libcrypto_root=$withval
		AC_MSG_RESULT([yes, using the version installed in $withval])
	fi
],[
	#
	# Use libcrypto if it's present, otherwise don't; no directory
	# was specified.
	#
	want_libcrypto=ifavailable
	AC_MSG_RESULT([yes, if available])
])
if test "$want_libcrypto" != "no"; then
	#
	# Were we told where to look for libcrypto?
	#
	if test -z "$libcrypto_root"; then
		#
		# No.
		#
		# First, try looking for it with pkg-config, if we have it.
		#
		# Homebrew's pkg-config does not, by default, look for
		# pkg-config files for packages it has installed.
		# Furthermore, at least for OpenSSL, they appear to be
		# dumped in package-specific directories whose paths are
		# not only package-specific but package-version-specific.
		#
		# So the only way to find openssl is to get the value of
		# PKG_CONFIG_PATH from "brew --env openssl" and add that
		# to PKG_CONFIG_PATH.  (No, we can't just assume it's under
		# /usr/local; Homebrew have conveniently chosen to put it
		# under /opt/homebrew on ARM.)
		#
		# That's the nice thing about Homebrew - it makes things easier!
		# Thanks!
		#
		save_PKG_CONFIG_PATH="$PKG_CONFIG_PATH"
		if test -n "$BREW"; then
			openssl_pkgconfig_dir=`$BREW --env --plain openssl | sed -n 's/PKG_CONFIG_PATH: //p'`
			PKG_CONFIG_PATH="$openssl_pkgconfig_dir:$PKG_CONFIG_PATH"
		fi
		PKG_CHECK_MODULE(LIBCRYPTO, libcrypto,
		    [
			#
			# We found OpenSSL/libressl libcrypto.
			#
			HAVE_LIBCRYPTO=yes
		    ])
		PKG_CONFIG_PATH="$save_PKG_CONFIG_PATH"

		#
		# If it wasn't found, and we have Homebrew installed, see
		# if it's in Homebrew.
		#
		if test "x$HAVE_LIBCRYPTO" != "xyes" -a -n "$BREW"; then
			AC_MSG_CHECKING(for openssl in Homebrew)
			#
			# The brew man page lies when it speaks of
			# $BREW --prefix --installed <formula>
			# outputting nothing.  In Homebrew 3.3.16,
			# it produces output regardless of whether
			# the formula is installed or not, so we
			# send the standard output and error to
			# the bit bucket.
			#
			# libcrypto isn't a formula, openssl is a formula.
			#
			if $BREW --prefix --installed openssl >/dev/null 2>&1; then
				#
				# Yes.  Get the include directory and library
				# directory.  (No, we can't just assume it's
				# under /usr/local; Homebrew have conveniently
				# chosen to put it under /opt/homebrew on ARM.)
				#
				AC_MSG_RESULT(yes)
				HAVE_LIBCRYPTO=yes
				openssl_path=`$BREW --prefix openssl`
				LIBCRYPTO_CFLAGS="-I$openssl_path/include"
				LIBCRYPTO_LIBS="-L$openssl_path/lib -lcrypto"
			else
				AC_MSG_RESULT(no)
			fi
		fi

		#
		# If it wasn't found, and /usr/local/include and /usr/local/lib
		# exist, check if it's in /usr/local.  (We check whether they
		# exist because, if they don't exist, the compiler will warn
		# about that and then ignore the argument, so they test
		# using just the system header files and libraries.)
		#
		# We include the standard include file to 1) make sure that
		# it's installed (if it's just a shared library for the
		# benefit of existing programs, that's not useful) and 2)
		# because SSL_library_init() is a library routine in some
		# versions and a #defined wrapper around OPENSSL_init_ssl()
		# in others.
		#
		if test "x$HAVE_LIBCRYPTO" != "xyes" -a -d "/usr/local/include" -a -d "/usr/local/lib"; then
			AC_LBL_SAVE_CHECK_STATE
			CFLAGS="$CFLAGS -I/usr/local/include"
			LIBS="$LIBS -L/usr/local/lib -lcrypto"
			AC_MSG_CHECKING(whether we have an OpenSSL/libressl libcrypto in /usr/local that we can use)
			AC_LINK_IFELSE([AC_LANG_PROGRAM(
			    [[
#include <openssl/evp.h>
			    ]],
			    [[
EVP_CIPHER_CTX_block_size((EVP_CIPHER_CTX *)0);
return 0;
			    ]])],
			    [
				AC_MSG_RESULT(yes)
				HAVE_LIBCRYPTO=yes
				LIBCRYPTO_CFLAGS="-I/usr/local/include"
				LIBCRYPTO_LIBS="-L/usr/local/lib -lcrypto"
			    ],
			    AC_MSG_RESULT(no))
			AC_LBL_RESTORE_CHECK_STATE
		fi

		#
		# If it wasn't found, check if it's a system library.
		#
		# We include the standard include file to 1) make sure that
		# it's installed (if it's just a shared library for the
		# benefit of existing programs, that's not useful) and 2)
		# make sure this isn't a newer macOS that provides libcrypto
		# as a shared library but doesn't provide headers - Apple,
		# bless their pointy little heads, apparently ship libcrypto
		# as a library, but not the header files, in El Capitan and
		# later, probably because they don't want you writing nasty
		# portable code that could run on other UN*Xes, they want you
		# writing code that uses their Shiny New Crypto Library and
		# that thus only runs on macOS.
		#
		if test "x$HAVE_LIBCRYPTO" != "xyes"; then
			AC_LBL_SAVE_CHECK_STATE
			LIBS="$LIBS -lcrypto"
			AC_MSG_CHECKING(whether we have a system OpenSSL/libressl that we can use)
			AC_LINK_IFELSE([AC_LANG_PROGRAM(
			    [[
#include <openssl/evp.h>
			    ]],
			    [[
EVP_CIPHER_CTX_block_size((EVP_CIPHER_CTX *)0);
return 0;
			    ]])],
			    [
				AC_MSG_RESULT(yes)
				HAVE_LIBCRYPTO=yes
				LIBCRYPTO_LIBS="-lcrypto"
			    ],
			    AC_MSG_RESULT(no))
			AC_LBL_RESTORE_CHECK_STATE
		fi
	else
		#
		# Yes.
		#
		# Look for it there.
		#
		AC_LBL_SAVE_CHECK_STATE
		CFLAGS="$CFLAGS -I$libcrypto_root/include"
		LIBS="$LIBS -L$libcrypto_root/lib -lcrypto"
		AC_MSG_CHECKING(whether we have a system OpenSSL/libressl that we can use)
		AC_LINK_IFELSE([AC_LANG_PROGRAM(
		    [[
#include <openssl/evp.h>
		    ]],
		    [[
EVP_CIPHER_CTX_block_size((EVP_CIPHER_CTX *)0);
return 0;
		    ]])],
		    [
			AC_MSG_RESULT(yes)
			HAVE_LIBCRYPTO=yes
			LIBCRYPTO_CFLAGS="-I$libcrypto_root/include"
			LIBCRYPTO_LIBS="-L$libcrypto_root/lib -lcrypto"
		    ],
		    AC_MSG_RESULT(no))
		AC_LBL_RESTORE_CHECK_STATE
	fi

	#
	# OK, did we find it?
	#
	if test "x$HAVE_LIBCRYPTO" = "xyes"; then
		AC_DEFINE([HAVE_LIBCRYPTO], [1], [Define to 1 if you have a usable `crypto' library (-lcrypto).])

		#
		# Put the subdirectories of the libcrypto root directory
		# at the end of the header and library search path, to
		# make sure they come after any -I or -L flags for
		# a local libpcap - those must take precedence of any
		# directory that might contain an installed version of
		# libpcap.
		#
		V_INCLS="$V_INCLS $LIBCRYPTO_CFLAGS"
		LIBS="$LIBS $LIBCRYPTO_LIBS"

		#
		# OK, then:
		#
		# 1) do we have EVP_CIPHER_CTX_new?
		# If so, we use it to allocate an EVP_CIPHER_CTX, as
		# EVP_CIPHER_CTX may be opaque; otherwise, we allocate it
		# ourselves.
		#
		# 2) do we have EVP_DecryptInit_ex()?
		# If so, we use it, because we need to be able to make
		# two "initialize the cipher" calls, one with the cipher
		# and key, and one with the IV, and, as of OpenSSL 1.1,
		# You Can't Do That with EVP_DecryptInit(), because a
		# call to EVP_DecryptInit() will unconditionally clear
		# the context, and if you don't supply a cipher, it'll
		# clear the cipher, rendering the context unusable and
		# causing a crash.
		#
		AC_CHECK_FUNCS(EVP_CIPHER_CTX_new EVP_DecryptInit_ex)
	else
		AC_MSG_NOTICE(OpenSSL/libressl libcrypto not found)
	fi
fi

# Check for libcap-ng
AC_MSG_CHECKING(whether to use libcap-ng)
# Specify location for both includes and libraries.
AC_ARG_WITH(cap_ng,
    AS_HELP_STRING([--with-cap-ng],
		   [use libcap-ng @<:@default=yes, if available@:>@]),
[
	if test $withval = no
	then
		want_libcap_ng=no
		AC_MSG_RESULT(no)
	elif test $withval = yes
	then
		want_libcap_ng=yes
		AC_MSG_RESULT(yes)
	fi
],[
	#
	# Use libcap-ng if it's present, otherwise don't.
	#
	want_libcap_ng=ifavailable
	AC_MSG_RESULT([yes, if available])
])

# libcap-ng is available on Linux only.
expr "$host_os" : linux >/dev/null || want_libcap_ng=no

if test "$want_libcap_ng" != "no"; then
	AC_CHECK_LIB(cap-ng, capng_change_id)
	AC_CHECK_HEADERS(cap-ng.h)
fi

dnl
dnl set additional include path if necessary
if test "$missing_includes" = "yes"; then
	CPPFLAGS="$CPPFLAGS -I$srcdir/missing"
	V_INCLS="$V_INCLS -I$srcdir/missing"
fi

AC_SUBST(V_CCOPT)
AC_SUBST(V_DEFS)
AC_SUBST(V_INCLS)
AC_SUBST(V_PCAPDEP)
AC_SUBST(LOCALSRC)
AC_SUBST(MAN_FILE_FORMATS)
AC_SUBST(MAN_MISC_INFO)

AC_PROG_INSTALL

AC_CONFIG_HEADERS([config.h])
AH_TOP([
#ifndef TCPDUMP_CONFIG_H_
#define TCPDUMP_CONFIG_H_
])
AH_BOTTOM([
#endif // TCPDUMP_CONFIG_H_
])

AC_CONFIG_COMMANDS([.devel],[[if test -f .devel; then
	echo timestamp > stamp-h
	cat $srcdir/Makefile-devel-adds >> Makefile
	make depend || exit 1
fi]])
AC_CONFIG_FILES([Makefile tcpdump.1])
AC_OUTPUT
exit 0
