/*
 * Copyright (c) 2002 - 2003
 * NetGroup, Politecnico di Torino (Italy)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Politecnico di Torino nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Include the appropriate OS header files on Windows and various flavors
 * of UNIX, include various non-OS header files on Windows, and define
 * various items as needed, to isolate most of netdissect's platform
 * differences to this one file.
 */

#ifndef netdissect_stdinc_h
#define netdissect_stdinc_h

#include <errno.h>

#include "compiler-tests.h"

#include "varattrs.h"

/*
 * Get the C99 types, and the PRI[doux]64 format strings, defined.
 */
#ifdef HAVE_PCAP_PCAP_INTTYPES_H
  /*
   * We have pcap/pcap-inttypes.h; use that, as it'll do all the
   * work, and won't cause problems if a file includes this file
   * and later includes a pcap header file that also includes
   * pcap/pcap-inttypes.h.
   */
  #include <pcap/pcap-inttypes.h>
#else
  /*
   * OK, we don't have pcap/pcap-inttypes.h, so we'll have to
   * do the work ourselves, but at least we don't have to
   * worry about other headers including it and causing
   * clashes.
   */
  #if defined(_MSC_VER)
    /*
     * Compiler is MSVC.
     */
    #if _MSC_VER >= 1800
      /*
       * VS 2013 or newer; we have <inttypes.h>.
       */
      #include <inttypes.h>
    #else
      /*
       * Earlier VS; we have to define this stuff ourselves.
       */
      typedef unsigned char uint8_t;
      typedef signed char int8_t;
      typedef unsigned short uint16_t;
      typedef signed short int16_t;
      typedef unsigned int uint32_t;
      typedef signed int int32_t;
      #ifdef _MSC_EXTENSIONS
        typedef unsigned _int64 uint64_t;
        typedef _int64 int64_t;
      #else /* _MSC_EXTENSIONS */
        typedef unsigned long long uint64_t;
        typedef long long int64_t;
      #endif

      /*
       * We have _strtoi64().  Use that for strtoint64_t().
       */
      #define strtoint64_t	_strtoi64
    #endif

    /*
     * Suppress definition of intN_t in bittypes.h, which might be included
     * by <pcap/pcap.h> in older versions of WinPcap.
     * (Yes, HAVE_U_INTn_T, as the definition guards are UN*X-oriented, and
     * we check for u_intN_t in the UN*X configure script.)
     */
    #define HAVE_U_INT8_T
    #define HAVE_U_INT16_T
    #define HAVE_U_INT32_T
    #define HAVE_U_INT64_T

    /*
     * These may be defined by <inttypes.h>.  If not, define them
     * ourselves.
     *
     * XXX - for MSVC, we always want the _MSC_EXTENSIONS versions.
     * What about other compilers?  If, as the MinGW Web site says MinGW
     * does, the other compilers just use Microsoft's run-time library,
     * then they should probably use the _MSC_EXTENSIONS even if the
     * compiler doesn't define _MSC_EXTENSIONS.
     */
    #ifndef PRId64
      #ifdef _MSC_EXTENSIONS
        #define PRId64	"I64d"
      #else
        #define PRId64	"lld"
      #endif
    #endif /* PRId64 */

    #ifndef PRIo64
      #ifdef _MSC_EXTENSIONS
        #define PRIo64	"I64o"
      #else
        #define PRIo64	"llo"
      #endif
    #endif /* PRIo64 */

    #ifndef PRIx64
      #ifdef _MSC_EXTENSIONS
        #define PRIx64	"I64x"
      #else
        #define PRIx64	"llx"
      #endif
    #endif

    #ifndef PRIu64
      #ifdef _MSC_EXTENSIONS
        #define PRIu64	"I64u"
      #else
        #define PRIu64	"llu"
      #endif
    #endif
  #elif defined(__MINGW32__) || !defined(_WIN32)
    /*
     * Compiler is MinGW or target is UN*X or MS-DOS.  Just use
     * <inttypes.h>.
     */
    #include <inttypes.h>
  #endif
#endif /* HAVE_PCAP_PCAP_INTTYPES_H */

#ifdef _WIN32

/*
 * Includes and definitions for Windows.
 */

#include <stdio.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <ctype.h>
#include <time.h>
#include <io.h>
#include <fcntl.h>
#include <sys/types.h>

#ifdef _MSC_VER
  /*
   * Compiler is MSVC.
   */
  #if _MSC_VER >= 1800
    /*
     * VS 2013 or newer; we have strtoll().  Use that for strtoint64_t().
     */
    #define strtoint64_t	strtoll
  #else
    /*
     * Earlier VS; we don't have strtoll(), but we do have
     * _strtoi64().  Use that for strtoint64_t().
     */
    #define strtoint64_t	_strtoi64
  #endif

  /*
   * Microsoft's documentation doesn't speak of LL as a valid
   * suffix for 64-bit integers, so we'll just use i64.
   */
  #define INT64_T_CONSTANT(constant)	(constant##i64)
#else
  /*
   * Non-Microsoft compiler.
   *
   * XXX - should we use strtoll or should we use _strtoi64()?
   */
  #define strtoint64_t		strtoll

  /*
   * Assume LL works.
   */
  #define INT64_T_CONSTANT(constant)	(constant##LL)
#endif

#ifdef _MSC_VER
  /*
   * Microsoft tries to avoid polluting the C namespace with UN*Xisms,
   * by adding a preceding underscore; we *want* the UN*Xisms, so add
   * #defines to let us use them.
   */
  #define isascii __isascii
  #define isatty _isatty
  #define stat _stat
  #define strdup _strdup
  #define open _open
  #define fstat _fstat
  #define read _read
  #define close _close
  #define O_RDONLY _O_RDONLY

  /*
   * If <crtdbg.h> has been included, and _DEBUG is defined, and
   * __STDC__ is zero, <crtdbg.h> will define strdup() to call
   * _strdup_dbg().  So if it's already defined, don't redefine
   * it.
   */
  #ifndef strdup
    #define strdup _strdup
  #endif
#endif  /* _MSC_VER */

/*
 * With MSVC, for C, __inline is used to make a function an inline.
 */
#ifdef _MSC_VER
#define inline __inline
#endif

#if defined(AF_INET6) && !defined(HAVE_OS_IPV6_SUPPORT)
#define HAVE_OS_IPV6_SUPPORT
#endif

#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 46
#endif

/* It is in MSVC's <errno.h>, but not defined in MingW+Watcom.
 */
#ifndef EAFNOSUPPORT
#define EAFNOSUPPORT WSAEAFNOSUPPORT
#endif

#ifndef caddr_t
typedef char* caddr_t;
#endif /* caddr_t */

#define MAXHOSTNAMELEN	64

#else /* _WIN32 */

/*
 * Includes and definitions for various flavors of UN*X.
 */

#include <ctype.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/param.h>
#include <sys/types.h>			/* concession to AIX */
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <time.h>

#include <arpa/inet.h>

/*
 * Assume all UN*Xes have strtoll(), and use it for strtoint64_t().
 */
#define strtoint64_t	strtoll

/*
 * Assume LL works.
 */
#define INT64_T_CONSTANT(constant)	(constant##LL)

#endif /* _WIN32 */

/*
 * Function attributes, for various compilers.
 */
#include "funcattrs.h"

/*
 * On Windows, snprintf(), with that name and with C99 behavior - i.e.,
 * guaranteeing that the formatted string is null-terminated - didn't
 * appear until Visual Studio 2015.  Prior to that, the C runtime had
 * only _snprintf(), which *doesn't* guarantee that the string is
 * null-terminated if it is truncated due to the buffer being too
 * small.  We therefore can't just define snprintf to be _snprintf
 * and define vsnprintf to be _vsnprintf, as we're relying on null-
 * termination of strings in all cases.
 *
 * Furthermore, some versions of Visual Studio prior to Visual
 * Studio 2015 had vsnprintf() (but not snprintf()!), but those
 * versions don't guarantee null termination, either.
 *
 * We assume all UN*Xes that have snprintf() and vsnprintf() provide
 * C99 behavior.
 */
#if defined(_MSC_VER) || defined(__MINGW32__)
  #if defined(_MSC_VER) && _MSC_VER >= 1900
    /*
     * VS 2015 or newer; just use the C runtime's snprintf() and
     * vsnprintf().
     */
    #define nd_snprintf		snprintf
    #define nd_vsnprintf	vsnprintf
  #else /* defined(_MSC_VER) && _MSC_VER >= 1900 */
    /*
     * VS prior to 2015, or MingGW; assume we have _snprintf_s() and
     * _vsnprintf_s(), which guarantee null termination.
     */
    #define nd_snprintf(buf, buflen, ...) \
        _snprintf_s(buf, buflen, _TRUNCATE, __VA_ARGS__)
    #define nd_vsnprintf(buf, buflen, fmt, ap) \
        _vsnprintf_s(buf, buflen, _TRUNCATE, fmt, ap)
  #endif /* defined(_MSC_VER) && _MSC_VER >= 1900 */
#else /* defined(_MSC_VER) || defined(__MINGW32__) */
  /*
   * Some other compiler, which we assume to be a UN*X compiler.
   * Use the system's snprintf() if we have it, otherwise use
   * our own implementation
   */
  #ifdef HAVE_SNPRINTF
    #define nd_snprintf		snprintf
  #else /* HAVE_SNPRINTF */
    int nd_snprintf (char *str, size_t sz, FORMAT_STRING(const char *format), ...)
        PRINTFLIKE(3, 4);
  #endif /* HAVE_SNPRINTF */

  #ifdef HAVE_VSNPRINTF
    #define nd_vsnprintf	vsnprintf
  #else /* HAVE_VSNPRINTF */
    int nd_vsnprintf (char *str, size_t sz, FORMAT_STRING(const char *format),
        va_list ap) PRINTFLIKE(3, 0);
  #endif /* HAVE_VSNPRINTF */
#endif /* defined(_MSC_VER) || defined(__MINGW32__) */

/*
 * fopen() read and write modes for text files and binary files.
 */
#if defined(_WIN32) || defined(MSDOS)
  #define FOPEN_READ_TXT   "rt"
  #define FOPEN_READ_BIN   "rb"
  #define FOPEN_WRITE_TXT  "wt"
  #define FOPEN_WRITE_BIN  "wb"
#else
  #define FOPEN_READ_TXT   "r"
  #define FOPEN_READ_BIN   FOPEN_READ_TXT
  #define FOPEN_WRITE_TXT  "w"
  #define FOPEN_WRITE_BIN  FOPEN_WRITE_TXT
#endif

/*
 * Inline x86 assembler-language versions of ntoh[ls]() and hton[ls](),
 * defined if the OS doesn't provide them.  These assume no more than
 * an 80386, so, for example, it avoids the bswap instruction added in
 * the 80486.
 *
 * (We don't use them on macOS; Apple provides their own, which *doesn't*
 * avoid the bswap instruction, as macOS only supports machines that
 * have it.)
 */
#if defined(__GNUC__) && defined(__i386__) && !defined(__APPLE__) && !defined(__ntohl)
  #undef ntohl
  #undef ntohs
  #undef htonl
  #undef htons

  static __inline__ unsigned long __ntohl (unsigned long x);
  static __inline__ unsigned short __ntohs (unsigned short x);

  #define ntohl(x)  __ntohl(x)
  #define ntohs(x)  __ntohs(x)
  #define htonl(x)  __ntohl(x)
  #define htons(x)  __ntohs(x)

  static __inline__ unsigned long __ntohl (unsigned long x)
  {
    __asm__ ("xchgb %b0, %h0\n\t"   /* swap lower bytes  */
             "rorl  $16, %0\n\t"    /* swap words        */
             "xchgb %b0, %h0"       /* swap higher bytes */
            : "=q" (x) : "0" (x));
    return (x);
  }

  static __inline__ unsigned short __ntohs (unsigned short x)
  {
    __asm__ ("xchgb %b0, %h0"       /* swap bytes */
            : "=q" (x) : "0" (x));
    return (x);
  }
#endif

/*
 * If the OS doesn't define AF_INET6 and struct in6_addr:
 *
 * define AF_INET6, so we can use it internally as a "this is an
 * IPv6 address" indication;
 *
 * define struct in6_addr so that we can use it for IPv6 addresses.
 */
#ifndef HAVE_OS_IPV6_SUPPORT
#ifndef AF_INET6
#define AF_INET6	24

struct in6_addr {
	union {
		__uint8_t   __u6_addr8[16];
		__uint16_t  __u6_addr16[8];
		__uint32_t  __u6_addr32[4];
	} __u6_addr;			/* 128-bit IP6 address */
};
#endif
#endif

#ifndef NI_MAXHOST
#define	NI_MAXHOST	1025
#endif

#ifndef INET_ADDRSTRLEN
#define INET_ADDRSTRLEN 16
#endif

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

/*
 * The Apple deprecation workaround macros below were adopted from the
 * FreeRADIUS server code under permission of Alan DeKok and Arran Cudbard-Bell.
 */

#define XSTRINGIFY(x) #x

/*
 *	Macros for controlling warnings in GCC >= 4.2 and clang >= 2.8
 */
#define DIAG_JOINSTR(x,y) XSTRINGIFY(x ## y)
#define DIAG_DO_PRAGMA(x) _Pragma (#x)

/*
 * The current clang compilers also define __GNUC__ and __GNUC_MINOR__
 * thus we need to test the clang case before the GCC one
 */
#if defined(__clang__)
#  if (__clang_major__ * 100) + __clang_minor__ >= 208
#    define DIAG_PRAGMA(x) DIAG_DO_PRAGMA(clang diagnostic x)
#    define DIAG_OFF(x) DIAG_PRAGMA(push) DIAG_PRAGMA(ignored DIAG_JOINSTR(-W,x))
#    define DIAG_ON(x) DIAG_PRAGMA(pop)
#  else
#    define DIAG_OFF(x)
#    define DIAG_ON(x)
#  endif
#elif defined(__GNUC__) && ((__GNUC__ * 100) + __GNUC_MINOR__) >= 402
#  define DIAG_PRAGMA(x) DIAG_DO_PRAGMA(GCC diagnostic x)
#  if ((__GNUC__ * 100) + __GNUC_MINOR__) >= 406
#    define DIAG_OFF(x) DIAG_PRAGMA(push) DIAG_PRAGMA(ignored DIAG_JOINSTR(-W,x))
#    define DIAG_ON(x) DIAG_PRAGMA(pop)
#  else
#    define DIAG_OFF(x) DIAG_PRAGMA(ignored DIAG_JOINSTR(-W,x))
#    define DIAG_ON(x)  DIAG_PRAGMA(warning DIAG_JOINSTR(-W,x))
#  endif
#else
#  define DIAG_OFF(x)
#  define DIAG_ON(x)
#endif

/* Use for clang specific warnings */
#ifdef __clang__
#  define DIAG_OFF_CLANG(x) DIAG_OFF(x)
#  define DIAG_ON_CLANG(x)  DIAG_ON(x)
#else
#  define DIAG_OFF_CLANG(x)
#  define DIAG_ON_CLANG(x)
#endif

/*
 *	For dealing with APIs which are only deprecated in OSX (like the OpenSSL API)
 */
#ifdef __APPLE__
#  define USES_APPLE_DEPRECATED_API DIAG_OFF(deprecated-declarations)
#  define USES_APPLE_RST DIAG_ON(deprecated-declarations)
#else
#  define USES_APPLE_DEPRECATED_API
#  define USES_APPLE_RST
#endif

/*
 * end of Apple deprecation workaround macros
 */

/*
 * Statement attributes, for various compilers.
 *
 * This was introduced sufficiently recently that compilers implementing
 * it also implement __has_attribute() (for example, GCC 5.0 and later
 * have __has_attribute(), and the "fallthrough" attribute was introduced
 * in GCC 7).
 *
 * Unfortunately, Clang does this wrong - a statement
 *
 *    __attribute__ ((fallthrough));
 *
 * produces bogus -Wmissing-declaration "declaration does not declare
 * anything" warnings (dear Clang: that's not a declaration, it's an
 * empty statement).  GCC, however, has no trouble with this.
 */
#if __has_attribute(fallthrough) && !defined(__clang__)
#  define ND_FALL_THROUGH __attribute__ ((fallthrough))
#else
#  define ND_FALL_THROUGH
#endif /*  __has_attribute(fallthrough) */

#endif /* netdissect_stdinc_h */
