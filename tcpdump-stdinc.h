/*
 * Copyright (c) 2002
 *	Politecnico di Torino.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) all advertising materials mentioning
 * features or use of this software display the following acknowledgement:
 * ``This product includes software developed by the Politecnico
 * di Torino, and its contributors.'' Neither the name of
 * the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 *
 * @(#) $Header: /tcpdump/master/tcpdump/tcpdump-stdinc.h,v 1.5 2003-03-22 06:30:39 guy Exp $ (LBL)
 */

/*
 * Include the appropriate OS header files on Windows and various flavors
 * of UNIX, and also define some additional items and include various
 * non-OS header files on Windows, and; this isolates most of the platform
 * differences to this one file.
 */

#ifndef tcpdump_stdinc_h
#define tcpdump_stdinc_h

#ifdef WIN32

#include <stdio.h>
#include <winsock2.h>
#include "bittypes.h"
#include <ctype.h>
#include <time.h>
#include <io.h>
#include "IP6_misc.h"
#include <fcntl.h>

#ifdef __MINGW32__
#include <stdint.h>
int* _errno();
#define errno (*_errno())

#define INET_ADDRSTRLEN 16
#define INET6_ADDRSTRLEN 46

#endif /* __MINGW32__ */

#ifndef toascii
#define toascii(c) ((c) & 0x7f)
#endif

#ifndef caddr_t
typedef char* caddr_t;
#endif /* caddr_t */

#define MAXHOSTNAMELEN	64
#define	NI_MAXHOST	1025
#define IPPROTO_EGP 8		/* Exterior Gateway Protocol */
#define snprintf _snprintf
#define vsnprintf _vsnprintf
#define RETSIGTYPE void

#if !defined(__MINGW32__) && !defined(__WATCOMC__)
#undef toascii
#define isascii __isascii
#define toascii __toascii
#define stat _stat
#define open _open
#define fstat _fstat
#define read _read
#define O_RDONLY _O_RDONLY

typedef short ino_t;
#endif /* __MINGW32__ */

#else /* WIN32 */

#include <ctype.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/param.h>
#include <sys/types.h>			/* concession to AIX */
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>

#ifdef TIME_WITH_SYS_TIME
#include <time.h>
#endif

#include <arpa/inet.h>

#endif /* WIN32 */

#ifdef INET6
#include "ip6.h"
#endif

#if defined(WIN32) || defined(MSDOS)
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

#endif /* tcpdump_stdinc_h */
