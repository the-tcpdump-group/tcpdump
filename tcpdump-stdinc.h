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
 */

#ifdef WIN32

#include <winsock2.h>
#include "bittypes.h"
#include <time.h>
#include <io.h>
#include "IP6_misc.h"
#include <fcntl.h>

#ifdef __MINGW32__
int* _errno();
#define errno (*_errno())

#define INET_ADDRSTRLEN 16
#define INET6_ADDRSTRLEN 46

#endif /* __MINGW32__ */

#ifndef caddr_t
typedef char* caddr_t;
#endif /* caddr_t */

#define MAXHOSTNAMELEN	64
#define	NI_MAXHOST	1025
#define IPPROTO_EGP 8		/* Exterior Gateway Protocol */
#define snprintf _snprintf
#define vsnprintf _vsnprintf
#define RETSIGTYPE void

#ifndef __MINGW32__
#define isascii __isascii
#define toascii __toascii
#define stat _stat
#define open _open
#define fstat _fstat
#define read _read
#define O_RDONLY _O_RDONLY

typedef short ino_t;
#endif

#else

#include <ctype.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/time.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/uio.h>

#ifdef HAVE_SYS_SOCKIO_H
#include <sys/sockio.h>
#include <arpa/inet.h>
#endif /* HAVE_SYS_SOCKIO_H */

#endif

#ifdef INET6
#include "ip6.h"
#endif
