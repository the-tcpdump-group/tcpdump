/*	$NetBSD: print-ntp.c,v 1.3 1997/03/15 18:37:55 is Exp $	*/

/*
 * Copyright (c) 1990, 1991, 1992, 1993, 1994
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) all advertising materials mentioning
 * features or use of this software display the following acknowledgement:
 * ``This product includes software developed by the University of California,
 * Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
 * the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 *
 * Format and print ntp packets.
 *	By Jeffrey Mogul/DECWRL
 *	loosely based on print-bootp.c
 */

#ifndef lint
static char rcsid[] =
    "@(#) Header: print-ntp.c,v 1.14 94/06/14 20:18:46 leres Exp (LBL)";
#endif

#include <sys/param.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <net/if.h>

#include <netinet/in.h>
#ifdef __NetBSD__
#include <net/if_ether.h>
#else
#include <netinet/if_ether.h>
#endif

#include <ctype.h>
#include <pcap.h>
#include <stdio.h>
#include <string.h>

#include "interface.h"
#include "addrtoname.h"
#undef MODEMASK					/* Solaris sucks */
#include "ntp.h"

struct isakmp_header {
  u_char  init_cookie[4];
  u_char  resp_cookie[4];
  u_char  nextpayload;
#if BYTE_ORDER == LITTLE_ENDIAN
  u_char  mnver:4;
  u_char  mjver:4;
#endif
#if BYTE_ORDER == BIG_ENDIAN
  u_char  mjver:4;
  u_char  mnver:4;
#endif  
  u_char  exgtype;
  u_char  flags;
  u_char  msgid[4];
  u_int32_t length;
};

#define FLAGS_ENCRYPTION 1
#define FLAGS_COMMIT     2

/*
 * Print isakmp requests
 */
void
isakmp_print(register const u_char *cp, int length)
{
  struct isakmp_header *ih;
  register const u_char *ep;
  int mode, version, leapind;
  
  ih = (struct isakmp_header *)cp;
  /* Note funny sized packets */
  if (length < 20)
    {
      (void)printf(" [len=%d]", length);
    }

  /* 'ep' points to the end of avaible data. */
  ep = snapend;

  printf(" isakmp");

  printf(" v%d.%d\n\t", ih->mjver, ih->mnver);

  if(ih->flags & FLAGS_ENCRYPTION)
    {
      printf(" encrypted");
    }
  
  if(ih->flags & FLAGS_COMMIT)
    {
      printf(" commit");
    }

  printf(" from:%02x%02x%02x%02x to: %02x%02x%02x%02x",
	 ih->init_cookie[0], ih->init_cookie[1],
	 ih->init_cookie[2], ih->init_cookie[3], 
	 ih->resp_cookie[0], ih->resp_cookie[1], 
	 ih->resp_cookie[2], ih->resp_cookie[3]);

  TCHECK(ih->msgid);
  printf(" msgid:%02x%02x%02x%02x",
	 ih->msgid[0], ih->msgid[1],
	 ih->msgid[2], ih->msgid[3]);

  TCHECK(ih->length);
  printf(" length %d", ntohl(ih->length));
  
  if(ih->mjver > 1)
    {
      printf(" new version");
      return;
    }

trunc:
	fputs(" [|isakmp]", stdout);
}
