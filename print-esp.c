/*	$NetBSD: print-ah.c,v 1.4 1996/05/20 00:41:16 fvdl Exp $	*/

/*
 * Copyright (c) 1988, 1989, 1990, 1991, 1992, 1993, 1994
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
 */

#ifndef lint
static char rcsid[] =
    "@(#) Header: print-ah.c,v 1.37 94/06/10 17:01:42 mccanne Exp (LBL)";
#endif

#include <sys/param.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <netinet/udp.h>
#include <netinet/udp_var.h>

#undef NOERROR					/* Solaris sucks */
#include <arpa/nameser.h>
#include <arpa/tftp.h>

#ifdef SOLARIS
#include <tiuser.h>
#endif
#include <rpc/rpc.h>

#include <errno.h>
#include <stdio.h>

#include "interface.h"
#include "addrtoname.h"

extern int packettype;


void
esp_print(register const u_char *bp, int length, register const u_char *bp2)
{
  register const struct ip *ip;
  register const u_char *cp, *nh;
  u_short ahlen, authlen;
  u_long  spi, seqno;

  ip = (struct ip *)bp2;

  (void)printf("ESP %s > %s\n\t\t",
	       ipaddr_string(&ip->ip_src), 
	       ipaddr_string(&ip->ip_dst));

  if (length < 8) {
    (void)printf(" [|esp] truncated-esp %d", length);
    return;
  }

  spi        = ntohl(*((u_long *)(bp)));
  seqno      = ntohl(*((u_long *)(bp+4)));

  nh         = bp+ahlen;

  (void)printf("spi:%08x seqno:%d ciphertext: ", spi, seqno);
  (void)default_print_unaligned(bp+8, length-8);

  /* XXX it would be nice to decrypt! */
}
