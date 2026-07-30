/*
 * Copyright (c) 2020 The TCPDUMP project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code
 * distributions retain the above copyright notice and this paragraph
 * in its entirety, and (2) distributions including binary code include
 * the above copyright notice and this paragraph in its entirety in
 * the documentation or other materials provided with the distribution.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND
 * WITHOUT ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, WITHOUT
 * LIMITATION, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE.
 */

/* \summary: unsupported link-layer protocols printer */

#include <config.h>

#include "netdissect-stdinc.h"

#include "netdissect.h"

void
unsupported_if_print(netdissect_options *ndo, const struct pcap_pkthdr *h,
		     const u_char *p)
{
	ndo->ndo_protocol = "unsupported";
	nd_print_protocol_caps(ndo);
	/*
	 * Print the packet contents as hex and ASCII only if no raw dump was
	 * requested via -x/-X/-A.  In that case pretty_print_packet() prints
	 * the raw data itself (honouring the requested format), and printing
	 * it here as well would duplicate the hex dump.
	 */
	if (!ndo->ndo_xflag && !ndo->ndo_Xflag && !ndo->ndo_Aflag)
		hex_and_ascii_print(ndo, "\n\t", p, h->caplen);
}
