/*
 * Copyright (c) 1988-1997
 *	The Regents of the University of California.  All rights reserved.
 *
 * Copyright (c) 1998-2012  Michael Richardson <mcr@tcpdump.org>
 *      The TCPDUMP project
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "netdissect-stdinc.h"
#include "netdissect.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef USE_LIBSMI
#include <smi.h>
#endif

/*
 * Initialize anything that must be initialized before dissecting
 * packets.
 *
 * This should be called at the beginning of the program; it does
 * not need to be called, and should not be called, for every
 * netdissect_options structure.
 */
int
nd_init(char *errbuf, size_t errbuf_size)
{
#ifdef _WIN32
	WORD wVersionRequested;
	WSADATA wsaData;
	int err;

	/*
	 * Request Winsock 2.2; we expect Winsock 2.
	 */
	wVersionRequested = MAKEWORD(2, 2);
	err = WSAStartup(wVersionRequested, &wsaData);
	if (err != 0) {
		strlcpy(errbuf, "Attempting to initialize Winsock failed",
		    errbuf_size);
		return (-1);
	}
#endif /* _WIN32 */

#ifdef USE_LIBSMI
	/*
	 * XXX - should we just fail if this fails?  Some of the
	 * libsmi calls may fail.
	 */
	smiInit("tcpdump");
#endif

	/*
	 * Clears the error buffer, and uses it so we don't get
	 * "unused argument" warnings at compile time.
	 */
	strlcpy(errbuf, "", errbuf_size);
	return (0);
}

/*
 * Clean up anything that ndo_init() did.
 */
void
nd_cleanup(void)
{
#ifdef USE_LIBSMI
	/*
	 * This appears, in libsmi 0.4.8, to do nothing if smiInit()
	 * wasn't done or failed, so we call it unconditionally.
	 */
	smiExit();
#endif

#ifdef _WIN32
	/*
	 * Undo the WSAStartup() call above.
	 */
	WSACleanup();
#endif
}

int
nd_have_smi_support(void)
{
#ifdef USE_LIBSMI
	return (1);
#else
	return (0);
#endif
}

/*
 * Indicates whether an SMI module has been loaded, so that we can use
 * libsmi to translate OIDs.
 */
int nd_smi_module_loaded;

int
nd_load_smi_module(const char *module, char *errbuf, size_t errbuf_size)
{
#ifdef USE_LIBSMI
	if (smiLoadModule(module) == 0) {
		snprintf(errbuf, errbuf_size, "could not load MIB module %s",
		    module);
		return (-1);
	}
	nd_smi_module_loaded = 1;
	return (0);
#else
	snprintf(errbuf, errbuf_size, "MIB module %s not loaded: no libsmi support",
	    module);
	return (-1);
#endif
}

const char *
nd_smi_version_string(void)
{
#ifdef USE_LIBSMI
	return (smi_version_string);
#else
	return (NULL);
#endif
}


int
nd_push_buffer(netdissect_options *ndo, u_char *new_buffer,
    const u_char *new_packetp, const u_char *new_snapend)
{
	struct netdissect_saved_packet_info *ndspi;

	ndspi = (struct netdissect_saved_packet_info *)malloc(sizeof(struct netdissect_saved_packet_info));
	if (ndspi == NULL)
		return (0);	/* fail */
	ndspi->ndspi_buffer = new_buffer;
	ndspi->ndspi_packetp = ndo->ndo_packetp;
	ndspi->ndspi_snapend = ndo->ndo_snapend;
	ndspi->ndspi_prev = ndo->ndo_packet_info_stack;

	ndo->ndo_packetp = new_packetp;
	ndo->ndo_snapend = new_snapend;
	ndo->ndo_packet_info_stack = ndspi;

	return (1);	/* success */
}

/*
 * Set a new snapshot end to the minimum of the existing snapshot end
 * and the new snapshot end.
 */
int
nd_push_snapend(netdissect_options *ndo, const u_char *new_snapend)
{
	struct netdissect_saved_packet_info *ndspi;

	ndspi = (struct netdissect_saved_packet_info *)malloc(sizeof(struct netdissect_saved_packet_info));
	if (ndspi == NULL)
		return (0);	/* fail */
	ndspi->ndspi_buffer = NULL;	/* no new buffer */
	ndspi->ndspi_packetp = ndo->ndo_packetp;
	ndspi->ndspi_snapend = ndo->ndo_snapend;
	ndspi->ndspi_prev = ndo->ndo_packet_info_stack;

	/* No new packet pointer, either */
	if (new_snapend < ndo->ndo_snapend)
		ndo->ndo_snapend = new_snapend;
	ndo->ndo_packet_info_stack = ndspi;

	return (1);	/* success */
}

/*
 * Change an already-pushed snapshot end.  This may increase the
 * snapshot end, as it may be used, for example, for a Jumbo Payload
 * option in IPv6.  It must not increase it past the snapshot length
 * atop which the current one was pushed, however.
 */
void
nd_change_snapend(netdissect_options *ndo, const u_char *new_snapend)
{
	struct netdissect_saved_packet_info *ndspi;

	ndspi = ndo->ndo_packet_info_stack;
	if (ndspi->ndspi_prev != NULL) {
		if (new_snapend <= ndspi->ndspi_prev->ndspi_snapend)
			ndo->ndo_snapend = new_snapend;
	} else {
		if (new_snapend < ndo->ndo_snapend)
			ndo->ndo_snapend = new_snapend;
	}
}

void
nd_pop_packet_info(netdissect_options *ndo)
{
	struct netdissect_saved_packet_info *ndspi;

	ndspi = ndo->ndo_packet_info_stack;
	ndo->ndo_packetp = ndspi->ndspi_packetp;
	ndo->ndo_snapend = ndspi->ndspi_snapend;
	ndo->ndo_packet_info_stack = ndspi->ndspi_prev;

	free(ndspi->ndspi_buffer);
	free(ndspi);
}

void
nd_pop_all_packet_info(netdissect_options *ndo)
{
	while (ndo->ndo_packet_info_stack != NULL)
		nd_pop_packet_info(ndo);
}
