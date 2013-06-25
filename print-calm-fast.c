/*
 * Copyright (c) 2013
 *	lykkja@hotmail.com  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) all advertising materials mentioning
 * features or use of this software display the following acknowledgement:
 * ``This product includes software developed by Paolo Abeni.'' 
 * The name of author may not be used to endorse or promote products derived 
 * from this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <tcpdump-stdinc.h>

#include <pcap.h>
#include <stdio.h>
#include <string.h>

#include "interface.h"
#include "extract.h"
#include "addrtoname.h"


static const char *
hex48_to_string(const u_char *bp)
{
        int i;
        static char sz[6*3+2];
        memset(sz, 0, sizeof(sz));
        for (i=0; i<6; i++) {
                if (i) strcat(sz,":");
                sprintf(sz+strlen(sz), "%02x", bp[i]);
        }
        return sz;
}

/*
 * This is the top level routine of the printer.  'p' points
 * to the calm header of the packet.
 */
void
calm_fast_print(netdissect_options *ndo, const u_char *eth, const u_char *bp, u_int length)
{
	printf("CALM FAST src:%s; ", hex48_to_string(eth+6));

	length -= 0;
	bp += 0;

	if (ndo->ndo_vflag)
		default_print(bp, length);
}


/*
 * Local Variables:
 * c-style: whitesmith
 * c-basic-offset: 8
 * End:
 */
