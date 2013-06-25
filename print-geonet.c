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


/*
   ETSI TS 102 636-5-1 V1.1.1 (2011-02)
   Intelligent Transport Systems (ITS); Vehicular Communications; GeoNetworking;
   Part 5: Transport Protocols; Sub-part 1: Basic Transport Protocol

   ETSI TS 102 636-4-1 V1.1.1 (2011-06)
   Intelligent Transport Systems (ITS); Vehicular communications; GeoNetworking;
   Part 4: Geographical addressing and forwarding for point-to-point and point-to-multipoint communications;
   Sub-part 1: Media-Independent Functionality
*/

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

static void
print_btp_body(const u_char *bp, u_int length)
{
	// Assuming ItsDpuHeader
	int version = bp[0];
	int msg_type = bp[1];
	const char *msg_type_str = "Unknown";

	switch (msg_type) {
		case   0: msg_type_str = "CAM"; break;
		case   1: msg_type_str = "DENM"; break;
		case 101: msg_type_str = "TPEGM"; break;
		case 102: msg_type_str = "TSPDM"; break;
		case 103: msg_type_str = "VPM"; break;
		case 104: msg_type_str = "SRM"; break;
		case 105: msg_type_str = "SLAM"; break;
		case 106: msg_type_str = "ecoCAM"; break;
		case 107: msg_type_str = "ITM"; break;
		case 150: msg_type_str = "SA"; break;
	}
	printf("; ItsPduHeader v:%d t:%d-%s", version, msg_type, msg_type_str);
}

static void
print_btp(const u_char *bp, u_int length)
{
	u_int16_t dest = EXTRACT_16BITS(bp+0);
	u_int16_t src = EXTRACT_16BITS(bp+2);
	printf("; BTP Dst:%u Src:%u", dest, src);
}

static void
print_long_pos_vector(const char *type, const u_char *bp, u_int length)
{
	int i;
	u_int32_t lat, lon;

	printf("GN_ADDR:");
	for (i=0; i<8; i++) {
		if (i) printf(":");
		printf("%02x", bp[i]);
	}
	printf(" ");

	lat = EXTRACT_32BITS(bp+12);
	printf("lat:%d ", lat);
	lon = EXTRACT_32BITS(bp+16);
	printf("lon:%d", lon);
}


/*
 * This is the top level routine of the printer.  'p' points
 * to the geonet header of the packet.
 */
void
geonet_print(netdissect_options *ndo, const u_char *eth, const u_char *bp, u_int length)
{
	printf("GeoNet src:%s; ", hex48_to_string(eth+6));

	if (length >= 36) {
		// Process Common Header
		int version = bp[0] >> 4;
		int next_hdr = bp[0] & 0x0f;
		int hdr_type = bp[1] >> 4;
		int hdr_subtype = bp[1] & 0x0f;
		u_int16_t payload_length = EXTRACT_16BITS(bp+4);
		int hop_limit = bp[7];
		const char *next_hdr_txt = "Unknown";
		const char *hdr_type_txt = "Unknown";
		int hdr_size = -1;

		switch (next_hdr) {
			case 0: next_hdr_txt = "Any"; break;
			case 1: next_hdr_txt = "BTP-A"; break;
			case 2: next_hdr_txt = "BTP-B"; break;
			case 3: next_hdr_txt = "IPv6"; break;
		}

		switch (hdr_type) {
			case 0: hdr_type_txt = "Any"; break;
			case 1: hdr_type_txt = "Beacon"; break;
			case 2: hdr_type_txt = "GeoUnicast"; break;
			case 3: switch (hdr_subtype) {
					case 0: hdr_type_txt = "GeoAnycastCircle"; break;
					case 1: hdr_type_txt = "GeoAnycastRect"; break;
					case 2: hdr_type_txt = "GeoAnycastElipse"; break;
				}
				break;
			case 4: switch (hdr_subtype) {
					case 0: hdr_type_txt = "GeoBroadcastCircle"; break;
					case 1: hdr_type_txt = "GeoBroadcastRect"; break;
					case 2: hdr_type_txt = "GeoBroadcastElipse"; break;
				}
				break;
			case 5: switch (hdr_subtype) {
					case 0: hdr_type_txt = "TopoScopeBcast-SH"; break;
					case 1: hdr_type_txt = "TopoScopeBcast-MH"; break;
				}
				break;
			case 6: switch (hdr_subtype) {
					case 0: hdr_type_txt = "LocService-Request"; break;
					case 1: hdr_type_txt = "LocService-Reply"; break;
				}
				break;
		}

		printf("v:%d ", version);
		printf("NH:%d-%s ", next_hdr, next_hdr_txt);
		printf("HT:%d-%d-%s ", hdr_type, hdr_subtype, hdr_type_txt);
		printf("HopLim:%d ", hop_limit);
		printf("Payload:%d ", payload_length);
        	print_long_pos_vector("Sender", bp + 8, 36-8);

		// Skip Common Header
		length -= 36;
		bp += 36;

		// Process Extended Headers
		switch (hdr_type) {
			case 0: /* Any */
				hdr_size = 0;
				break;
			case 1: /* Beacon */
				hdr_size = 0;
				break;
			case 2: /* GeoUnicast */
				break;
			case 3: switch (hdr_subtype) {
					case 0: /* GeoAnycastCircle */
						break;
					case 1: /* GeoAnycastRect */
						break;
					case 2: /* GeoAnycastElipse */
						break;
				}
				break;
			case 4: switch (hdr_subtype) {
					case 0: /* GeoBroadcastCircle */
						break;
					case 1: /* GeoBroadcastRect */
						break;
					case 2: /* GeoBroadcastElipse */
						break;
				}
				break;
			case 5: switch (hdr_subtype) {
					case 0: /* TopoScopeBcast-SH */
						hdr_size = 0;
						break;
					case 1: /* TopoScopeBcast-MH */
						hdr_size = 68 - 36;
						break;
				}
				break;
			case 6: switch (hdr_subtype) {
					case 0: /* LocService-Request */
						break;
					case 1: /* LocService-Reply */
						break;
				}
				break;
		}

		// Skip Extended headers
		if (hdr_size >= 0) {
			length -= hdr_size;
			bp += hdr_size;
			switch (next_hdr) {
				case 0: /* Any */
					break;
				case 1:
				case 2: /* BTP A/B */
					print_btp(bp, length);
					length -= 4;
					bp += 4;
					print_btp_body(bp, length);
					break;
				case 3: /* IPv6 */
					break;
			}
		}
	} else {
		printf("Malformed (small) ");
	}

	// Print user data part
	if (ndo->ndo_vflag)
		default_print(bp, length);
}


/*
 * Local Variables:
 * c-style: whitesmith
 * c-basic-offset: 8
 * End:
 */
