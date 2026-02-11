/*
 * Copyright (c) 2013 The TCPDUMP project
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
 *
 * Original code by Ola Martin Lykkja (ola.lykkja@q-free.com).
 * Updated code by Daniel Ulied (daniel.ulied@i2cat.net) and Jordi Marias-Parella (jordi.marias@i2cat.net).
 */

/* \summary: ETSI GeoNetworking & Basic Transport Protocol printer */

#include <config.h>

#include "netdissect-stdinc.h"

#define ND_LONGJMP_FROM_TCHECK
#include "netdissect.h"
#include "extract.h"
#include "addrtoname.h"

/*
   ETSI EN 302 636-5-1 V2.2.1 (2019-05)
   Intelligent Transport Systems (ITS);
   Vehicular Communications;
   GeoNetworking;
   Part 5: Transport Protocols;
   Sub-part 1: Basic Transport Protocol

   ETSI EN 302 636-4-1 V1.4.1 (2020-01)
   Intelligent Transport Systems (ITS);
   Vehicular Communications;
   GeoNetworking;
   Part 4: Geographical addressing and forwarding for point-to-point and point-to-multipoint communications;
   Sub-part 1: Media-Independent Functionality;
   Release 2
*/

/*Specific Definitions*/
#define NDO_V_FLAG_FIRST_DEBUG_LEVEL 1
#define NDO_V_FLAG_SECOND_DEBUG_LEVEL 2
#define NDO_V_FLAG_THIRD_DEBUG_LEVEL 3

/*Bit-Wise Definitions*/
#define ONE_BYTE 8
#define TWO_BYTES 16
#define THREE_BYTES 24
#define FOUR_BYTES 32
#define FIVE_BYTES 40
#define SIX_BYTES 48
#define SEVEN_BYTES 56
#define EIGHT_BYTES 64

#define ONE_BIT_MASK 0x01
#define TWO_BITS_MASK 0x03
#define THREE_BITS_MASK 0x07
#define FOUR_BITS_MASK 0x0F
#define FIVE_BITS_MASK 0x1F
#define SIX_BITS_MASK 0x3F
#define SEVEN_BITS_MASK 0x7F
#define EIGHT_BITS_MASK 0xFF
#define TEN_BITS_MASK 0x3FF
#define SIXTEEN_BITS_MASK 0xFFFF
#define FORTY_EIGHT_BITS_MASK 0xFFFFFFFFFFFF

/* GeoNetworking Definitons*/

/* GeoNetworking Basic Header Definitions*/
#define GN_BASIC_HEADER_MINIMUM_PACKET_LENGTH 4

#define IMPLEMENTED_GN_VERSION 1

#define NH_COMMONHEADER 1
#define NH_SECUREDPACKET 2
#define IMPLEMENTED_GN_NEXT_HEADER NH_COMMONHEADER
static const struct tok basic_header_next_header_values[] = {
	{0, "Any"},
	{NH_COMMONHEADER, "CommonHeader"},
	{NH_SECUREDPACKET, "SecuredPacket"},
	{0, NULL}};

#define HT_BEACON 1
#define HT_TSB 5
#define HT_TSB_SHB 0
#define HT_TSB_MULTI_HOP 1
#define ELAPSED_SECONDS 5

#define IMPLEMENTED_GN_HEADER_TYPE_1 HT_BEACON
#define IMPLEMENTED_GN_HEADER_TYPE_2 HT_TSB

#define LT_BASE_FIFTY_MILLISECONDS 0.05
#define LT_BASE_ONE_SECOND 1
#define LT_BASE_TEN_SECONDS 10
#define LT_BASE_ONE_HUNDRED_SECONDS 100

/* GeoNetworking Common Header Defintiions*/
#define BTP_A 1
#define BTP_B 2
static const struct tok common_header_next_header_values[] = {
	{0, "Any"},
	{BTP_A, "BTP-A"},
	{BTP_B, "BTP-B"},
	{3, "IPv6"},
	{0, NULL}};

#define HT_HST(ht, hst) (((ht) << 8) | (hst))
static const struct tok header_type_tok[] = {
	{HT_HST(0, 0), "Any"},

	{HT_HST(1, 0), "Beacon"},

	{HT_HST(2, 0), "GeoUnicast"},

	{HT_HST(3, 0), "GeoAnycastCircle"},
	{HT_HST(3, 1), "GeoAnycastRect"},
	{HT_HST(3, 2), "GeoAnycastElipse"},

	{HT_HST(4, 0), "GeoBroadcastCircle"},
	{HT_HST(4, 1), "GeoBroadcastRect"},
	{HT_HST(4, 2), "GeoBroadcastElipse"},

	{HT_HST(5, 0), "TopoScopeBcast-SH"},
	{HT_HST(5, 1), "TopoScopeBcast-MH"},

	{HT_HST(6, 0), "LocService-Request"},
	{HT_HST(6, 1), "LocService-Reply"},
	{0, NULL}};

static const struct tok flags_text_from_bytes[] = {
	{0, "Stationary"},
	{1, "Mobile"},
	{0, NULL}};

static const struct tok st_text_from_bytes[] = {
	{1, "Pedestrian"},
	{2, "Cyclist"},
	{3, "Moped"},
	{4, "Motorcycle"},
	{5, "Passenger Car"},
	{6, "Bus"},
	{7, "Light Truck"},
	{8, "Heavy Truck"},
	{9, "Trailer"},
	{10, "Special Vehicle"},
	{11, "Tram"},
	{12, "Road Side Unit"},
	{0, NULL}};

/* GeoNetworking Long Position Vector*/
#define CONVERT_CORD_TO_DEGREES 1e7
#define CONVERT_HEADING_TO_DEGREES 1e1
#define CONVERT_SPEED_TO_METERS_PER_SECOND 1e2

/* BasicTransportProtocol Definitions*/
static const struct tok btp_port_values[] = {
	{2001, "CAM"},
	{2002, "DENM"},
	{2003, "MAPEM"},
	{2004, "SPATEM"},
	{2005, "SAEM"},
	{2006, "IVIM"},
	{2007, "SREM"},
	{2008, "SSEM"},
	{2009, "CPM"},
	{2010, "EVCSN_POI"},
	{2011, "TPG"},
	{2012, "EV_RSR"},
	{2013, "RTCMEM"},
	{2014, "CTLM"},
	{2015, "CRLM"},
	{2016, "EC_AT_REQ"},
	{2017, "MCDM"},
	{2018, "VAM"},
	{2019, "IMZM"},
	{2020, "DSM"},
	{2021, "P2P_CRLM"},
	{2022, "P2P_CTLM"},
	{2023, "MRS"},
	{2024, "P2P_FULL_CTLM"},
	{0, NULL}};

static float convert_lt_to_seconds(uint8_t lt_base, uint8_t lt_multiplier)
{
	float base_seconds;
	switch (lt_base)
	{
	case 0:
		base_seconds = LT_BASE_FIFTY_MILLISECONDS;
		break;
	case 1:
		base_seconds = LT_BASE_ONE_SECOND;
		break;
	case 2:
		base_seconds = LT_BASE_TEN_SECONDS;
		break;
	case 3:
		base_seconds = LT_BASE_ONE_HUNDRED_SECONDS;
		break;
	}
	return (float)(base_seconds * lt_multiplier);
}

/* Process GN Basic Header as per Section 9.6 (ETSI EN 302 636-4-1 V1.4.1 (2020-01))*/
static u_int gn_basic_header_decode_from_bytes(netdissect_options *ndo, const u_char *bp, u_int length, uint8_t *next_header)
{
	uint8_t version;
	uint8_t reserved;
	uint8_t lt;
	uint8_t lt_multiplier;
	uint8_t lt_base;
	uint8_t rhl;

	u_int initial_length = length;

	uint8_t value = GET_U_1(bp);
	bp++;
	length--;
	version = (value >> 4) & FOUR_BITS_MASK;
	if (version != IMPLEMENTED_GN_VERSION)
	{
		ND_PRINT(" (Unsupported GeoNetworking Basic Header version %u)", version);
		*next_header = 0; // Indicates an error.
		return initial_length - length;
	}
	*next_header = value & FOUR_BITS_MASK;

	reserved = GET_U_1(bp);
	bp++;
	length--;

	lt = GET_U_1(bp);
	bp++;
	length--;
	lt_multiplier = (lt >> 2) & SIX_BITS_MASK;
	lt_base = lt & TWO_BITS_MASK;

	rhl = GET_U_1(bp);
	bp++;
	length--;

	const char *next_header_text = tok2str(basic_header_next_header_values, "Unknown", *next_header);
	float lt_product = convert_lt_to_seconds(lt_base, lt_multiplier);

	if (ndo->ndo_vflag == NDO_V_FLAG_FIRST_DEBUG_LEVEL)
	{
		ND_PRINT("ver:%u nh:%s lt:%.2fs rhl:%u; ",
				 version, next_header_text, lt_product, rhl);
	}
	else if (ndo->ndo_vflag > NDO_V_FLAG_FIRST_DEBUG_LEVEL)
	{
		ND_PRINT("ver:%u nh:%s reserved:%u lt:[base:%u mult:%u = %.2fs] rhl:%u; ",
				 version, next_header_text, reserved,
				 lt_base, lt_multiplier, lt_product, rhl);
	}

	return initial_length - length;
}

/* Process GN Common Header as per Section 9.7 (ETSI EN 302 636-4-1 V1.4.1 (2020-01))*/
static u_int gn_common_header_decode_from_bytes(netdissect_options *ndo, const u_char *bp, u_int length, uint8_t *header_type, uint8_t *header_subtype, uint8_t *next_header)
{
	uint8_t reserved;
	uint8_t tc_encoded;
	uint8_t tc_scf;
	uint8_t tc_channel_offload;
	uint8_t tc_id;
	uint8_t flags;
	uint16_t pl;
	uint8_t mhl;
	uint8_t reserved2;
	u_int initial_length = length;

	uint8_t value = GET_U_1(bp);
	bp++;
	length--;
	*next_header = (value >> 4) & FOUR_BITS_MASK;
	reserved = value & FOUR_BITS_MASK;

	value = GET_U_1(bp);
	bp++;
	length--;
	*header_type = (value >> 4) & FOUR_BITS_MASK;
	*header_subtype = value & FOUR_BITS_MASK;

	tc_encoded = GET_U_1(bp);
	bp++;
	length--;
	tc_scf = (tc_encoded >> 7) & ONE_BIT_MASK;
	tc_channel_offload = (tc_encoded >> 6) & ONE_BIT_MASK;
	tc_id = tc_encoded & SIX_BITS_MASK;

	flags = GET_U_1(bp);
	bp++;
	length--;

	pl = GET_BE_U_2(bp);
	bp += 2;
	length -= 2;

	mhl = GET_U_1(bp);
	bp++;
	length--;

	reserved2 = GET_U_1(bp);
	bp++;
	length--;

	const char *next_header_text = tok2str(common_header_next_header_values, "Unknown", *next_header);
	const char *header_type_text = tok2str(header_type_tok, "Unknown", HT_HST(*header_type, *header_subtype));
	const char *flags_text = tok2str(flags_text_from_bytes, "Unknown", flags);
	switch (ndo->ndo_vflag)
	{
	case 0:
		ND_PRINT("nh:%s nt:%s; ",
				 next_header_text, header_type_text);
		break;

	case 1:
		ND_PRINT("nh:%s ht:%s f:%s pl:%u mhl:%u; ",
				 next_header_text, header_type_text, flags_text, pl, mhl);
		break;

	default:
		ND_PRINT("nh:%s reserved:%u ht:%s hst:%u tc:[scf:%u co:%u id:%u] f:%s pl:%u mhl:%u reserved2:%u; ",
				 next_header_text, reserved, header_type_text, *header_subtype,
				 tc_scf, tc_channel_offload, tc_id,
				 flags_text, pl, mhl, reserved2);
		break;
	}

	return initial_length - length;
}

static const char *process_gn_addr(netdissect_options *ndo, uint64_t gn_addr)
{
	uint8_t m = (gn_addr >> (7 + SEVEN_BYTES)) & ONE_BIT_MASK;
	uint8_t st = (gn_addr >> (2 + SEVEN_BYTES)) & FIVE_BITS_MASK;
	uint16_t reserved = (gn_addr >> SIX_BYTES) & TEN_BITS_MASK;
	uint64_t mib = gn_addr & FORTY_EIGHT_BITS_MASK;
	static char buffer[128];
	if (ndo->ndo_vflag >= NDO_V_FLAG_FIRST_DEBUG_LEVEL)
	{
		snprintf(buffer, sizeof(buffer), "[m:%u st:%s reserved:%u mib:0x%llx]", m, tok2str(st_text_from_bytes, "Unknown", st), reserved, (unsigned long long)mib);
	}
	else
	{
		snprintf(buffer, sizeof(buffer), "0x%llx", (unsigned long long)mib);
	}

	return buffer;
}

static const char *process_lat(int32_t lat)
{
	static char buffer[24];
	if (lat > 0)
	{
		snprintf(buffer, sizeof(buffer), "%.6f N", (double)lat / CONVERT_CORD_TO_DEGREES);
	}
	else
	{
		snprintf(buffer, sizeof(buffer), "%.6f S", -(double)lat / CONVERT_CORD_TO_DEGREES);
	}
	return buffer;
}

static const char *process_lon(int32_t lon)
{
	static char buffer[24];
	if (lon > 0)
	{
		snprintf(buffer, sizeof(buffer), "%.6f E", (double)lon / CONVERT_CORD_TO_DEGREES);
	}
	else
	{
		snprintf(buffer, sizeof(buffer), "%.6f W", -(double)lon / CONVERT_CORD_TO_DEGREES);
	}
	return buffer;
}

static const char *process_heading(u_int heading)
{
	static char buffer[16];

	snprintf(buffer, sizeof(buffer),
			 "%.1f°", (double)heading / CONVERT_HEADING_TO_DEGREES);

	return buffer;
}

static const char *process_speed(int16_t speed)
{
	static char buffer[16];

	snprintf(buffer, sizeof buffer,
			 "%.2f m/s", (double)speed / CONVERT_SPEED_TO_METERS_PER_SECOND);

	return buffer;
}

static const char *process_pai(u_int pai)
{
	if (pai == 0)
	{
		return "True";
	}
	else
	{
		return "False";
	}
}

/* Process Long Position Vector as per Section 9.5.2 of ETSI EN 302 636-4-1 V1.4.1 (2020-01)*/
static u_int process_long_position_vector_from_bytes(netdissect_options *ndo, const u_char *bp, u_int length)
{
	uint64_t gn_addr;
	u_int tst;
	int32_t lat;
	int32_t lon;
	u_int pai;
	int16_t s;
	u_int h;

	u_int initial_length = length;

	gn_addr = GET_BE_U_8(bp);
	bp += 8;
	length -= 8;
	tst = GET_BE_U_4(bp);
	bp += 4;
	length -= 4;
	lat = GET_BE_S_4(bp);
	bp += 4;
	length -= 4;
	lon = GET_BE_S_4(bp);
	bp += 4;
	length -= 4;
	uint32_t value = GET_BE_U_2(bp);
	bp += 2;
	length -= 2;
	pai = (value >> (7 + ONE_BYTE)) & ONE_BIT_MASK;
	s = ((int16_t)value << 1) >> 1;
	h = GET_BE_U_2(bp);
	bp += 2;
	length -= 2;
	if (ndo->ndo_vflag > NDO_V_FLAG_FIRST_DEBUG_LEVEL)
	{
		ND_PRINT("GN_ADDR:%s tst:%u lat:%s lon:%s pai:%s, s:%s, h:%s; ", process_gn_addr(ndo, gn_addr), tst, process_lat(lat), process_lon(lon), process_pai(pai), process_speed(s), process_heading(h));
	}
	else
	{
		ND_PRINT("GN_ADDR:%s lat:%s, lon:%s; ", process_gn_addr(ndo, gn_addr), process_lat(lat), process_lon(lon));
	}
	return initial_length - length;
}

static u_int process_beacon_header_from_bytes(netdissect_options *ndo, const u_char *bp, u_int length)
{
	return process_long_position_vector_from_bytes(ndo, bp, length);
}

static u_int process_tsb_shb_header_from_bytes(netdissect_options *ndo, const u_char *bp, u_int length)
{
	u_int initial_length = length;
	u_int bytes_processed;

	bytes_processed = process_long_position_vector_from_bytes(ndo, bp, length);
	bp += bytes_processed;
	length -= bytes_processed;
	u_int media_indpendenet_data = GET_BE_U_4(bp);
	bp += 4;
	length -= 4;
	if (ndo->ndo_vflag > NDO_V_FLAG_SECOND_DEBUG_LEVEL)
	{
		ND_PRINT("Media-Independent Data: %u; ", media_indpendenet_data);
	}
	return initial_length - length;
}

static u_int process_tsb_header_from_bytes(netdissect_options *ndo, const u_char *bp, u_int length)
{
	u_int sn;
	u_int reseved;

	u_int initial_length = length;

	sn = GET_BE_U_2(bp);
	bp += 2;
	length -= 2;
	reseved = GET_BE_U_2(bp);
	bp += 2;
	length -= 2;
	if (ndo->ndo_vflag > 2)
	{
		ND_PRINT("sn:%u reserved:%u; ", sn, reseved);
	}
	u_int bytes_processed = process_long_position_vector_from_bytes(ndo, bp, length);
	length -= bytes_processed;

	return initial_length - length;
}

static u_int process_optional_extended_header(netdissect_options *ndo, const u_char *bp, u_int length, uint8_t header_type, uint8_t header_subtype)
{
	u_int initial_length = length;
	u_int bytes_processed;

	switch (header_type)
	{
	case HT_BEACON:
		bytes_processed = process_beacon_header_from_bytes(ndo, bp, length);
		bp += bytes_processed;
		length -= bytes_processed;
		break;
	case HT_TSB:
		switch (header_subtype)
		{
		case 0:
			bytes_processed = process_tsb_shb_header_from_bytes(ndo, bp, length);
			bp += bytes_processed;
			length -= bytes_processed;
			break;
		case 1:
			bytes_processed = process_tsb_header_from_bytes(ndo, bp, length);
			bp += bytes_processed;
			length -= bytes_processed;
			break;
		default:
			ND_PRINT(" (TSB Header-Subtype not supported)");
			break;
		}
		break;
	default:
		ND_PRINT(" (Header-Type not supported)");
		break;
	}

	return initial_length - length;
}

/* Process BTP Header as per Section 7.2 (ETSI EN 302 636-5-1 V2.2.1 (2019-05))*/
static u_int process_btp_header_from_bytes(netdissect_options *ndo, const u_char *bp, u_int length, u_int common_header_next_header)
{
	u_int dst_port;
	u_int src_port;
	u_int dst_port_info;

	u_int initial_length = length;

	dst_port = GET_BE_U_2(bp);
	bp += 2;
	length -= 2;

	switch (common_header_next_header)
	{
	case BTP_A:
		src_port = GET_BE_U_2(bp);
		bp += 2;
		length -= 2;
		ND_PRINT("BTP-A dst:%s src:%s; ", tok2str(btp_port_values, "Unknown", dst_port), tok2str(btp_port_values, "Unknown", src_port));
		break;

	case BTP_B:
		dst_port_info = GET_BE_U_2(bp);
		bp += 2;
		length -= 2;
		if (ndo->ndo_vflag > NDO_V_FLAG_SECOND_DEBUG_LEVEL)
		{
			ND_PRINT("BTP-B dst:%s dpi:%u; ", tok2str(btp_port_values, "Unknown", dst_port), dst_port_info);
		}
		else
		{
			ND_PRINT("BTP-B dst:%s; ", tok2str(btp_port_values, "Unknown", dst_port));
		}
		break;

	default:
		break;
	}
	return initial_length - length;
}

void geonet_print(netdissect_options *ndo, const u_char *bp, u_int length)
{
	u_int bytes_processed;
	ndo->ndo_protocol = "geonet";
	ND_PRINT("GeoNet ");

	if (length < GN_BASIC_HEADER_MINIMUM_PACKET_LENGTH)
	{
		ND_PRINT(" (length %u < %u)", length, GN_BASIC_HEADER_MINIMUM_PACKET_LENGTH);
		goto invalid;
	}

	/* Process Basic Header */
	uint8_t basic_header_next_header;
	bytes_processed = gn_basic_header_decode_from_bytes(ndo, bp, length, &basic_header_next_header);
	bp += bytes_processed;
	length -= bytes_processed;

	if (basic_header_next_header != IMPLEMENTED_GN_NEXT_HEADER)
	{
		ND_PRINT(" (Next-Header not supported: %s)", tok2str(basic_header_next_header_values, "Unknown", basic_header_next_header));
		goto invalid;
	}

	/* Process Common Header */
	uint8_t header_type;
	uint8_t header_subtype;
	uint8_t common_header_next_header;
	bytes_processed = gn_common_header_decode_from_bytes(ndo, bp, length, &header_type, &header_subtype, &common_header_next_header);
	bp += bytes_processed;
	length -= bytes_processed;
	if (header_type != IMPLEMENTED_GN_HEADER_TYPE_1 && header_type != IMPLEMENTED_GN_HEADER_TYPE_2)
	{
		ND_PRINT(" (GeoNetworking Header-Type %s not supported)", tok2str(header_type_tok, "Unknown", HT_HST(header_type, header_subtype)));
		goto invalid;
	}

	/* Process Optional Extended Header*/
	bytes_processed = process_optional_extended_header(ndo, bp, length, header_type, header_subtype);
	bp += bytes_processed;
	length -= bytes_processed;
	if (common_header_next_header == BTP_A || common_header_next_header == BTP_B)
	{
		/* Print Basic Transport Header */
		bytes_processed = process_btp_header_from_bytes(ndo, bp, length, common_header_next_header);
		bp += bytes_processed;
		length -= bytes_processed;
	}

	/* Print user data part */
	if (ndo->ndo_vflag)
		ND_DEFAULTPRINT(bp, length);
	return;

invalid:
	nd_print_invalid(ndo);
}
