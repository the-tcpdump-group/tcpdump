// Copyright (c) 2018 Arista Networks, Inc.  All rights reserved.

/* \summary: EtherType protocol for Arista Networks printer */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <netdissect-stdinc.h>

#include <string.h>

#include "netdissect.h"
#include "interface.h"
#include "extract.h"
#include "addrtoname.h"

#define ARISTA_SUBTYPE_TIMESTAMP 0x01

#define ARISTA_TIMESTAMP_V1 0x10
#define ARISTA_TIMESTAMP_V2 0x20

int
arista_ethertype_print(netdissect_options *ndo, const u_char *bp, u_int len _U_)
{
	uint16_t subTypeId;
	uint16_t version;
	u_short bytesConsumed = 0;
	u_short size = 0;

	ndo->ndo_protocol = "arista";

	subTypeId = GET_BE_U_2(bp);
	bp += 2;
	version = GET_BE_U_2(bp);
	bp += 2;
	bytesConsumed += 4;

	ND_PRINT("SubType: 0x%1X, Version: 0x%02x, ", subTypeId, version);

	// TapAgg Header Timestamping
	if (subTypeId == ARISTA_SUBTYPE_TIMESTAMP) {
		// Timestamp has 32-bit lsb in nanosec and remaining msb in sec

		switch (version) {
		case ARISTA_TIMESTAMP_V1:
			ND_PRINT("Timestamp TAI(64-bit)");
			ND_PRINT(": Seconds: %u,", GET_BE_U_4(bp));
			ND_PRINT(" Nanoseconds: %u, ", GET_BE_U_4(bp + 4));
			bytesConsumed += size + 8;
			break;
		case ARISTA_TIMESTAMP_V2:
			ND_PRINT("Timestamp (48-bit)");
			ND_PRINT(": Seconds %u,", GET_BE_U_2(bp));
			ND_PRINT(" Nanoseconds %u, ", GET_BE_U_4(bp + 2));
			bytesConsumed += size + 6;
			break;
		default:
			ND_PRINT("Unknown timestamp Version 0x%02X ", version);
			return -1;
		}
	} else {
		return -1;
	}
	return bytesConsumed;
}
