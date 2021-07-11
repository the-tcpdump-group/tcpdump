// Copyright (c) 2018 Arista Networks, Inc.  All rights reserved.

/* \summary: EtherType protocol for Arista Networks printer */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "netdissect-stdinc.h"

#include "netdissect.h"
#include "extract.h"
#include "addrtoname.h"

#define ARISTA_SUBTYPE_TIMESTAMP 0x01

#define ARISTA_TIMESTAMP_64_TAI 0x0010
#define ARISTA_TIMESTAMP_64_UTC 0x0110
#define ARISTA_TIMESTAMP_48_TAI 0x0020
#define ARISTA_TIMESTAMP_48_UTC 0x0120

static const struct tok ts_version_name[] = {
	{ ARISTA_TIMESTAMP_64_TAI, "TAI(64-bit)" },
	{ ARISTA_TIMESTAMP_64_UTC, "UTC(64-bit)" },
	{ ARISTA_TIMESTAMP_48_TAI, "TAI(48-bit)" },
	{ ARISTA_TIMESTAMP_48_UTC, "UTC(48-bit)" },
	{ 0, NULL }
};

static inline void
arista_print_date_hms_time(netdissect_options *ndo, uint32_t seconds,
		uint32_t nanoseconds)
{
	time_t ts;
	struct tm *tm;
	char buf[BUFSIZE];

	ts = seconds + (nanoseconds / 1000000000);
	if (NULL == (tm = gmtime(&ts)))
		ND_PRINT(": gmtime() error");
	else if (0 == strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", tm))
		ND_PRINT(": strftime() error");
	else
		ND_PRINT(": %s, %09u ns, ", buf, nanoseconds);
}

int
arista_ethertype_print(netdissect_options *ndo, const u_char *bp, u_int len _U_)
{
	uint16_t subTypeId;
	uint16_t version;
	u_short bytesConsumed = 0;
	u_short size = 0;
	uint32_t seconds, nanoseconds;

	ndo->ndo_protocol = "arista";

	subTypeId = GET_BE_U_2(bp);
	bp += 2;
	version = GET_BE_U_2(bp);
	bp += 2;
	bytesConsumed += 4;

	ND_PRINT("SubType: 0x%1x, Version: 0x%04x, ", subTypeId, version);

	// TapAgg Header Timestamping
	if (subTypeId == ARISTA_SUBTYPE_TIMESTAMP) {
		// Timestamp has 32-bit lsb in nanosec and remaining msb in sec
		ND_PRINT("Timestamp %s", tok2str(ts_version_name,
					"Unknown timestamp Version 0x%04x ", version));
		switch (version) {
		case ARISTA_TIMESTAMP_64_TAI:
		case ARISTA_TIMESTAMP_64_UTC:
			seconds = GET_BE_U_4(bp);
			nanoseconds = GET_BE_U_4(bp + 4);
			arista_print_date_hms_time(ndo, seconds, nanoseconds);
			bytesConsumed += size + 8;
			break;
		case ARISTA_TIMESTAMP_48_TAI:
		case ARISTA_TIMESTAMP_48_UTC:
			ND_PRINT(": Seconds %u,", GET_BE_U_2(bp));
			ND_PRINT(" Nanoseconds %u, ", GET_BE_U_4(bp + 2));
			bytesConsumed += size + 6;
			break;
		default:
			return -1;
		}
	} else {
		return -1;
	}
	return bytesConsumed;
}
