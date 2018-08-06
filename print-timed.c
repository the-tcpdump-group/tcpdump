/*
 * Copyright (c) 2000 Ben Smithurst <ben@scientia.demon.co.uk>
 * All rights reserved.
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

/* \summary: Berkeley UNIX Time Synchronization Protocol */

/* specification: http://docs.freebsd.org/44doc/smm/12.timed/paper.pdf */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "netdissect-stdinc.h"

#include "netdissect.h"
#include "extract.h"

struct tsp_timeval {
	nd_int32_t	tv_sec;
	nd_int32_t	tv_usec;
};

struct tsp {
	nd_uint8_t	tsp_type;
	nd_uint8_t	tsp_vers;
	nd_uint16_t	tsp_seq;
	union {
		struct tsp_timeval tspu_time;
		nd_int8_t tspu_hopcnt;
	} tsp_u;
	nd_byte		tsp_name[256];	/* null-terminated string up to 256 */
};

#define	tsp_time	tsp_u.tspu_time
#define	tsp_hopcnt	tsp_u.tspu_hopcnt

/*
 * Command types.
 */
#define	TSP_ANY			0	/* match any types */
#define	TSP_ADJTIME		1	/* send adjtime */
#define	TSP_ACK			2	/* generic acknowledgement */
#define	TSP_MASTERREQ		3	/* ask for master's name */
#define	TSP_MASTERACK		4	/* acknowledge master request */
#define	TSP_SETTIME		5	/* send network time */
#define	TSP_MASTERUP		6	/* inform slaves that master is up */
#define	TSP_SLAVEUP		7	/* slave is up but not polled */
#define	TSP_ELECTION		8	/* advance candidature for master */
#define	TSP_ACCEPT		9	/* support candidature of master */
#define	TSP_REFUSE		10	/* reject candidature of master */
#define	TSP_CONFLICT		11	/* two or more masters present */
#define	TSP_RESOLVE		12	/* masters' conflict resolution */
#define	TSP_QUIT		13	/* reject candidature if master is up */
#define	TSP_DATE		14	/* reset the time (date command) */
#define	TSP_DATEREQ		15	/* remote request to reset the time */
#define	TSP_DATEACK		16	/* acknowledge time setting  */
#define	TSP_TRACEON		17	/* turn tracing on */
#define	TSP_TRACEOFF		18	/* turn tracing off */
#define	TSP_MSITE		19	/* find out master's site */
#define	TSP_MSITEREQ		20	/* remote master's site request */
#define	TSP_TEST		21	/* for testing election algo */
#define	TSP_SETDATE		22	/* New from date command */
#define	TSP_SETDATEREQ		23	/* New remote for above */
#define	TSP_LOOP		24	/* loop detection packet */

#define	TSPTYPENUMBER		25


static const char *tsptype[TSPTYPENUMBER] =
  { "ANY", "ADJTIME", "ACK", "MASTERREQ", "MASTERACK", "SETTIME", "MASTERUP",
  "SLAVEUP", "ELECTION", "ACCEPT", "REFUSE", "CONFLICT", "RESOLVE", "QUIT",
  "DATE", "DATEREQ", "DATEACK", "TRACEON", "TRACEOFF", "MSITE", "MSITEREQ",
  "TEST", "SETDATE", "SETDATEREQ", "LOOP" };

void
timed_print(netdissect_options *ndo,
            const u_char *bp)
{
	const struct tsp *tsp = (const struct tsp *)bp;
	uint8_t tsp_type;
	int sec, usec;

	ndo->ndo_protocol = "timed";
	ND_TCHECK_1(tsp->tsp_type);
	tsp_type = EXTRACT_U_1(tsp->tsp_type);
	if (tsp_type < TSPTYPENUMBER)
		ND_PRINT("TSP_%s", tsptype[tsp_type]);
	else
		ND_PRINT("(tsp_type %#x)", tsp_type);

	ND_TCHECK_1(tsp->tsp_vers);
	ND_PRINT(" vers %u", EXTRACT_U_1(tsp->tsp_vers));

	ND_TCHECK_2(tsp->tsp_seq);
	ND_PRINT(" seq %u", EXTRACT_BE_U_2(tsp->tsp_seq));

	switch (tsp_type) {
	case TSP_LOOP:
		ND_TCHECK_1(tsp->tsp_hopcnt);
		ND_PRINT(" hopcnt %u", EXTRACT_U_1(tsp->tsp_hopcnt));
		break;
	case TSP_SETTIME:
	case TSP_ADJTIME:
	case TSP_SETDATE:
	case TSP_SETDATEREQ:
		ND_TCHECK_8(&tsp->tsp_time);
		sec = EXTRACT_BE_S_4(tsp->tsp_time.tv_sec);
		usec = EXTRACT_BE_S_4(tsp->tsp_time.tv_usec);
		/* XXX The comparison below is always false? */
		if (usec < 0)
			/* invalid, skip the rest of the packet */
			return;
		ND_PRINT(" time ");
		if (sec < 0 && usec != 0) {
			sec++;
			if (sec == 0)
				ND_PRINT("-");
			usec = 1000000 - usec;
		}
		ND_PRINT("%d.%06d", sec, usec);
		break;
	}
	ND_PRINT(" name ");
	if (nd_printzp(ndo, tsp->tsp_name, sizeof(tsp->tsp_name),
		       ndo->ndo_snapend))
		goto trunc;
	return;

trunc:
	nd_print_trunc(ndo);
}
