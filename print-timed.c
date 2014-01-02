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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <tcpdump-stdinc.h>

#include <stdio.h>
#include <string.h>

#include "interface.h"
#include "extract.h"

/*
 * Time Synchronization Protocol
 */

struct tsp_timeval {
	u_int32_t	tv_sec;
	u_int32_t	tv_usec;
};

struct tsp {
	u_int8_t	tsp_type;
	u_int8_t	tsp_vers;
	u_int16_t	tsp_seq;
	union {
		struct tsp_timeval tspu_time;
		int8_t tspu_hopcnt;
	} tsp_u;
	int8_t tsp_name[256];
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

static const char tstr[] = "[|timed]";

static const char *tsptype[TSPTYPENUMBER] =
  { "ANY", "ADJTIME", "ACK", "MASTERREQ", "MASTERACK", "SETTIME", "MASTERUP",
  "SLAVEUP", "ELECTION", "ACCEPT", "REFUSE", "CONFLICT", "RESOLVE", "QUIT",
  "DATE", "DATEREQ", "DATEACK", "TRACEON", "TRACEOFF", "MSITE", "MSITEREQ",
  "TEST", "SETDATE", "SETDATEREQ", "LOOP" };

void
timed_print(register const u_char *bp)
{
#define endof(x) ((u_char *)&(x) + sizeof (x))
	struct tsp *tsp = (struct tsp *)bp;
	long sec, usec;
	const u_char *end;

	if (endof(tsp->tsp_type) > snapend) {
		printf("%s", tstr);
		return;
	}
	if (tsp->tsp_type < TSPTYPENUMBER)
		printf("TSP_%s", tsptype[tsp->tsp_type]);
	else
		printf("(tsp_type %#x)", tsp->tsp_type);

	if (endof(tsp->tsp_vers) > snapend) {
		printf(" %s", tstr);
		return;
	}
	printf(" vers %d", tsp->tsp_vers);

	if (endof(tsp->tsp_seq) > snapend) {
		printf(" %s", tstr);
		return;
	}
	printf(" seq %d", tsp->tsp_seq);

	if (tsp->tsp_type == TSP_LOOP) {
		if (endof(tsp->tsp_hopcnt) > snapend) {
			printf(" %s", tstr);
			return;
		}
		printf(" hopcnt %d", tsp->tsp_hopcnt);
	} else if (tsp->tsp_type == TSP_SETTIME ||
	  tsp->tsp_type == TSP_ADJTIME ||
	  tsp->tsp_type == TSP_SETDATE ||
	  tsp->tsp_type == TSP_SETDATEREQ) {
		if (endof(tsp->tsp_time) > snapend) {
			printf(" %s", tstr);
			return;
		}
		sec = EXTRACT_32BITS(&tsp->tsp_time.tv_sec);
		usec = EXTRACT_32BITS(&tsp->tsp_time.tv_usec);
		if (usec < 0)
			/* corrupt, skip the rest of the packet */
			return;
		fputs(" time ", stdout);
		if (sec < 0 && usec != 0) {
			sec++;
			if (sec == 0)
				fputc('-', stdout);
			usec = 1000000 - usec;
		}
		printf("%ld.%06ld", sec, usec);
	}

	end = memchr(tsp->tsp_name, '\0', snapend - (u_char *)tsp->tsp_name);
	if (end == NULL)
		printf(" %s", tstr);
	else {
		fputs(" name ", stdout);
		fwrite(tsp->tsp_name, end - (u_char *)tsp->tsp_name, 1, stdout);
	}
}
