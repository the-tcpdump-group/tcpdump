/*
 * Copyright (C) 2001 WIDE Project.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef lint
static const char rcsid[] =
    "@(#) $Header: /tcpdump/master/tcpdump/print-lwres.c,v 1.1 2001-01-29 09:18:50 itojun Exp $ (LBL)";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/param.h>
#include <sys/time.h>

#include <netinet/in.h>

#ifdef NOERROR
#undef NOERROR					/* Solaris sucks */
#endif
#ifdef NOERROR
#undef T_UNSPEC					/* SINIX does too */
#endif
#include "nameser.h"

#include <stdio.h>
#include <string.h>

#include "interface.h"
#include "addrtoname.h"
#include "extract.h"                    /* must come after interface.h */

/* BIND9 lib/lwres/include/lwres */
typedef u_int32_t lwres_uint32_t;
typedef u_int16_t lwres_uint16_t;
typedef u_int8_t lwres_uint8_t;

struct lwres_lwpacket {
	lwres_uint32_t		length;
	lwres_uint16_t		version;
	lwres_uint16_t		pktflags;
	lwres_uint32_t		serial;
	lwres_uint32_t		opcode;
	lwres_uint32_t		result;
	lwres_uint32_t		recvlength;
	lwres_uint16_t		authtype;
	lwres_uint16_t		authlength;
};

#define LWRES_FLAG_TRUSTNOTREQUIRED	0x00000001U
#define LWRES_FLAG_SECUREDATA		0x00000002U

/*
 * no-op
 */
#define LWRES_OPCODE_NOOP		0x00000000U

typedef struct {
	/* public */
	lwres_uint16_t			datalength;
	unsigned char			*data;
} lwres_nooprequest_t;

typedef struct {
	/* public */
	lwres_uint16_t			datalength;
	unsigned char		       *data;
} lwres_noopresponse_t;

/*
 * get addresses by name
 */
#define LWRES_OPCODE_GETADDRSBYNAME	0x00010001U

typedef struct {
	/* public */
	lwres_uint32_t			flags;
	lwres_uint32_t			addrtypes;
	lwres_uint16_t			namelen;
	/* name follows */
} lwres_gabnrequest_t;

typedef struct {
	/* public */
	lwres_uint32_t			flags;
	lwres_uint16_t			naliases;
	lwres_uint16_t			naddrs;
	char			       *realname;
	char			      **aliases;
	lwres_uint16_t			realnamelen;
	lwres_uint16_t		       *aliaslen;
#if 0
	lwres_addrlist_t		addrs;
	/* if base != NULL, it will be freed when this structure is freed. */
	void			       *base;
	size_t				baselen;
#endif
} lwres_gabnresponse_t;

/*
 * get name by address
 */
#define LWRES_OPCODE_GETNAMEBYADDR	0x00010002U
typedef struct {
	/* public */
	lwres_uint32_t			flags;
#if 0
	lwres_addr_t			addr;
#endif
} lwres_gnbarequest_t;

typedef struct {
	/* public */
	lwres_uint32_t			flags;
	lwres_uint16_t			naliases;
#if 0
	char			       *realname;
	char			      **aliases;
	lwres_uint16_t			realnamelen;
	lwres_uint16_t		       *aliaslen;
	/* if base != NULL, it will be freed when this structure is freed. */
	void			       *base;
	size_t				baselen;
#endif
} lwres_gnbaresponse_t;

/*
 * get rdata by name
 */
#define LWRES_OPCODE_GETRDATABYNAME	0x00010003U

typedef struct {
	/* public */
	lwres_uint32_t			flags;
	lwres_uint16_t			rdclass;
	lwres_uint16_t			rdtype;
	lwres_uint16_t			namelen;
#if 0
	char			       *name;
#endif
} lwres_grbnrequest_t;

typedef struct {
	/* public */
	lwres_uint32_t			flags;
	lwres_uint16_t			rdclass;
	lwres_uint16_t			rdtype;
	lwres_uint32_t			ttl;
	lwres_uint16_t			nrdatas;
	lwres_uint16_t			nsigs;
#if 0
	char			       *realname;
	lwres_uint16_t			realnamelen;
	unsigned char		      **rdatas;
	lwres_uint16_t		       *rdatalen;
	unsigned char		      **sigs;
	lwres_uint16_t		       *siglen;
	/* if base != NULL, it will be freed when this structure is freed. */
	void			       *base;
	size_t				baselen;
#endif
} lwres_grbnresponse_t;

#define LWRDATA_VALIDATED	0x00000001

#define LWRES_ADDRTYPE_V4		0x00000001U	/* ipv4 */
#define LWRES_ADDRTYPE_V6		0x00000002U	/* ipv6 */

#define LWRES_MAX_ALIASES		16		/* max # of aliases */
#define LWRES_MAX_ADDRS			64		/* max # of addrs */

struct vstr {
	u_int32_t v;
	const char *s;
};

struct vstr opcode[] = {
	{ LWRES_OPCODE_NOOP,		"noop", },
	{ LWRES_OPCODE_GETADDRSBYNAME,	"getaddrsbyname", },
	{ LWRES_OPCODE_GETNAMEBYADDR,	"getnamebyaddr", },
	{ LWRES_OPCODE_GETRDATABYNAME,	"getrdatabyname", },
	{ 0, 				NULL, },
};

static const char *vtostr(struct vstr *, u_int32_t, const char *);

static const char *
vtostr(p, v, lastresort)
	struct vstr *p;
	u_int32_t v;
	const char *lastresort;
{

	while (p->s) {
		if (v == p->v)
			return p->s;
		p++;
	}

	return lastresort;
}

void
lwres_print(register const u_char *bp, u_int length)
{
	const struct lwres_lwpacket *np;
	u_int32_t v;
	const char *s;
#if 0
	u_int32_t l;
	lwres_gabnrequest_t *gabn;
	int i;
#endif

	np = (const struct lwres_lwpacket *)bp;
	TCHECK(np->authlength);

	printf(" lwres");
	if (vflag)
		printf(" v%u", ntohs(np->version));

	/* opcode */
	v = (u_int32_t)ntohl(np->opcode);
	s = vtostr(opcode, v, NULL);
	if (s) {
		printf(" %s", s);
		if (vflag)
			printf("(0x%x)", v);
	} else
		printf(" 0x%x", v);

	/* flag bit */
	v = ntohs(np->pktflags);
	if (v) {
		printf("[%s%s]",
		    (v & LWRES_FLAG_TRUSTNOTREQUIRED) ? "t" : "", 
		    (v & LWRES_FLAG_SECUREDATA) ? "S" : "");
	}

	if (vflag > 1) {
		printf(" (");	/*)*/
		printf("serial:0x%x", (unsigned int)ntohl(np->serial));
		printf(" result:0x%x", (unsigned int)ntohl(np->result));
		printf(" recvlen:%u", (unsigned int)ntohl(np->recvlength));
		printf(" authtype:0x%x", ntohs(np->authtype));
		printf(" authlen:%u", ntohs(np->authlength));
		/*(*/
		printf(")");
	}

#if 0 /*not completed yet*/
	/* per-opcode content */
	switch (ntohl(np->opcode)) {
	case LWRES_OPCODE_NOOP:
		break;
	case LWRES_OPCODE_GETADDRSBYNAME:
		gabn = (lwres_gabnrequest_t *)(np + 1);
		TCHECK(gabn->namelen);
		/* XXX gabn points to packed struct */
		s = (const char *)&gabn->namelen + sizeof(gabn->namelen);
		l = ntohs(gabn->namelen);
		if (s + l > (const char *)snapend)
			goto trunc;

		printf(" flags:0x%x", (unsigned int)ntohl(gabn->flags));
		v = (u_int32_t)ntohl(gabn->addrtypes);
		switch (v & (LWRES_ADDRTYPE_V4 | LWRES_ADDRTYPE_V6)) {
		case LWRES_ADDRTYPE_V4:
			printf(" IPv4");
			break;
		case LWRES_ADDRTYPE_V6:
			printf(" IPv6");
			break;
		case LWRES_ADDRTYPE_V4 | LWRES_ADDRTYPE_V6:
			printf(" IPv4/6");
			break;
		}
		if (v & ~(LWRES_ADDRTYPE_V4 | LWRES_ADDRTYPE_V6))
			printf("[0x%x]", v);
		printf(" ");
		for (i = 0; i < l; i++)
			safeputchar(s[i]);
		break;
	case LWRES_OPCODE_GETNAMEBYADDR:
		break;
	case LWRES_OPCODE_GETRDATABYNAME:
		break;
	default:
		break;
	}
#endif

	/* length mismatch */
	if (ntohl(np->length) != length)
		printf(" [len: %u != %u]", (unsigned int)ntohl(np->length), length);
	return;

  trunc:
	printf("[|lwres]");
	return;
}
