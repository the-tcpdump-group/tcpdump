/*
 * Copyright (C) Arnaldo Carvalho de Melo 2004
 * Copyright (C) Ian McDonald 2005
 * Copyright (C) Yoshifumi Nishida 2005
 *
 * This software may be distributed either under the terms of the
 * BSD-style license that accompanies tcpdump or the GNU GPL version 2
 */

#ifndef lint
static const char rcsid[] _U_ =
    "@(#) $Header: /tcpdump/master/tcpdump/print-dccp.c,v 1.8 2007-11-09 00:44:09 guy Exp $ (LBL)";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <tcpdump-stdinc.h>

#include "dccp.h"

#include <stdio.h>
#include <string.h>

#include "interface.h"
#include "addrtoname.h"
#include "extract.h"			/* must come after interface.h */
#include "ip.h"
#ifdef INET6
#include "ip6.h"
#endif
#include "ipproto.h"

static const char *dccp_reset_codes[] = {
	"unspecified",
	"closed",
	"aborted",
	"no_connection",
	"packet_error",
	"option_error",
	"mandatory_error",
	"connection_refused",
	"bad_service_code",
	"too_busy",
	"bad_init_cookie",
	"aggression_penalty",
};

static const char *dccp_feature_nums[] = {
	"reserved", 
	"ccid",
	"allow_short_seqno",
	"sequence_window",
	"ecn_incapable", 
	"ack_ratio",     
	"send_ack_vector",
	"send_ndp_count", 
	"minimum checksum coverage", 
	"check data checksum",
};

static inline u_int dccp_csum_coverage(const struct dccp_hdr* dh, u_int len)
{
	u_int cov;
	
	if (DCCPH_CSCOV(dh) == 0)
		return len;
	cov = (dh->dccph_doff + DCCPH_CSCOV(dh) - 1) * sizeof(u_int32_t);
	return (cov > len)? len : cov;
}

static int dccp_cksum(const struct ip *ip,
	const struct dccp_hdr *dh, u_int len)
{
	return nextproto4_cksum(ip, (const u_int8_t *)(void *)dh, len,
				dccp_csum_coverage(dh, len), IPPROTO_DCCP);
}

#ifdef INET6
static int dccp6_cksum(const struct ip6_hdr *ip6, const struct dccp_hdr *dh, u_int len)
{
	return nextproto6_cksum(ip6, (const u_int8_t *)(void *)dh, len,
				dccp_csum_coverage(dh, len), IPPROTO_DCCP);
}
#endif

static const char *dccp_reset_code(u_int8_t code)
{
	if (code >= __DCCP_RESET_CODE_LAST)
		return "invalid";
	return dccp_reset_codes[code];
}

static u_int64_t dccp_seqno(const u_char *bp)
{
	const struct dccp_hdr *dh = (const struct dccp_hdr *)bp;
	u_int64_t seqno;

	if (DCCPH_X(dh) != 0) {
		const struct dccp_hdr_ext *dhx = (const struct dccp_hdr_ext *)bp;
		seqno = EXTRACT_48BITS(dhx->dccph_seq);
	} else {
		seqno = EXTRACT_24BITS(dh->dccph_seq);
	}

	return seqno;
}

static inline unsigned int dccp_basic_hdr_len(const struct dccp_hdr *dh)
{
	return DCCPH_X(dh) ? sizeof(struct dccp_hdr_ext) : sizeof(struct dccp_hdr);
}

static void dccp_print_ack_no(const u_char *bp)
{
	const struct dccp_hdr *dh = (const struct dccp_hdr *)bp;
	const u_char *ackp = bp + dccp_basic_hdr_len(dh);
	u_int64_t ackno;

	if (DCCPH_X(dh) != 0) {
		TCHECK2(*ackp, 8);
		ackno = EXTRACT_48BITS(ackp + 2);
	} else {
		TCHECK2(*ackp, 4);
		ackno = EXTRACT_24BITS(ackp + 1);
	}

	(void)printf("(ack=%" PRIu64 ") ", ackno);
trunc:
	return;
}

static int dccp_print_option(const u_char *option, u_int hlen);

/**
 * dccp_print - show dccp packet
 * @bp - beginning of dccp packet
 * @data2 - beginning of enclosing 
 * @len - lenght of ip packet
 */
void dccp_print(const u_char *bp, const u_char *data2, u_int len)
{
	const struct dccp_hdr *dh;
	const struct ip *ip;
#ifdef INET6
	const struct ip6_hdr *ip6;
#endif
	const u_char *cp;
	u_short sport, dport;
	u_int hlen;
	u_int fixed_hdrlen;

	dh = (const struct dccp_hdr *)bp;

	ip = (struct ip *)data2;
#ifdef INET6
	if (IP_V(ip) == 6)
		ip6 = (const struct ip6_hdr *)data2;
	else
		ip6 = NULL;
#endif /*INET6*/

	/* make sure we have enough data to look at the X bit */
	cp = (const u_char *)(dh + 1);
	if (cp > snapend) {
		printf("[Invalid packet|dccp]");
		return;
	}
	if (len < sizeof(struct dccp_hdr)) {
		printf("truncated-dccp - %u bytes missing!",
			     len - (u_int)sizeof(struct dccp_hdr));
		return;
	}

	/* get the length of the generic header */
	fixed_hdrlen = dccp_basic_hdr_len(dh);
	if (len < fixed_hdrlen) {
		printf("truncated-dccp - %u bytes missing!",
			     len - fixed_hdrlen);
		return;
	}
	TCHECK2(*dh, fixed_hdrlen);

	sport = EXTRACT_16BITS(&dh->dccph_sport);
	dport = EXTRACT_16BITS(&dh->dccph_dport);
	hlen = dh->dccph_doff * 4;

#ifdef INET6
	if (ip6) {
		(void)printf("%s.%d > %s.%d: ",
			     ip6addr_string(&ip6->ip6_src), sport,
			     ip6addr_string(&ip6->ip6_dst), dport);
	} else
#endif /*INET6*/
	{
		(void)printf("%s.%d > %s.%d: ",
			     ipaddr_string(&ip->ip_src), sport,
			     ipaddr_string(&ip->ip_dst), dport);
	}
	fflush(stdout);

	if (qflag) {
		(void)printf(" %d", len - hlen);
		if (hlen > len) {
			(void)printf("dccp [bad hdr length %u - too long, > %u]",
			    hlen, len);
		}
		return;
	}

	/* other variables in generic header */
	if (vflag) {
		(void)printf("CCVal %d, CsCov %d, ", DCCPH_CCVAL(dh), DCCPH_CSCOV(dh));
	}

	/* checksum calculation */
	if (vflag && TTEST2(bp[0], len)) {
		u_int16_t sum = 0, dccp_sum;

		dccp_sum = EXTRACT_16BITS(&dh->dccph_checksum);
		(void)printf("cksum 0x%04x ", dccp_sum);
		if (IP_V(ip) == 4)
			sum = dccp_cksum(ip, dh, len);
#ifdef INET6
		else if (IP_V(ip) == 6)
			sum = dccp6_cksum(ip6, dh, len);
#endif
		if (sum != 0)
			(void)printf("(incorrect -> 0x%04x), ",in_cksum_shouldbe(dccp_sum, sum));
		else
			(void)printf("(correct), ");
	}

	switch (DCCPH_TYPE(dh)) {
	case DCCP_PKT_REQUEST: {
		struct dccp_hdr_request *dhr =
			(struct dccp_hdr_request *)(bp + fixed_hdrlen);
		fixed_hdrlen += 4;
		if (len < fixed_hdrlen) {
			printf("truncated-dccp request - %u bytes missing!",
				     len - fixed_hdrlen);
			return;
		}
		TCHECK(*dhr);
		(void)printf("request (service=%d) ",
			     EXTRACT_32BITS(&dhr->dccph_req_service));
		break;
	}
	case DCCP_PKT_RESPONSE: {
		struct dccp_hdr_response *dhr =
			(struct dccp_hdr_response *)(bp + fixed_hdrlen);
		fixed_hdrlen += 12;
		if (len < fixed_hdrlen) {
			printf("truncated-dccp response - %u bytes missing!",
				     len - fixed_hdrlen);
			return;
		}
		TCHECK(*dhr);
		(void)printf("response (service=%d) ",
			     EXTRACT_32BITS(&dhr->dccph_resp_service));
		break;
	}
	case DCCP_PKT_DATA:
		(void)printf("data ");
		break;
	case DCCP_PKT_ACK: {
		fixed_hdrlen += 8;
		if (len < fixed_hdrlen) {
			printf("truncated-dccp ack - %u bytes missing!",
				     len - fixed_hdrlen);
			return;
		}
		(void)printf("ack ");
		break;
	}
	case DCCP_PKT_DATAACK: {
		fixed_hdrlen += 8;
		if (len < fixed_hdrlen) {
			printf("truncated-dccp dataack - %u bytes missing!",
				     len - fixed_hdrlen);
			return;
		}
		(void)printf("dataack ");
		break;
	}
	case DCCP_PKT_CLOSEREQ:
		fixed_hdrlen += 8;
		if (len < fixed_hdrlen) {
			printf("truncated-dccp closereq - %u bytes missing!",
				     len - fixed_hdrlen);
			return;
		}
		(void)printf("closereq ");
		break;
	case DCCP_PKT_CLOSE:
		fixed_hdrlen += 8;
		if (len < fixed_hdrlen) {
			printf("truncated-dccp close - %u bytes missing!",
				     len - fixed_hdrlen);
			return;
		}
		(void)printf("close ");
		break;
	case DCCP_PKT_RESET: {
		struct dccp_hdr_reset *dhr =
			(struct dccp_hdr_reset *)(bp + fixed_hdrlen);
		fixed_hdrlen += 12;
		if (len < fixed_hdrlen) {
			printf("truncated-dccp reset - %u bytes missing!",
				     len - fixed_hdrlen);
			return;
		}
		TCHECK(*dhr);
		(void)printf("reset (code=%s) ",
			     dccp_reset_code(dhr->dccph_reset_code));
		break;
	}
	case DCCP_PKT_SYNC:
		fixed_hdrlen += 8;
		if (len < fixed_hdrlen) {
			printf("truncated-dccp sync - %u bytes missing!",
				     len - fixed_hdrlen);
			return;
		}
		(void)printf("sync ");
		break;
	case DCCP_PKT_SYNCACK:
		fixed_hdrlen += 8;
		if (len < fixed_hdrlen) {
			printf("truncated-dccp syncack - %u bytes missing!",
				     len - fixed_hdrlen);
			return;
		}
		(void)printf("syncack ");
		break;
	default:
		(void)printf("invalid ");
		break;
	}

	if ((DCCPH_TYPE(dh) != DCCP_PKT_DATA) && 
			(DCCPH_TYPE(dh) != DCCP_PKT_REQUEST))
		dccp_print_ack_no(bp);

	if (vflag < 2)
		return;

	(void)printf("seq %" PRIu64, dccp_seqno(bp));

	/* process options */
	if (hlen > fixed_hdrlen){
		const u_char *cp;
		u_int optlen;
		cp = bp + fixed_hdrlen;
		printf(" <");

		hlen -= fixed_hdrlen;
		while(1){
			optlen = dccp_print_option(cp, hlen);
			if (!optlen)
				break;
			if (hlen <= optlen)
				break;
			hlen -= optlen;
			cp += optlen;
			printf(", ");
		}
		printf(">");
	}
	return;
trunc:
	printf("[|dccp]");
	return;
}

static const struct tok dccp_option_values[] = {
	{ 0, "nop" },
	{ 1, "mandatory" },
	{ 2, "slowreceiver" },
	{ 32, "change_l" },
	{ 33, "confirm_l" },
	{ 34, "change_r" },
	{ 35, "confirm_r" },
	{ 36, "initcookie" },
	{ 37, "ndp_count" },
	{ 38, "ack_vector0" },
	{ 39, "ack_vector1" },
	{ 40, "data_dropped" },
	{ 41, "timestamp" },
	{ 42, "timestamp_echo" },
	{ 43, "elapsed_time" },
	{ 44, "data_checksum" },
        { 0, NULL }
};

static int dccp_print_option(const u_char *option, u_int hlen)
{
	u_int8_t optlen, i;

	TCHECK(*option);

	if (*option >= 32) {
		TCHECK(*(option+1));
		optlen = *(option +1);
		if (optlen < 2) {
			if (*option >= 128)
				printf("CCID option %u optlen too short", *option);
			else
				printf("%s optlen too short",
				    tok2str(dccp_option_values, "Option %u", *option));
			return 0;
		}
	} else
		optlen = 1;

	if (hlen < optlen) {
		if (*option >= 128)
			printf("CCID option %u optlen goes past header length",
			    *option);
		else
			printf("%s optlen goes past header length",
			    tok2str(dccp_option_values, "Option %u", *option));
		return 0;
	}
	TCHECK2(*option, optlen);

	if (*option >= 128) {
		printf("CCID option %d", *option);
		switch (optlen) {
			case 4:
				printf(" %u", EXTRACT_16BITS(option + 2));
				break;
			case 6:
				printf(" %u", EXTRACT_32BITS(option + 2));
				break;
			default:
				break;
		}
	} else {
		printf("%s", tok2str(dccp_option_values, "Option %u", *option));
		switch (*option) {
		case 32:
		case 33:
		case 34:
		case 35:
			if (optlen < 3) {
				printf(" optlen too short");
				return optlen;
			}
			if (*(option + 2) < 10){
				printf(" %s", dccp_feature_nums[*(option + 2)]);
				for (i = 0; i < optlen - 3; i++)
					printf(" %d", *(option + 3 + i));
			}
			break;
		case 36:
			if (optlen > 2) {
				printf(" 0x");
				for (i = 0; i < optlen - 2; i++)
					printf("%02x", *(option + 2 + i));
			}
			break;
		case 37:
			for (i = 0; i < optlen - 2; i++)
				printf(" %d", *(option + 2 + i));
			break;
		case 38:
			if (optlen > 2) {
				printf(" 0x");
				for (i = 0; i < optlen - 2; i++)
					printf("%02x", *(option + 2 + i));
			}
			break;
		case 39:
			if (optlen > 2) {
				printf(" 0x");
				for (i = 0; i < optlen - 2; i++)
					printf("%02x", *(option + 2 + i));
			}
			break;
		case 40:
			if (optlen > 2) {
				printf(" 0x");
				for (i = 0; i < optlen - 2; i++)
					printf("%02x", *(option + 2 + i));
			}
			break;
		case 41:
			if (optlen == 4)
				printf(" %u", EXTRACT_32BITS(option + 2));
			else
				printf(" optlen != 4");
			break;
		case 42:
			if (optlen == 4)
				printf(" %u", EXTRACT_32BITS(option + 2));
			else
				printf(" optlen != 4");
			break;
		case 43:
			if (optlen == 6)
				printf(" %u", EXTRACT_32BITS(option + 2));
			else if (optlen == 4)
				printf(" %u", EXTRACT_16BITS(option + 2));
			else
				printf(" optlen != 4 or 6");
			break;
		case 44:
			if (optlen > 2) {
				printf(" ");
				for (i = 0; i < optlen - 2; i++)
					printf("%02x", *(option + 2 + i));
			}
			break;
		}
	}

	return optlen;
trunc:
	printf("[|dccp]");
	return 0;
}
