/*	$NetBSD: print-ah.c,v 1.4 1996/05/20 00:41:16 fvdl Exp $	*/

/*
 * Copyright (c) 1988, 1989, 1990, 1991, 1992, 1993, 1994
 *	The Regents of the University of California.  All rights reserved.
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

#ifndef lint
static const char rcsid[] =
    "@(#) $Header: /tcpdump/master/tcpdump/print-esp.c,v 1.35 2003-03-13 07:40:48 guy Exp $ (LBL)";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>

#include <tcpdump-stdinc.h>

#include <stdlib.h>

#ifdef HAVE_LIBCRYPTO
#include <openssl/des.h>
#include <openssl/blowfish.h>
#ifdef HAVE_OPENSSL_RC5_H
#include <openssl/rc5.h>
#endif
#ifdef HAVE_OPENSSL_CAST_H
#include <openssl/cast.h>
#endif
#endif

#include <stdio.h>

#include "ip.h"
#include "esp.h"
#ifdef INET6
#include "ip6.h"
#endif

#if defined(__MINGW32__) || defined(__WATCOMC__)
#include "addrinfo.h"
extern char *strsep (char **stringp, const char *delim); /* Missing/strsep.c */
#endif

#define AVOID_CHURN 1
#include "interface.h"
#include "addrtoname.h"
#include "extract.h"

enum cipher { NONE,
	      DESCBC,
	      BLOWFISH,
	      RC5,
	      CAST128,
	      DES3CBC};



struct esp_algorithm {
  const char   *name;
  enum  cipher algo;
  int          ivlen;
  int          authlen;
  int          replaysize;   /* number of bytes, in excess of 4,
				may be negative */
};

struct esp_algorithm esp_xforms[]={
	{"none",                  NONE,    0,  0, 0},
	{"des-cbc",               DESCBC,  8,  0, 0},
	{"des-cbc-hmac96",        DESCBC,  8, 12, 0},
	{"blowfish-cbc",          BLOWFISH,8,  0, 0},
	{"blowfish-cbc-hmac96",   BLOWFISH,8, 12, 0},
	{"rc5-cbc",               RC5,     8,  0, 0},
	{"rc5-cbc-hmac96",        RC5,     8, 12, 0},
	{"cast128-cbc",           CAST128, 8,  0, 0},
	{"cast128-cbc-hmac96",    CAST128, 8, 12, 0},
	{"3des-cbc-hmac96",       DES3CBC, 8, 12, 0},
	{NULL,                    NONE,    0,  0, 0}
};

struct esp_algorithm *null_xf =
  &esp_xforms[sizeof(esp_xforms)/sizeof(esp_xforms[0]) - 1];

#ifndef HAVE_SOCKADDR_STORAGE
#ifdef INET6
struct sockaddr_storage {
	union {
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
	} un;
};
#else
#define sockaddr_storage sockaddr
#endif
#endif /* HAVE_SOCKADDR_STORAGE */

struct sa_list {
  struct sa_list *next;
  struct sockaddr_storage daddr;
  uint32_t         spi;
  struct         esp_algorithm *xform;
  char           secret[256];  /* is that big enough for all secrets? */
  int            secretlen;
};

static struct sa_list *sa_list_head=NULL;
static struct sa_list *sa_default=NULL;

static void esp_print_addsa(struct sa_list *sa, int sa_def)
{
  /* copy the "sa" */

  struct sa_list *nsa;

  nsa = (struct sa_list *)malloc(sizeof(struct sa_list));
  if(nsa == NULL ) {
    fprintf(stderr, "%s: ran out of memory (%d) to allocate sa structure\n",
	    program_name, sizeof(struct sa_list));
    exit(2);
  }

  *nsa = *sa;

  if(sa_def) {
    sa_default = nsa;
  }

  nsa->next = sa_list_head;
  sa_list_head = nsa;
}
 

static int hexdigit(char hex)
{
	if(hex >= '0' && hex <= '9') {
		return (hex - '0');
	} else if(hex >= 'A' && hex <= 'F') {
		return (hex - 'A' + 10);
	} else if(hex >= 'a' && hex <= 'f') {
		return (hex - 'a' + 10);
	} else {
		printf("invalid hex digit %c in espsecret\n", hex);
		return 0;
	}
}

static int hex2byte(char *hexstring)
{
	int byte;

	byte = (hexdigit(hexstring[0]) << 4) +
		hexdigit(hexstring[1]);
	return byte;
}

/* 
 * decode the form:    SPINUM@IP <tab> ALGONAME:0xsecret
 *
 * special form: file /name 
 * causes us to go read from this file instead.
 *
 */

static void esp_print_decode_onesecret(char *line)
{
  struct esp_algorithm *xf;
  struct sa_list sa1;
  int sa_def;

  char *spikey;
  char *decode;

  spikey = strsep(&line, " \t");
  sa_def = 0;
  memset(&sa1, 0, sizeof(struct sa_list));

  /* if there is only one token, then it is an algo:key token */
  if(line == NULL) {
    decode = spikey;
    spikey = NULL;
    /* memset(&sa1.daddr, 0, sizeof(sa1.daddr)); */
    /* sa1.spi = 0; */
    sa_def    = 1;
  } else {
    decode = line;
  }

  if(spikey && strcasecmp(spikey, "file")==0) {
    /* open file and read it */
    FILE *secretfile;
    char  fileline[1024];
    char  *nl;

    secretfile = fopen(line, FOPEN_READ_TXT);
    if(secretfile == NULL) {
      perror(line);
      exit(3);
    }
    
    while(fgets(fileline, sizeof(fileline)-1, secretfile) != NULL) {

      /* remove newline from the line */
      nl = strchr(fileline, '\n');
      if(nl) {
	*nl = '\0';
      }
      if(fileline[0]=='#') continue;
      if(fileline[0]=='\0') continue;
      
      esp_print_decode_onesecret(fileline);
    }
    fclose(secretfile);
    
    return;
  }

  if(spikey) {
    char *spistr, *foo;
    u_int32_t spino;
    struct sockaddr_in *sin;
#ifdef INET6
    struct sockaddr_in6 *sin6;
#endif

    spistr = strsep(&spikey, "@");
   
    spino = strtoul(spistr, &foo, 0);
    if(spistr == foo || !spikey) {
      printf("print_esp: failed to decode spi# %s\n", foo);
      return;
    }

    sa1.spi = spino;

    sin = (struct sockaddr_in *)&sa1.daddr;
#ifdef INET6
    sin6 = (struct sockaddr_in6 *)&sa1.daddr;
    if(inet_pton(AF_INET6, spikey, &sin6->sin6_addr) == 1) {
#ifdef HAVE_SOCKADDR_SA_LEN
      sin6->sin6_len = sizeof(struct sockaddr_in6);
#endif
      sin6->sin6_family = AF_INET6;
    } else
#endif
    if(inet_pton(AF_INET, spikey, &sin->sin_addr) == 1) {
#ifdef HAVE_SOCKADDR_SA_LEN
      sin->sin_len = sizeof(struct sockaddr_in);
#endif
      sin->sin_family = AF_INET;
    } else {
      printf("print_esp: can not decode IP# %s\n", spikey);
      return;
    }
  }

  if(decode) {
    char *colon;
    char  espsecret_key[256];
    unsigned int   len, i;

    /* skip any blank spaces */
    while(isspace(*decode)) decode++;

    colon = strchr(decode, ':');
    if(colon == NULL) {
      printf("failed to decode espsecret: %s\n", decode);
      return;
    }

    len = colon - decode;
    xf = esp_xforms;
    while(xf->name && strncasecmp(decode, xf->name, len)!=0) {
      xf++;
    }
    if(xf->name == NULL) {
      printf("failed to find cipher algo %s\n", decode);
      /* set to NULL transform */
      return;
    }
    sa1.xform = xf;

    colon++;
    if(colon[0]=='0' && colon[1]=='x') {
      /* decode some hex! */
      colon+=2;
      len = strlen(colon) / 2;

      if(len > 256) {
	printf("secret is too big: %d\n", len);
	return;
      }

      i = 0;
      while(colon[0] != '\0' && colon[1]!='\0') {
	espsecret_key[i]=hex2byte(colon);
	colon+=2;
	i++;
      }
      memcpy(sa1.secret, espsecret_key, i);
      sa1.secretlen=i;
    } else {
      i = strlen(colon);
      if(i < sizeof(sa1.secret)) {
	memcpy(sa1.secret, espsecret_key, i);
	sa1.secretlen = i;
      } else {
	memcpy(sa1.secret, espsecret_key, sizeof(sa1.secret));
	sa1.secretlen = sizeof(sa1.secret);
      }
    }
    
  }

  esp_print_addsa(&sa1, sa_def);
}


static void esp_print_decodesecret(void)
{
  char *line;
  char *p;
  
  if(espsecret == NULL) {
    sa_list_head = NULL;
    return;
  }
  
  if(sa_list_head != NULL) {
    return;
  }
  
  p=espsecret;
  
  while(espsecret && espsecret[0]!='\0') { 
    /* pick out the first line or first thing until a comma */
    if((line = strsep(&espsecret, "\n,"))==NULL) {
      line=espsecret;
      espsecret=NULL;
    }
    
    esp_print_decode_onesecret(line);
  }
}

int
esp_print(register const u_char *bp, register const u_char *bp2,
	  int *nhdr, int *padlen)
{
	register const struct newesp *esp;
	register const u_char *ep;
	struct ip *ip;
	struct sa_list *sa = NULL;
	int espsecret_keylen;
#ifdef INET6
	struct ip6_hdr *ip6 = NULL;
#endif
	int advance;
	int len;
	char *secret;
	int ivlen = 0;
	u_char *ivoff;
#ifdef HAVE_LIBCRYPTO
	u_char *p;
#endif

	esp = (struct newesp *)bp;
	secret = NULL;
	advance = 0;

#if 0
	/* keep secret out of a register */
	p = (u_char *)&secret;
#endif

	/* 'ep' points to the end of available data. */
	ep = snapend;

	if ((u_char *)(esp + 1) >= ep) {
		fputs("[|ESP]", stdout);
		goto fail;
	}
	printf("ESP(spi=0x%08x", EXTRACT_32BITS(&esp->esp_spi));
	printf(",seq=0x%x", EXTRACT_32BITS(&esp->esp_seq));
	printf(")");

	/* if we don't have decryption key, we can't decrypt this packet. */
	if(sa_list_head == NULL) {
	  if (!espsecret) {
	    goto fail;
	  }
	  esp_print_decodesecret();
	}

	if(sa_list_head == NULL) {
		goto fail;
	}

	ip = (struct ip *)bp2;
	switch (IP_V(ip)) {
#ifdef INET6
	case 6:
		ip6 = (struct ip6_hdr *)bp2;
		/* we do not attempt to decrypt jumbograms */
		if (!EXTRACT_16BITS(&ip6->ip6_plen))
			goto fail;
		/* if we can't get nexthdr, we do not need to decrypt it */
		len = sizeof(struct ip6_hdr) + EXTRACT_16BITS(&ip6->ip6_plen);

		/* see if we can find the SA, and if so, decode it */
		for (sa = sa_list_head; sa != NULL; sa = sa->next) {
			struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&sa->daddr;
			if (sa->spi == ntohl(esp->esp_spi) &&
			    sin6->sin6_family == AF_INET6 &&
			    memcmp(&sin6->sin6_addr, &ip6->ip6_dst,
				   sizeof(struct in6_addr)) == 0) {
				break;
			}
		}
		break;
#endif /*INET6*/
	case 4:
		/* nexthdr & padding are in the last fragment */
		if (EXTRACT_16BITS(&ip->ip_off) & IP_MF)
			goto fail;
		len = EXTRACT_16BITS(&ip->ip_len);

		/* see if we can find the SA, and if so, decode it */
		for (sa = sa_list_head; sa != NULL; sa = sa->next) {
			struct sockaddr_in *sin = (struct sockaddr_in *)&sa->daddr;
			if (sa->spi == ntohl(esp->esp_spi) &&
			    sin->sin_family == AF_INET &&
			    sin->sin_addr.s_addr == ip->ip_dst.s_addr) {
				break;
			}
		}
		break;
	default:
		goto fail;
	}

	/* if we didn't find the specific one, then look for
	 * an unspecified one.
	 */
	if(sa == NULL) {
		sa = sa_default;
	}
	
	/* if not found fail */
	if(sa == NULL)
		goto fail;

	/* if we can't get nexthdr, we do not need to decrypt it */
	if (ep - bp2 < len)
		goto fail;
	if (ep - bp2 > len) {
		/* FCS included at end of frame (NetBSD 1.6 or later) */
		ep = bp2 + len;
	}

	ivoff = (u_char *)(esp + 1) + sa->xform->replaysize;
	ivlen = sa->xform->ivlen;
	secret = sa->secret;
	espsecret_keylen = sa->secretlen;

	switch (sa->xform->algo) {
	case DESCBC:
#ifdef HAVE_LIBCRYPTO
	    {
		u_char iv[8];
#if OPENSSL_VERSION_NUMBER >= 0x00907000L
		DES_key_schedule schedule;
#else
		des_key_schedule schedule;
#endif

		switch (ivlen) {
		case 4:
			memcpy(iv, ivoff, 4);
			memcpy(&iv[4], ivoff, 4);
			p = &iv[4];
			*p++ ^= 0xff;
			*p++ ^= 0xff;
			*p++ ^= 0xff;
			*p++ ^= 0xff;
			break;
		case 8:
			memcpy(iv, ivoff, 8);
			break;
		default:
			goto fail;
		}
		p = ivoff + ivlen;

		if (espsecret_keylen != 8)
			goto fail;

#if OPENSSL_VERSION_NUMBER >= 0x00908000L
		DES_set_key_unchecked((const_DES_cblock *)secret, &schedule);

		DES_cbc_encrypt((const unsigned char *)p, p,
			(long)(ep - p), &schedule, (DES_cblock *)iv,
			DES_DECRYPT);

#elif OPENSSL_VERSION_NUMBER >= 0x00907000L
		DES_set_key_unchecked((DES_cblock *)secret, schedule);

		DES_cbc_encrypt((const unsigned char *)p, p,
			(long)(ep - p), schedule, (DES_cblock *)iv,
			DES_DECRYPT);
#else
		des_check_key = 0;
		des_set_key((void *)secret, schedule);

		des_cbc_encrypt((void *)p, (void *)p,
			(long)(ep - p), schedule, (void *)iv,
			DES_DECRYPT);
#endif
		advance = ivoff - (u_char *)esp + ivlen;
		break;
	    }
#else
		goto fail;
#endif /*HAVE_LIBCRYPTO*/

	case BLOWFISH:
#ifdef HAVE_LIBCRYPTO
	    {
		BF_KEY schedule;

		if (espsecret_keylen < 5 || espsecret_keylen > 56)
			goto fail;
		BF_set_key(&schedule, espsecret_keylen, secret);

		p = ivoff + ivlen;
		BF_cbc_encrypt(p, p, (long)(ep - p), &schedule, ivoff,
			BF_DECRYPT);
		advance = ivoff - (u_char *)esp + ivlen;
		break;
	    }
#else
		goto fail;
#endif /*HAVE_LIBCRYPTO*/

	case RC5:
#if defined(HAVE_LIBCRYPTO) && defined(HAVE_RC5_H)
	    {
		RC5_32_KEY schedule;

		if (espsecret_keylen < 5 || espsecret_keylen > 255)
			goto fail;
		RC5_32_set_key(&schedule, espsecret_keylen, secret,
			RC5_16_ROUNDS);

		p = ivoff + ivlen;
		RC5_32_cbc_encrypt(p, p, (long)(ep - p), &schedule, ivoff,
			RC5_DECRYPT);
		advance = ivoff - (u_char *)esp + ivlen;
		break;
	    }
#else
		goto fail;
#endif /*HAVE_LIBCRYPTO*/

	case CAST128:
#if defined(HAVE_LIBCRYPTO) && defined(HAVE_CAST_H) && !defined(HAVE_BUGGY_CAST128)
	    {
		CAST_KEY schedule;

		if (espsecret_keylen < 5 || espsecret_keylen > 16)
			goto fail;
		CAST_set_key(&schedule, espsecret_keylen, secret);

		p = ivoff + ivlen;
		CAST_cbc_encrypt(p, p, (long)(ep - p), &schedule, ivoff,
			CAST_DECRYPT);
		advance = ivoff - (u_char *)esp + ivlen;
		break;
	    }
#else
		goto fail;
#endif /*HAVE_LIBCRYPTO*/

	case DES3CBC:
#if defined(HAVE_LIBCRYPTO)
	    {
#if OPENSSL_VERSION_NUMBER >= 0x00907000L
		DES_key_schedule s1, s2, s3;

		if (espsecret_keylen != 24)
			goto fail;
		DES_set_odd_parity((DES_cblock *)secret);
		DES_set_odd_parity((DES_cblock *)(secret + 8));
		DES_set_odd_parity((DES_cblock *)(secret + 16));
#if OPENSSL_VERSION_NUMBER >= 0x00908000L
		if(DES_set_key_checked((const_DES_cblock *)secret, &s1) != 0) {
		  printf("failed to schedule key 1\n");
		}
		if(DES_set_key_checked((const_DES_cblock *)(secret + 8), &s2)!=0) {
		  printf("failed to schedule key 2\n");
		}
		if(DES_set_key_checked((const_DES_cblock *)(secret + 16), &s3)!=0) {
		  printf("failed to schedule key 3\n");
		}
#else
		if(DES_set_key_checked((DES_cblock *)secret, s1) != 0) {
		  printf("failed to schedule key 1\n");
		}
		if(DES_set_key_checked((DES_cblock *)(secret + 8), s2)!=0) {
		  printf("failed to schedule key 2\n");
		}
		if(DES_set_key_checked((DES_cblock *)(secret + 16), s3)!=0) {
		  printf("failed to schedule key 3\n");
		}
#endif

		p = ivoff + ivlen;
		DES_ede3_cbc_encrypt((const unsigned char *)p, p,
				     (long)(ep - p),
				     &s1, &s2, &s3,
				     (DES_cblock *)ivoff, DES_DECRYPT);
#else
		des_key_schedule s1, s2, s3;

		if (espsecret_keylen != 24)
			goto fail;
		des_check_key = 1;
		des_set_odd_parity((void *)secret);
		des_set_odd_parity((void *)(secret + 8));
		des_set_odd_parity((void *)(secret + 16));
		if(des_set_key((void *)secret, s1) != 0) {
		  printf("failed to schedule key 1\n");
		}
		if(des_set_key((void *)(secret + 8), s2)!=0) {
		  printf("failed to schedule key 2\n");
		}
		if(des_set_key((void *)(secret + 16), s3)!=0) {
		  printf("failed to schedule key 3\n");
		}

		p = ivoff + ivlen;
		des_ede3_cbc_encrypt((void *)p, (void *)p,
				     (long)(ep - p),
				     s1, s2, s3,
				     (void *)ivoff, DES_DECRYPT);
#endif
		advance = ivoff - (u_char *)esp + ivlen;
		break;
	    }
#else
		goto fail;
#endif /*HAVE_LIBCRYPTO*/

	case NONE:
	default:
		advance = sizeof(struct newesp) + sa->xform->replaysize;
		break;
	}

	ep = ep - sa->xform->authlen;
	/* sanity check for pad length */
	if (ep - bp < *(ep - 2))
		goto fail;

	if (padlen)
		*padlen = *(ep - 2) + 2;

	if (nhdr)
		*nhdr = *(ep - 1);

	printf(": ");
	return advance;

fail:
	if (nhdr)
		*nhdr = -1;
	return 65536;
}
