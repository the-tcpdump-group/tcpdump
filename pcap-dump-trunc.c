/*
 * Copyright (c) 2001
 *	Seth Webster <swebster@sst.ll.mit.edu>
 *
 * License: BSD
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *  3. The names of the authors may not be used to endorse or promote
 *     products derived from this software without specific prior
 *     written permission.
 *  
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 *
 */

#include <stdio.h>
#include <pcap.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include "interface.h"

static void reverse(char *s);
static void swebitoa(unsigned int n, char s[]);

static void reverse (char s[]) {
  int i, j, c;
  
  for (i = 0, j = strlen(s)-1; i < j; i++, j--) {
    c = s[i];
    s[i] = s[j];
    s[j] = c;
  }
}


static void swebitoa (unsigned int n, char s[]) {
  
  unsigned int i;
  
  i = 0;
  do {
    s[i++] = n % 10 + '0';
  } while ((n /= 10) > 0);
  
  s[i] = '\0';
  reverse(s);
}

void
dump_and_trunc(u_char *user, const struct pcap_pkthdr *h, const u_char *sp)
{
	extern char *WFileName;
	register FILE *f;
	static uint cnt = 2;
	char *name;
	extern pcap_t *pd;
	extern long int Cflag;

	f = (FILE *)user;
	
	if (Cflag && ftell(f) > Cflag) {
	  name = (char *) malloc(strlen(WFileName) + 4);
	  strcpy(name, WFileName);
	  swebitoa(cnt, name + strlen(WFileName));
	  cnt++;
	  pcap_dump_close((pcap_dumper_t *) f);
	  f = (FILE *) pcap_dump_open(pd, name); 
	  free(name);
	}

	/* XXX we should check the return status */
	(void)fwrite((char *)h, sizeof(*h), 1, f);
	(void)fwrite((char *)sp, h->caplen, 1, f);
}
