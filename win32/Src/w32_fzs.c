/*
 * Copyright (c) 1999, 2000
 *	Politecnico di Torino.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) all advertising materials mentioning
 * features or use of this software display the following acknowledgement:
 * ``This product includes software developed by the Politecnico
 * di Torino, and its contributors.'' Neither the name of
 * the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#include <w32_fzs.h>
#include <tcpdump-stdinc.h>
#include <signal.h>

static WCHAR *TmpName=NULL;

extern char* AdapterName1;


WCHAR* SChar2WChar(char* nome)
{
	int i;
	TmpName=(WCHAR*) malloc ((strlen(nome)+2)*sizeof(WCHAR));
	for (i=0;i<(signed)strlen(nome)+1; i++)
		TmpName[i]=nome[i];
	TmpName[i]=0;
	return TmpName;
}

void* GetAdapterFromList(void* device,int index)
{
	DWORD dwVersion;
	DWORD dwWindowsMajorVersion;
	char* Adapter95;
	WCHAR* Adapter;
	int i;

	dwVersion=GetVersion();
	dwWindowsMajorVersion =  (DWORD)(LOBYTE(LOWORD(dwVersion)));
	if (dwVersion >= 0x80000000 && dwWindowsMajorVersion >= 4)			// Windows '95
	{
		Adapter95=device;
		for(i=0;i<index-1;i++){
			while(*Adapter95++!=0);
			if(*Adapter95==0)return NULL; 
		}
		return	Adapter95;
	}
	else{
		Adapter=(WCHAR*)device;
		for(i=0;i<index-1;i++){
			while(*Adapter++!=0);
			if(*Adapter==0)return NULL; 
		}
		return	Adapter;
	}
	
}


void PrintCapBegins (char* program_name, char* device)
{
	DWORD dwVersion;
	DWORD dwWindowsMajorVersion;
	int ii,jj;
	char dev[256];

	dwVersion=GetVersion();
	dwWindowsMajorVersion =  (DWORD)(LOBYTE(LOWORD(dwVersion)));
	if (dwVersion >= 0x80000000 && dwWindowsMajorVersion >= 4)			// Windows '95
	{
		for(ii=0,jj=0;ii<128;ii++) 
				if (device[ii]=='\0') break; 
				else if (device[ii]!='\0') {dev[jj]=device[ii];jj++;}
		dev[jj]='\0';
		(void)fprintf(stderr, "%s: listening on %s\n",program_name, dev);
		(void)fflush(stderr);
	}

	else
	{
		for(ii=0,jj=0;ii<128;ii++) 
				if (device[ii]=='\0'&& device[ii+1]=='\0') break; 
				else if (device[ii]!='\0') {dev[jj]=device[ii];jj++;}
		dev[jj++]='\0';
		dev[jj]='\0';
		fwrite(program_name,strlen(program_name),1,stderr);
		fwrite(": listening on ",15,1,stderr);
		fwrite(dev,strlen(dev),1,stderr); 
		fwrite("\n",1,1,stderr); 
		(void)fflush(stderr);
	}
}
