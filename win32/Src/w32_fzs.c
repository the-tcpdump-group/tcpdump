/*
 * Copyright (c) 1999 - 2003
 * NetGroup, Politecnico di Torino (Italy)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Politecnico di Torino nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
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

	if(IsTextUnicode(device,  
		wcslen((short*)device),                // Device always ends with a double \0, so this way to determine its 
												// length should be always valid
		NULL))
	{
		fprintf(stderr, "%s: listening on %ws\n",program_name, device);
	}
	else
	{
		fprintf(stderr, "%s: listening on %s\n",program_name, device);
	}

	fflush(stderr);	
}
