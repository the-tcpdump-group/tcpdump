/*Copyright (C) 1999 Politecnico di Torino

This file is part of the libpcap library for win32.

The GNU C Library is free software; you can redistribute it and/or
modify it under the terms of the GNU Library General Public License as
published by the Free Software Foundation; either version 2 of the
License, or (at your option) any later version.

The GNU C Library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Library General Public License for more details.

You should have received a copy of the GNU Library General Public
License along with the GNU C Library; see the file COPYING.LIB.  If
not, write to the Free Software Foundation, Inc., 675 Mass Ave,
Cambridge, MA 02139, USA.
*/
#ifndef _WINSOCKAPI_
#define _WINSOCKAPI_ /* Prevent inclusion of winsock.h in windows.h */
#endif /* _WINSOCKAPI_ */
#include <windows.h>
#include <winsock2.h>

extern int progress;
int wsockinit();
void InitP();
void PrintCapBegins (char* program_name, char* device);
extern char* AdapterName1;
#ifndef WIN95
WCHAR* SChar2WChar(char* nome);
#else
BOOLEAN StartPacketDriver(LPTSTR ServiceName);
#endif
