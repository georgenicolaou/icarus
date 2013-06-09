/*
Copyright (C) 2013  George Nicolaou <george[at]preaver.[dot]com>
Copyright (C) 2013  Glafkos Charalambous <glafkos[at]gmail.[dot]com>

This file is part of Exploitation Toolkit Icarus (ETI) Library.

Exploitation Toolkit Icarus (ETI) Library is free software: you can redistribute 
it and/or modify it under the terms of the GNU General Public License as 
published by the Free Software Foundation, either version 3 of the License, 
or (at your option) any later version.

Exploitation Toolkit Icarus (ETI) Library is distributed in the hope that it 
will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Exploitation Toolkit Icarus (ETI) Library.  
If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once
/* 
* Here lies the definition for the processor architecture. Defining the
* architecture should be a gcc command line parameter
*/
//#define _AMD64_
#define _X86_
#define OS_WIN_

#ifdef _AMD64_
#define ARCH_X64_
#else
#ifdef _X86_
#define ARCH_X86_
#endif
#endif

#ifdef ARCH_X64_
#define HEXPRINT "%016X"
#else
#define HEXPRINT "%08X"
#endif

#pragma warning( push, 0 )
#include <stdio.h>
#include <stdarg.h>
#pragma warning( pop )
#define _break __asm int 3;

typedef int		BOOL;
typedef unsigned long DWORD;

#ifndef _NATIVE_WCHAR_T_DEFINED
typedef unsigned short wchar_t;
#endif

#define NULL    0
#define uchar	unsigned char
#define FALSE	0
#define TRUE	1
#define MORE	-1 //More stuff but not enough memory
#define DEBUG_LEVEL 2
#define BOOL_ERROR -1

#define FlagCheck( var, flag ) \
	{ \
	if( var & flag ) { \
		return TRUE; \
	} \
	else { \
		return FALSE; \
	} \
}

#define PrintError( fmt, ... )  \
	{ \
	printf( "%s:%u:" fmt "\n", __FUNCTION__, __LINE__, ##__VA_ARGS__ );   \
}	

#define PrintErrorNaked( fmt, ... ) \
	{ \
	printf( fmt "\n", ##__VA_ARGS__ ); \
}

#define dprintf( fmt, ... )  \
	{ \
	printf( "%s:%u:" fmt "\n", __FUNCTION__, __LINE__, ##__VA_ARGS__ );   \
}	

#define dprintflvl( lvl, fmt, ... )  \
	{ \
	if( lvl <= DEBUG_LEVEL ) \
		printf( "[%d]%s:%u:" fmt "\n", lvl, __FUNCTION__, __LINE__, \
			##__VA_ARGS__ );   \
}	

#define ICARUSVERSION "0.0.1"
#define MYARRAYSIZE( x ) ( sizeof( x ) / sizeof( *( x ) ) )

#define LIBEXPORT __declspec( dllexport )