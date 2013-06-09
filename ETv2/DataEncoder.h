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
#include "icarus_include.h"
#include "HexPattern.h"

class LIBEXPORT DataEncoder
{
public:
	DataEncoder(void);
	~DataEncoder(void);

	static char * wchar_to_ascii( wchar_t * lpwcLongString );
	static HexPattern * ansi_to_hex_pattern( char * lpszInputPattern );
	static BOOL is_ascii( char * lpszString );
	static BOOL is_unicode( wchar_t * lpuszString );
	static char hex_to_c( unsigned char * lpucHex );
	static char * ltostr( unsigned long ulValue, char * lpszOutputString );
	static unsigned long lswap_endianess( unsigned long ulValue );
	static void * swap_endianess( void * lvpValue, int nBitsSize );
	static char * DataEncoder::htoa( void * lpValue, int nValueSize );
	static char * DataEncoder::atoah( char * lpszHex, int * nResultingLen, 
		BOOL bSwapEndianess );
	static BOOL DataEncoder::is_ascii_string( char * str );
};

