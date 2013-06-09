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

#include "DataEncoder.h"
#include <malloc.h>
#include <string.h>

const char * lpszHexValues = "0123456789ABCDEF";

DataEncoder::DataEncoder(void)
{
}


DataEncoder::~DataEncoder(void)
{
}

BOOL DataEncoder::is_ascii_string( char * str )
{
	do {
		if( !( *str >= 0x32 && *str <= 0x7e ) ) {
			return FALSE;
		}
	} while( *++str );
	return TRUE;
}
BOOL DataEncoder::is_ascii( char * lpszString )
{
	if( *(lpszString+1) == 0 ) return FALSE;
	return TRUE;
}

BOOL DataEncoder::is_unicode( wchar_t * lpuszString )
{
	return FALSE;
}

char * DataEncoder::wchar_to_ascii( wchar_t * lpwczLongString )
{
	int nLength = 0, i;
	char * lpszAsciiString = NULL;


	if( is_ascii( (char*)lpwczLongString ) == TRUE ) 
		return (char *)lpwczLongString;

	wchar_t * lpwczLongStringTemp = lpwczLongString;
	while( *lpwczLongStringTemp++ ) nLength++;

	if( ( lpszAsciiString = (char *) calloc( nLength + 1, sizeof( char ) ) ) 
		== NULL ) {
			return NULL;
	}

	for( i = 0; i < nLength; i++ ) {
		lpszAsciiString[i] = (char)lpwczLongString[i];
	}
	return lpszAsciiString;
}

HexPattern * DataEncoder::ansi_to_hex_pattern( char * lpszInputPattern )
{
	return NULL;
}

char DataEncoder::hex_to_c( unsigned char * lpucHex )
{
	return NULL;
}

char * DataEncoder::htoa( void * lpValue, int nValueSize )
{
	char * lpszAscii = (char *)calloc( ( nValueSize * sizeof( char ) * 2 ) + 1, 
		sizeof( char ) );
	nValueSize *= 2;
	int nByte = 0;
	unsigned char * lpucValue = (unsigned char *)lpValue;
	char * lpszAsciiTmp = lpszAscii;
	for( int i = 0; i < nValueSize; i += 2 ) {
		nByte = *lpucValue++;
		for( int j = 1; j >= 0; --j, nByte /= 16 ) {
			*(lpszAsciiTmp + i + j ) = lpszHexValues[ nByte % 16 ];
		}
	}
	return lpszAscii;
}

char * DataEncoder::ltostr( unsigned long ulValue, char * lpszOutputString )
{
	unsigned long ulInputTmp = ulValue;
	char * lpszOutputStringTmp = lpszOutputString;
	while( ulInputTmp ) {
		*lpszOutputStringTmp = ( ulInputTmp & 0xff000000 ) >> 24;
		lpszOutputStringTmp++;
		ulInputTmp <<= 8;
	}
	*lpszOutputStringTmp = 0;
	return lpszOutputString;
}

unsigned long DataEncoder::lswap_endianess( unsigned long ulValue )
{
	return ( ( ulValue & 0x000000ff ) << 24 ) + 
		( ( ulValue & 0x0000ff00 ) << 8 ) + ( ( ulValue & 0x00ff0000 ) >> 8 ) + 
		( ( ulValue >> 24 ) & 0xff );
}

void * DataEncoder::swap_endianess( void * lvpValue, int nBitsSize )
{
	int nNumberOfBytes = nBitsSize / ( sizeof( char ) * 8 );
	unsigned char * lpucValue = (unsigned char *)lvpValue;
	unsigned char * lpucNewValue = (unsigned char *)calloc( nNumberOfBytes, 
		sizeof( char ) );

	for( int i = 0; i < nNumberOfBytes; i++ ) {
		lpucNewValue[nNumberOfBytes - i - 1] = lpucValue[i];
	}
	return lpucNewValue;
}

char * DataEncoder::atoah( char * lpszHex, int * nResultingLen, BOOL bSwapEndianess )
{
	*nResultingLen = strlen( lpszHex ) / 2;
	char * lpFinalHex = (char *)malloc( (*nResultingLen) + 1 );
	if( lpFinalHex == NULL ) return NULL;
	unsigned char cValue;
	unsigned char cValueFinal = 0;
	BOOL bSecondFlag = FALSE;
	char * lpHexTmp = NULL;
	if( bSwapEndianess ) {
		lpHexTmp = lpFinalHex + (*nResultingLen) - 1;
	}
	else {
		lpHexTmp = lpFinalHex;
	}
	*(lpFinalHex + (*nResultingLen) ) = '\0'; //Not rly needed
	do {
		if( *lpszHex >= '0' || *lpszHex <= '9' ) {
			cValue = *lpszHex - '0';
		}
		else if( *lpszHex >= 'A' || *lpszHex <= 'F' ) {
			cValue = *lpszHex - 'A' + 10;
		}
		else if( *lpszHex >= 'a' || *lpszHex <= 'f' ) {
			cValue = *lpszHex - 'a' + 10;
		}
		else {
			dprintflvl( 1, "Bad Hexadecimal digit given: %c", *lpszHex );
			return NULL;
		}
		cValueFinal = ( cValueFinal << 4 ) + cValue;
		if( bSecondFlag ) {
			if( bSwapEndianess ) {
				*lpHexTmp-- = cValueFinal;
			}
			else {
				*lpHexTmp++ = cValueFinal;
			}
			cValueFinal = 0;
			bSecondFlag = FALSE;
		}
		else {
			bSecondFlag = TRUE;
		}
	} while( *++lpszHex );

	return lpFinalHex;
}