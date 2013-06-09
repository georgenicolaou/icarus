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

#include "HexPattern.h"


HexPattern::HexPattern(void)
{
	this->nHexPatternSize = 0;
	this->lpucHexPattern = NULL;
	this->lvpLastFound = NULL;
	this->bContainsOR = FALSE;
	this->nNumberOfPatterns = 0;
}


HexPattern::~HexPattern(void)
{
	free( this->lpucHexPattern );
}

BOOL HexPattern::is_special_character( unsigned char ucChar )
{
	if( ucChar == TOKEN_WILDCHAR || ucChar == TOKEN_MULTIBYTE_START ) {
		return TRUE;
	}
	else {
		return FALSE;
	}
}

BOOL HexPattern::is_special_position( int nPosition )
{
	int i;
	for( i = 0; i < (int)this->vnSpecialPositions.size(); i++ ) {
		if( this->vnSpecialPositions[i] == nPosition ) {
			return TRUE;
		}
	}
	return FALSE;
}

BOOL HexPattern::char_matches( int nPosition, unsigned char ucCharacter)
{
	int nNumberofMultiBytes = 0;
	int nLocationofMultiBytes;
	unsigned char * lpucMultiBytes = NULL;
	if( !this->is_special_position( nPosition ) ) {
		if( this->lpucHexPattern[nPosition] == ucCharacter )
			return TRUE;
		else
			return FALSE;
	}
	else {
		switch( this->lpucHexPattern[nPosition] ) {
			case HexPattern::SPECIAL_WILDCHAR: {
				return TRUE;
			}
			case HexPattern::SPECIAL_MULTIBYTE: {
				this->nSeekPosition++;
				nLocationofMultiBytes = (int)( 
					(unsigned char)this->lpucHexPattern[nPosition + 1] );
				lpucMultiBytes = this->vlpucMultibytes[nLocationofMultiBytes];
				nNumberofMultiBytes = (int)( *lpucMultiBytes );
				lpucMultiBytes++;
				while( nNumberofMultiBytes-- ) {
					if( *lpucMultiBytes == ucCharacter ) {
						return TRUE;
					}
					lpucMultiBytes++;
				}
				return FALSE;
			}
		}
	}
	return FALSE;
}

void * HexPattern::find_next_match( void * lvpHaystack, int nHaystackSize )
{
	unsigned char * lpucHaystack = NULL;

	//Handle multiple OR patterns
	if( this->bContainsOR ) {
		for( int i = 0; i < (int)this->vMultiplePatterns.size(); i++ ) {
			if( ( lpucHaystack = 
				(unsigned char *)this->vMultiplePatterns[i]->find_next_match( 
				lvpHaystack, nHaystackSize ) ) != NULL ) {
					return lpucHaystack;
			}
		}
		return NULL;
	}

	int nHaystackSizeTmp = 0;
	lpucHaystack = (unsigned char *) lvpHaystack;
	unsigned char * lpucHaystackTmp = NULL;
	unsigned char * test;
	int nPatternSize = this->nHexPaternRealSize;
	this->nSeekPosition = 0;

	if( this->nHexPatternSize == 0 || this->lpucHexPattern == NULL ) 
		return NULL;

	//We shouldn not do lpucHaystack + this->nPatternSize since we loose matches
	if( this->lvpLastFound == (void *)lpucHaystack ) lpucHaystack++;
	nHaystackSize -= 1; //Normalize
	while( nHaystackSize ) {
		nHaystackSizeTmp = nHaystackSize;
		lpucHaystackTmp = lpucHaystack;
		this->nSeekPosition = 0;
		test = (unsigned char *) this->lpucHexPattern[this->nSeekPosition];
// 		dprintf( "\n%d && !( %d == %d ) && char_matches( %d (0x%02X %s), "
// 			"0x%02X ) == TRUE", 
// 			nHaystackSize, this->nSeekPosition, nPatternSize,
// 			this->nSeekPosition, this->lpucHexPattern[this->nSeekPosition], 
// 			this->is_special_position( this->nSeekPosition ) ? "*" : "", 
// 			*lpucHaystackTmp );
		while( nHaystackSize && ( this->nSeekPosition - nPatternSize ) != 0
			&& this->char_matches( this->nSeekPosition, *lpucHaystackTmp ) 
			== TRUE ) {
				//if( this->nSeekPosition == nPatternSize ) break;
				this->nSeekPosition++;
				lpucHaystackTmp++;
				test = (unsigned char *) 
					this->lpucHexPattern[this->nSeekPosition];
		}

		if( this->nSeekPosition == nPatternSize ) {
			this->lvpLastFound = (void *) lpucHaystack;
			return lpucHaystack;
		}

		lpucHaystack++;
		nHaystackSize--;
	}

	return NULL;
}

void HexPattern::set_hex_pattern( unsigned char * lpucPattern )
{

}

void HexPattern::add_special_position( int nIndex )
{
	this->vnSpecialPositions.push_back( nIndex );
}

BOOL HexPattern::ascii_to_byte( 
	/*Pointer to a single character*/ unsigned char * lpucReturn, 
	char * lpszAscii )
{
	unsigned char ucReturnTmp = 0;
	int nFlag;
	int i;

	for( i = 0; i <= sizeof( char ); i++ ) {
		if( *lpszAscii == 0 )
			return FALSE;
		else if( *lpszAscii >= '0' && *lpszAscii <= '9' )
			ucReturnTmp += (*lpszAscii - '0' );
		else if( *lpszAscii >= 'a' && *lpszAscii <= 'f' )
			ucReturnTmp += (char)( *lpszAscii - 'a' ) + 10;
		else if( *lpszAscii >= 'A' && *lpszAscii <= 'F' )
			ucReturnTmp += (char)( *lpszAscii - 'A' ) + 10;
		else
			return FALSE;
		if( !( i % 2 ) )
			ucReturnTmp <<= 4;
		lpszAscii++;
	}

	*lpucReturn = ucReturnTmp;
	return TRUE;
}

/*
Example pattern:
AAaaAA0034*[AABBCCDD]55
=>

AA aa AA 00 34 * [AA BB CC DD] 55

Generated values are:
0xAA, 0xAA, 0xAA, 0xAA, 0x34, ANY, 0xAA OR 0xBB OR 0xCC OR 0xDD, 0x55
*/
BOOL HexPattern::parse_pattern( char * lpszInputPattern )
{
	char * lpszInputPatternTmp;
	char * lpszInputPatternTmpAlloc;
	char * lpucHexPatternOrLookup;
	int nWildchars = 0;
	int nMultibyte = 0, nMultibyteBytes = 0;
	int nCounter = 0;
	unsigned char * lpucHexPattern;
	unsigned char * lpucHexPatternTmp;
	unsigned char * lpucMultiBytes;
	unsigned char ucChar;
	//HexPattern * lpcHexPattern = new HexPattern();
	int nConversionFlag;
	BOOL bGotOR = FALSE;

	this->nNumberOfPatterns = 0;
	
	lpszInputPatternTmp = (char *)calloc( strlen(lpszInputPattern) + 1, 
		sizeof(char) ); 

	memcpy( lpszInputPatternTmp, lpszInputPattern, 
		strlen(lpszInputPattern) + 1 );

	lpszInputPatternTmpAlloc = lpszInputPatternTmp;
	//Check for OR
	if( *lpszInputPatternTmp == HexPattern::TOKEN_OR ) {
		PrintError( "OR cannot exist in the beginning of a pattern");
		free( lpszInputPatternTmpAlloc );
		return FALSE;
	}
	lpucHexPatternOrLookup = lpszInputPatternTmp;
	HexPattern * lpORPattern;
	while( *lpszInputPatternTmp ) {
		if( *lpszInputPatternTmp == HexPattern::TOKEN_OR ) {
			this->nNumberOfPatterns++;
			bGotOR = TRUE;
			lpORPattern = new HexPattern();
			*lpszInputPatternTmp = '\0';
			if( lpORPattern->parse_pattern( lpucHexPatternOrLookup ) == FALSE ) {
				PrintError( "Syntax Error");
				free( lpszInputPatternTmpAlloc );
				return FALSE;
			}
			lpucHexPatternOrLookup = lpszInputPatternTmp + 1;
			this->vMultiplePatterns.push_back( lpORPattern );
		}
		lpszInputPatternTmp++;
	}

	
	if( bGotOR ) {
		if( *lpucHexPatternOrLookup ) {
			lpORPattern = new HexPattern();
			if( lpORPattern->parse_pattern( lpucHexPatternOrLookup ) == FALSE ) {
				PrintError( "Syntax Error" );
				free( lpszInputPatternTmpAlloc );
				return FALSE;
			}
			this->nNumberOfPatterns++;
			this->vMultiplePatterns.push_back( lpORPattern );
		}
		this->bContainsOR = TRUE;
		free( lpszInputPatternTmpAlloc );
		return TRUE;
	}
	free( lpszInputPatternTmpAlloc );
	lpszInputPatternTmp = lpszInputPattern;
	this->nNumberOfPatterns = 1;
	//Count wildchars and multichars
	while( *lpszInputPatternTmp ) {
		if( ( *lpszInputPatternTmp >= '0' && *lpszInputPatternTmp <= '9' ) ||
			( *lpszInputPatternTmp >= 'a' && *lpszInputPatternTmp <= 'f' ) || 
			( *lpszInputPatternTmp >= 'A' && *lpszInputPatternTmp <= 'F' ) ) {
				nCounter++;
		}
		else if( *lpszInputPatternTmp == HexPattern::TOKEN_WILDCHAR ) {
			nWildchars++;
			//nCounter++;
			//nCounter += 2;
		}
		else if( *lpszInputPatternTmp == HexPattern::TOKEN_MULTIBYTE_START ) {
			lpszInputPatternTmp++;
			nMultibyteBytes = 0;
			while( *lpszInputPatternTmp++ != HexPattern::TOKEN_MULTIBYTE_END ) {
				if( *lpszInputPatternTmp == 0 ) {
					PrintError( "Syntax Error" );
					return NULL;
				}
				nMultibyteBytes++;
			}
			if( ( nMultibyteBytes % 2 ) != 0 ) {
				PrintError( "Syntax error in multibyte definition" );
				return NULL;
			}
			nMultibyte++;
		}
		else {
			PrintError( "Syntax Error" );
			return NULL;
		}
		if( *lpszInputPatternTmp == 0) break; //XXX fix
		lpszInputPatternTmp++;
	}

	if( ( lpucHexPattern = (unsigned char *) calloc( nWildchars + 
		nMultibyte * 2 + ( nCounter / 2 ), sizeof( char )  ) ) == NULL ) {
			return NULL;
	}
	
	//Multibyte tokens are 2 chars long but we dont care in size
	this->nHexPatternSize = nWildchars + nMultibyte + nCounter / 2;
	this->nHexPaternRealSize = nWildchars + nMultibyte * 2 + nCounter / 2;

	lpucHexPatternTmp = lpucHexPattern;
	nCounter = 0;
	nMultibyteBytes = 0;

	while( *lpszInputPattern ) {
		if( *lpszInputPattern == HexPattern::TOKEN_WILDCHAR ) {
			*lpucHexPatternTmp = (unsigned char) HexPattern::SPECIAL_WILDCHAR;
			this->add_special_position( nCounter );
		}
		else if( *lpszInputPattern == HexPattern::TOKEN_MULTIBYTE_START ) {
			*lpucHexPatternTmp = (unsigned char) HexPattern::SPECIAL_MULTIBYTE;
			this->add_special_position( nCounter++ );
			lpucHexPatternTmp++;
			*lpucHexPatternTmp = this->vlpucMultibytes.size(); //Location
			
			lpszInputPatternTmp = lpszInputPattern;
			lpszInputPatternTmp++;
			nMultibyteBytes = 0;
			while( *lpszInputPatternTmp != HexPattern::TOKEN_MULTIBYTE_END ) {
				nMultibyteBytes++;
				lpszInputPatternTmp++;
			}

			nMultibyteBytes /= 2;

			if( ( lpucMultiBytes = (unsigned char *)malloc( nMultibyteBytes + 1 
				) ) == NULL ) {
					PrintError( "Memory Allocation" );
					return FALSE;
			}

			
			this->vlpucMultibytes.push_back( lpucMultiBytes );
			*lpucMultiBytes = nMultibyteBytes;
			lpucMultiBytes++;
			lpszInputPattern++;
			while( nMultibyteBytes-- ) {
				if( this->ascii_to_byte( &ucChar, lpszInputPattern ) == FALSE )
					return FALSE;
				*lpucMultiBytes = ucChar;
				lpucMultiBytes++;
				lpszInputPattern += 2;
			}
			lpszInputPattern = lpszInputPatternTmp; // Move to *pat = ']'
		}
		else {
			if( ascii_to_byte( &ucChar, lpszInputPattern ) == FALSE ) {
				return FALSE;
			}
			*lpucHexPatternTmp = ucChar;
			lpszInputPattern++;
		}
		
		lpszInputPattern++;
		nCounter++;
		lpucHexPatternTmp++;
	}

	this->lpucHexPattern = lpucHexPattern;
	return TRUE;
}

//XXX This is not the real size since we are adding an extra byte when we
//get a multibyte pattern
int HexPattern::get_pattern_size()
{
	return this->nHexPatternSize;
}