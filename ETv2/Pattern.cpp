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

#include "Pattern.h"
#include "IMemory.h"
using namespace std;
#pragma warning( push, 0 )
#include <string>
#include <iostream>
#pragma warning( pop )

char SetAlphaCapital[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
char SetAlphaLower[] = "abcdefghijklmnopqrstuvwxyz";
char SetNumeric[] = "0123456789";
char SetSymbol[] = "";

Pattern::Pattern(void)
{
	this->lplpszCharSet = NULL;
	this->nNumberOfSets = 0;
	this->lpszPattern = NULL;
	this->nPatternSize = 0;

}


Pattern::~Pattern(void)
{
	free( this->lplpszCharSet );
	this->pattern_release_pattern();
}


BOOL Pattern::pattern_set_characters_set( int nNumberOfSets, ... )
{
	va_list lpVaList;
	char * lpszTmpVal;
	int i;


	if( ( this->lplpszCharSet = (char **)malloc( nNumberOfSets * 
		sizeof( char * ) ) ) == NULL ) {
			return FALSE;
	}

	va_start( lpVaList, nNumberOfSets );
	for( i = 0; i < nNumberOfSets; i++ ) {
		lpszTmpVal = va_arg( lpVaList, char * );
		this->lplpszCharSet[i] = lpszTmpVal;
	}

	this->nNumberOfSets = nNumberOfSets;
	return TRUE;
}

BOOL Pattern::pattern_set_default_sets( void )
{
	return this->pattern_set_characters_set( 3, SetAlphaCapital, SetAlphaLower,
		SetNumeric );
}

char * Pattern::pattern_create( int nPatternLength )
{
	char ** tmpSets;
	char * lpszPatternTmp;
	int i, j;

	if( this->lpszPattern != NULL && nPatternLength == this->nPatternSize ) {
		return this->lpszPattern;
	}

	if( this->lpszPattern != NULL ) {
		free( this->lpszPattern );
	}

	if( ( lpszPatternTmp = (char *)malloc( nPatternLength + 1 ) ) 
		== NULL ) {
			return NULL;
	}

	this->nPatternSize = nPatternLength;
	this->lpszPattern = lpszPatternTmp;

	if( ( tmpSets = (char **)malloc( this->nNumberOfSets * sizeof(char *) ) )
		== NULL ) {
			return NULL;
	}

	for( i = 0; i < this->nNumberOfSets; i++ ) {
		tmpSets[i] = this->lplpszCharSet[i];
	}

	while( nPatternLength > 0 ) {
		for( i = 0; i < this->nNumberOfSets; i++ ) {
			*lpszPatternTmp = *tmpSets[i];
			nPatternLength--;
			if( !nPatternLength ) {
				break;
			}
			lpszPatternTmp++;

			if( i == this->nNumberOfSets - 1 )
				tmpSets[i]++;

			if( *tmpSets[i] == '\0' ) {
				for( j = (this->nNumberOfSets - 1); j >= 0; j-- ) {
					if( *tmpSets[j] == '\0' ) {
						if( j > 0 ) tmpSets[j-1]++;
						tmpSets[j] = this->lplpszCharSet[j];
					}
				}
			}
		}
	}

	*(lpszPatternTmp+1) = '\0';
	free( tmpSets );
	return this->lpszPattern;
}

char * Pattern::pattern_get_pattern()
{
	return this->lpszPattern;
}

void Pattern::pattern_release_pattern( char * lpszPattern )
{
	free( lpszPattern );
}

void Pattern::pattern_release_pattern()
{
	if( this->lpszPattern != NULL ) {
		free( this->lpszPattern );
		this->lpszPattern = NULL;
	}		
}

vector<int> Pattern::pattern_search( int nPatternLength, char * lpszNiddle,
	int nNiddleSize )
{
	unsigned char * lpszPatternLocation;
	int nPatternSize, nPatternOffset;

	this->vOffsets.clear();
	if( this->pattern_create( nPatternLength ) != NULL ) {
		lpszPatternLocation = (unsigned char *)this->lpszPattern;
		nPatternSize = this->nPatternSize;

		while( lpszPatternLocation && nPatternSize > 0) {
			lpszPatternLocation = IMemory::memory_ustrstr( 
				(unsigned char *)lpszPatternLocation, nPatternSize, 
				(unsigned char *)lpszNiddle, nNiddleSize );
			if( lpszPatternLocation ) {
				nPatternOffset = lpszPatternLocation - 
					(unsigned char *)this->lpszPattern;
				lpszPatternLocation++;
				nPatternSize -= nPatternOffset;
				this->vOffsets.push_back( nPatternOffset );
			}
		}

	}
	return this->vOffsets;
}

int Pattern::get_pattern_size()
{
	return this->nPatternSize;
}