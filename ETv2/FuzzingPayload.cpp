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

#include "FuzzingPayload.h"
using namespace std::tr1;
#include <regex>
#include <string>
#include <string.h>

FuzzingPayload::FuzzingPayload(void)
{
}


FuzzingPayload::~FuzzingPayload(void)
{
}

void FuzzingPayload::fuzzingpayload_set_payload( unsigned char * lpucPayload, 
	int nPayloadLength )
{
	this->lpucPayload = lpucPayload;
	this->nPayloadLength = nPayloadLength;
}

unsigned char * FuzzingPayload::fuzzingpayload_get_payload()
{
	return this->lpucPayload;
}
vector<int> * FuzzingPayload::fuzzingpayload_search( unsigned char * lpucNiddle, 
	int nNiddleSize )
{
	return NULL;
}

void FuzzingPayload::fuzzingpayload_clear_pattern()
{
	if( this->lpcPattern != NULL ) {
		delete this->lpcPattern;
		this->lpcPattern = NULL;
	}
}

void FuzzingPayload::fuzzingpayload_set_pattern( Pattern * lpcPattern )
{
	if( lpcPattern == NULL ) return;
	this->lpcPattern = lpcPattern;
}

Pattern * FuzzingPayload::fuzzingpayload_get_pattern()
{
	return this->lpcPattern;
}

typedef struct _PAYLOAD_TOKEN {
	char * lpszToken;
	int nTokenLen;
	int nNofArgs;
} PAYLOAD_TOKEN;

PAYLOAD_TOKEN sTokens[] = {
	{ "pattern", 7, 2 },
	{ "randomb", 7, 2 },
	{ "randoma", 7, 2 },
	{ "format", 6, 3 },
	{ "and", 3, -1 },
	{ "or", 2, -1 }
};

BOOL FuzzingPayload::parse_token( unsigned char * lpucToken )
{
	PAYLOAD_TOKEN * lpsToken = NULL;
	for( int i = 0; i < sizeof( sTokens ); i++ ) {
		if( memcmp( lpucToken+1, sTokens[i].lpszToken, sTokens[i].nTokenLen ) == 0 ) {
			lpsToken = &sTokens[i];
			break;
		}
	}

	if( lpsToken == NULL ) {
		dprintflvl( 1, "Unknown Token provided" );
		return FALSE;
	}
	
	char ** lpacArguments = NULL;
	if( ( lpacArguments = (char **)malloc( 
		lpsToken->nNofArgs * sizeof( char * ) ) ) == NULL ) {
			dprintflvl( 1, "Allocation Error" );
			return FALSE;
	}

	int nNested = 0;
	int nCurrentArgument = 0;
	int nConsumedChars = 0;
	lpucToken += lpsToken->nTokenLen;
	unsigned char * lpucStartingPos = lpucToken;

	do {
		if( *lpucToken == '(' ) nNested++;
		else if( *lpucToken == ')' ) nNested--;
		else if( *lpucToken == ',' && nNested == 0 )  {
			*lpucToken = '\0';
			lpacArguments[nCurrentArgument] = (char *)lpucStartingPos;
			nCurrentArgument++;
			lpucStartingPos = lpucToken+1;
		}
		lpucToken++;
	} while( sTokens->nNofArgs < nCurrentArgument );
}

BOOL FuzzingPayload::fuzzingpayload_parse()
{
	unsigned char * lpucPayload; //= this->lpucPayload;
	char ** alpszArguments;
	if( ( lpucPayload = (unsigned char *)malloc( this->nPayloadLength ) ) == 
		NULL ) {
			dprintflvl( 1, "Allocation Error" );
			return FALSE;
	}

	memcpy( lpucPayload, this->lpucPayload, this->nPayloadLength );
	unsigned char * lpucTokenBegin = NULL;
	while( nPayloadLength-- ) {
		if( *lpucPayload == '%' && *(lpucPayload+1) == '(' ) {
			lpucTokenBegin = lpucPayload+1;
// 			lpucPayload += 2;
// 			nPayloadLength -= 1;
// 			for( int i = 0; i < sizeof( sTokens ); i++ ) {
// 				if( sTokens[i].nTokenLen >= nPayloadLength ) {
// 					continue;
// 				}
// 				int nNested;
// 				if( memcmp( lpucPayload, sTokens[i].lpszToken, 
// 					sTokens[i].nTokenLen ) == 0 ) {
// 						if( ( alpszArguments = 
// 							(char **)malloc( sTokens[i].nNofArgs ) ) == NULL ) {
// 								dprintflvl( 1, "Allocation Error" );
// 						}
// 						lpucPayload += sTokens[i].nTokenLen;
// 						nPayloadLength -= sTokens[i].nTokenLen;
// 						unsigned char * lpucTmp;
// 						lpucTmp = lpucPayload;
// 						for( int j = 0; j < sTokens[i].nNofArgs; j++ ) {
// 
// 						}
// 
// 				}
// 			}
		}
		if( *lpucPayload == ')' && *(lpucPayload+1) == '%' ) {
			this->parse_token( lpucTokenBegin );
		}
		lpucPayload++;
	}
	return TRUE;
}