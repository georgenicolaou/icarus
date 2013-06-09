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

#include "Payload.h"
#include <stdlib.h>



Payload::Payload(void)
{
	this->lpsPayload = NULL;
}


Payload::~Payload(void)
{
}


char * Payload::get_payload( void )
{
	return NULL;
}

BOOL Payload::append_addresses_payload( int nSize, vector<Address *> * vAddresses )
{

	PAYLOAD_ELEMENT * lpsPayloadElement = NULL;

	if( ( lpsPayloadElement = (PAYLOAD_ELEMENT *)calloc( 1, 
		sizeof( PAYLOAD_ELEMENT ) ) ) == NULL ) {
			dprintflvl( 1, "Unable to allocate space for payload" );
			return FALSE;
	}

	lpsPayloadElement->nSize = nSize;
	lpsPayloadElement->eType = PAYLOAD_ADDRESS_MULTIPLE;
	lpsPayloadElement->u.vPayloadAddresses = vAddresses;

	ll_push_back( lpsPayloadElement );
}

BOOL Payload::append_payload( PAYLOAD_ELEMENT_TYPE eType, int nSize, 
	unsigned char * lpucContents, unsigned char * lpucRestrictedChars )
{
	PAYLOAD_ELEMENT * lpsPayloadElement = NULL;
	
	if( ( lpsPayloadElement = (PAYLOAD_ELEMENT *)calloc( 1, 
		sizeof( PAYLOAD_ELEMENT ) ) ) == NULL ) {
			dprintflvl( 1, "Unable to allocate space for payload" );
			return FALSE;
	}

	lpsPayloadElement->nSize = nSize;
	lpsPayloadElement->eType = eType;
	//if( eType == PAYLOAD_ADDRESS_MULTIPLE ) {
		//lpsPayloadElement->u.lpucContentsArray = (unsigned char **)lpucContents;
	//}
	//else {
		lpsPayloadElement->u.lpucContents = lpucContents;
	//}
	lpsPayloadElement->lpucRestrictedChars = lpucRestrictedChars;
	ll_push_back( lpsPayloadElement );
}

void Payload::ll_push_back(	PAYLOAD_ELEMENT * lpsElement )
{
	if( this->lpsPayload == NULL ) {
		this->lpsPayload = lpsElement;
		this->lpsPayload->lpsNext = NULL;
		this->lpsPayload->lpsPrev = NULL;
		return;
	}

	PAYLOAD_ELEMENT * lpsCurrElement = this->lpsPayload;
	while( lpsCurrElement->lpsNext != NULL ) {
		lpsCurrElement = lpsCurrElement->lpsNext;
	}
	lpsCurrElement->lpsNext = lpsElement;
	lpsElement->lpsPrev = lpsCurrElement;
	return;
}


PAYLOAD_ELEMENT * Payload::get_head_element(void)
{
	return this->lpsPayload;
}

BOOL Payload::remove_element( PAYLOAD_ELEMENT * lpsRemoveElement )
{
	if( lpsRemoveElement == NULL ) return FALSE;

	PAYLOAD_ELEMENT * lpsCurrElement = this->lpsPayload;
	
	if( lpsCurrElement == NULL ) return FALSE;

	do {
		if( lpsCurrElement == lpsRemoveElement ) {
			if( lpsCurrElement->lpsPrev == NULL ) {
				if( lpsCurrElement->lpsNext != NULL ) {
					this->lpsPayload = lpsCurrElement->lpsNext;
				}
				else {
					this->lpsPayload = NULL;
				}
				free( lpsCurrElement );
				return TRUE;
			}
			lpsCurrElement->lpsPrev->lpsNext = lpsCurrElement->lpsNext;
			if( lpsCurrElement->lpsNext != NULL ) {
				lpsCurrElement->lpsNext->lpsPrev = lpsCurrElement->lpsPrev;
			}
			free( lpsCurrElement );
			return TRUE;
		}
		lpsCurrElement = lpsCurrElement->lpsNext;
	} while( lpsCurrElement != NULL );

	return FALSE;
}