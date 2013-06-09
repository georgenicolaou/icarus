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
#include "Address.h"

using namespace std;
#include <vector>

typedef enum {
	PAYLOAD_RANDOM,
	PAYLOAD_ADDRESS,
	PAYLOAD_ADDRESS_MULTIPLE,
	PAYLOAD_CODE,
	PAYLOAD_BAD,
	PAYLOAD_FIXED
} PAYLOAD_ELEMENT_TYPE;

typedef struct _PAYLOAD_ELEMENT {
	struct _PAYLOAD_ELEMENT * lpsNext;
	struct _PAYLOAD_ELEMENT * lpsPrev;
	PAYLOAD_ELEMENT_TYPE eType;
	int nSize;
	unsigned char * lpucRestrictedChars;
	union {
		unsigned char * lpucContents;
		vector<Address *> * vPayloadAddresses;
	} u;
} PAYLOAD_ELEMENT;

class LIBEXPORT Payload
{
public:
	Payload(void);
	~Payload(void);
	PAYLOAD_ELEMENT * get_head_element( void );
	char * get_payload( void );
	BOOL append_addresses_payload( int nSize, vector<Address *> * vAddresses );
	BOOL append_payload( PAYLOAD_ELEMENT_TYPE eType, int nSize, 
		unsigned char * lpucContents, unsigned char * lpucRestrictedChars );
	BOOL remove_element( PAYLOAD_ELEMENT * );

private:
	void ll_push_back( PAYLOAD_ELEMENT * );
	PAYLOAD_ELEMENT * lpsPayload;
};

