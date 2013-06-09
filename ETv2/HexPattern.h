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
using namespace std;
#include <vector>
#include "icarus_include.h"
class LIBEXPORT HexPattern
{
public:
	static const char TOKEN_WILDCHAR = '*';
	static const char TOKEN_MULTIBYTE_START = '[';
	static const char TOKEN_MULTIBYTE_END = ']';
	static const char TOKEN_OR = '|'; //XXX not implemented
	
	const enum _SPECIAL_TYPE {
		SPECIAL_WILDCHAR, //Wildchar special character to match any bytes
		SPECIAL_MULTIBYTE //Match multiple bytes
	};

	HexPattern(void);
	~HexPattern(void);
	BOOL is_special_position( int nPosition );
	BOOL is_special_character( unsigned char ucChar );
	BOOL char_matches( int nPosition, unsigned char ucCharacter);
	void set_hex_pattern( unsigned char * lpucPattern );
	BOOL parse_pattern( char * lpszInputPattern );
	void * find_next_match( void * lvpHaystack, int nHaystackSize );
	int get_pattern_size();
	/*
	* lpucMultibytes can be NULL
	*/
	void add_special_position( int nIndex );
private:
	BOOL ascii_to_byte( unsigned char * ucReturn, char * lpszAscii );
	int nHexPaternRealSize;
	int nHexPatternSize;
	int nSeekPosition;
	unsigned char * lpucHexPattern;
	vector<int> vnSpecialPositions;
	vector<unsigned char *> vlpucMultibytes;
	void * lvpLastFound;
	vector<HexPattern *> vMultiplePatterns;
	BOOL bContainsOR;
	int nNumberOfPatterns;
};

