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

#include "icarus_include.h"
//#include <Windows.h>
#pragma warning( push, 0 )
#include <vector>
#pragma warning( pop )
using std::vector;

//Note that the actual wrap size depends on the size of a register in this
//architecture. It is calculated from the actual MAX_WRAP_SIZE + sizeof register
#define MAX_WRAP_SIZE 20280

class LIBEXPORT Pattern
{
public:
	Pattern(void);
	~Pattern(void);
	BOOL pattern_set_characters_set( int nNumberOfSets, ... );
	char * pattern_create( int nPatternLength );
	vector<int> pattern_search( int nPatternLength, char * lpszNiddle, 
		int nNiddleSize );
	BOOL pattern_set_default_sets( void );
	void pattern_release_pattern( char * ); //Just a free() wrapper
	void pattern_release_pattern();
	char * pattern_get_pattern();
	int get_pattern_size();
	char ** lplpszCharSet;
	int nNumberOfSets;
private:
	char * lpszPattern;
	int nPatternSize;
	vector<int> vOffsets;
};

