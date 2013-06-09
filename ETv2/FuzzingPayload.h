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
using namespace std;
#include <vector>
#include "Pattern.h"

/*
FuzzingPayload constructs the payload given an input language string that contains
a number of tokens that map to specific fuzzing information such as pattern,
number, format string, etc generation that Icarus understands. The definition of
those tokens is as such:

-------------------------------------------------------------------------------
Tokens:
-------------------------------------------------------------------------------
Token: %(randomb,s,e,d)%
Description:
	Generate random bytes.
Arguments:
	s - Integer specifying the number of characters to begin with.
	e - Integer specifying the final number of characters to test.
	d - A stepping value specifying the number of character increase.
Example:
	%(randomb,100,1000,10)%
	This will generate random bytes starting with 100 bytes, adding 10 bytes at
	each iteration and ending when the number of bytes becomes greater than 1000

Token: %(randoma,s,e,d)%
Description:
	Same as randomb but with ASCII characters.

Token: %(pattern,s,e,d)%
Description:
	The pattern token is replaced with a cyclic generated pattern. It takes 3
	arguments in order to generate the pattern
Arguments:
	s - An integer value signifying the starting number of pattern characters to
		begin with.
	e - An integer value signifying at which number of characters to stop the
		pattern generation.
	d - An integer value signifying how many characters to step at each iteration.
Example:
	%(pattern,100,100000,100)%

Token: %(format,s,e,d,f)%
Description:
	The format token is replaced with a set of format string characters specified
	within the f variable.
Arguments:
	s - An integer value signifying the starting number of format characters to
		begin with.
	e - An integer value signifying at which number of characters to stop the
		format string generation.
	d - An integer value signifying how many characters to step at each iteration.
	f - A list of format string characters to choose from.
Example:
	%(format,100,10000,100,(%d,%s,%x))%

-------------------------------------------------------------------------------
Token Operators
-------------------------------------------------------------------------------
Token: %(and,(TOKEN),(TOKEN),...)%
Description:
	Run multiple tokens at the same location one after another. Note that tokens
	are placed in the same order they appear on the AND token operator.
	The following constraints apply:
		- Only one pattern token can be specified
		- Only one format string token can be specified
Arguments:
	(TOKEN) - A primitive token.
Example:
	%(and,(pattern,10,100,10),(randoma,10,100,10))%

Token: %(or,(TOKEN),(TOKEN),...)%
Description:
	Run one by one the specified tokens. Each token will be processed until finished
	before the next token is processed. No restrictions apply.
Example:
	%(or,(pattern,10,100,10),(pattern,1000,50000,100))%

*/
class LIBEXPORT FuzzingPayload
{
public:
	FuzzingPayload(void);
	~FuzzingPayload(void);

	void fuzzingpayload_set_payload( unsigned char *, int );
	BOOL fuzzingpayload_parse();
	unsigned char * fuzzingpayload_get_payload();

	vector<int> * fuzzingpayload_search( unsigned char * lpucNiddle, 
		int nNiddleSize );
	void fuzzingpayload_set_pattern( Pattern * );
	Pattern * fuzzingpayload_get_pattern( void );
	void fuzzingpayload_clear_pattern();

private:
	BOOL parse_token( unsigned char * lpucToken );
	BOOL bContainsPattern;
	Pattern * lpcPattern;
	unsigned char * lpucPayload;
	int nPayloadLength;
};

