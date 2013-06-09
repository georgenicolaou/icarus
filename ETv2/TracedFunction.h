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
#include "ThreadStack.h"
#include "processor\IRegister.h"
#include "IMemory.h"
#include "Function.h"

typedef enum _ARGUMENT_TYPE {
	VALUE,
	STRING_ASCII,
	STRING_UNICODE
} ARGUMENT_TYPE;

/*
typedef enum _CALLING_CONVENTION {
	CALL_NONE = 0,
	CALL_CDECL,
	CALL_STDCALL,
	CALL_FASTCALL,
	//...
} CALLING_CONVENTION;
*/
class TracedFunction
{
public:
	TracedFunction(void);
	~TracedFunction(void);

	/*
	** nNumberofArgs is optional and can be NULL
	*/
	BOOL setup_function( ThreadStack * lpobjThreadStack, 
		vector<IRegister *> * lpvCurrentRegisters, IMemory * lpobjMemory, 
		int nNumberOfArgs );

	ARGUMENT_TYPE get_argument_n_type( int nArgumentNumber );
	void * get_argument_n_value( int nArgumentNumber );
	void set_calling_convention( CALLING_CONVENTION );
	BOOL has_symbolic_information();
	//XXX Symbols this
	char * get_function_name();
private:
	ARGUMENT_TYPE guess_argument_type( void * lpvArgument );

	ThreadStack * lpobjThreadStack;
	vector<void *> vArguments;
	vector<ARGUMENT_TYPE> vArgumentTypes;
	BOOL bHasSymbols;
	CALLING_CONVENTION eCallingConvention;
	IRegister * lpobjSPRegister;
	IRegister * lpobjFPRegister;
	IRegister * lpobjPCRegister;
	//If required for stack arguments
	unsigned char * lpucArgumentsPtr;
	unsigned char * lpucFramePtr;

	char * lpszLocalModule;

	void * lpvReturnAddress;
	char * lpszReturnModule;
};

