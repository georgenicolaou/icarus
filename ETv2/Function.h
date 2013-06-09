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
#include "IMemory.h"

typedef enum _ARG_TYPE {
	ARG_BYTE,
	ARG_WORD,
	ARG_DWORD,
	ARG_ASCIIPTR,
	ARG_UNICODEPTR
} ARG_TYPE;

typedef enum _CALLING_CONVENTION {
	NONECALL = 0,
	CDECLCALL,
	STDCALL,
	FASTCALL
	//...
} CALLING_CONVENTION;

class LIBEXPORT Function
{
public:
	Function(void);
	~Function(void);
	void set_function_address( void * );
	void set_function_file_address( void * );
	void set_function_virtual_address( void * );
	void set_function_name( char * );
	void set_function_image_name( char * );
	void set_stack_allocation_size( unsigned long );
	void * get_function_address( void );
	void * get_function_file_address( void );
	void * get_function_virtual_address( void );
	char * get_function_name( void );
	char * get_function_image_name();
	unsigned long get_stack_allocation_size( void );
	//Best return a basic block tree
	unsigned char * get_function_contents( IMemory * lpcProcessMemory, 
		int nNumberOfBytes );
	BOOL has_symbolic_information();

	//XXX also good to have the module this function belongs to...
private:
	void * lvpFunctionAddress;
	void * lvpFunctionFileAddress;
	void * lvpFunctionVirtualAddress;
	char * lpszFunctionName;
	char * lpszFunctionImageName;
	unsigned long ulStackAllocationSize;
	unsigned char * lpucFunctionContents;
	int nContentsSize;

	//Tracing Specifics
	ThreadStack * lpobjThreadStack;
};

