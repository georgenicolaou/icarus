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
#include "Function.h"


Function::Function(void)
{
	this->lpucFunctionContents = NULL;
	this->nContentsSize = 0;
	this->lpszFunctionName = NULL;
	this->lvpFunctionAddress = NULL;
	this->lvpFunctionFileAddress = NULL;
	this->lvpFunctionVirtualAddress = NULL;
	this->ulStackAllocationSize = 0;
	this->lpszFunctionImageName = NULL;
}


Function::~Function(void)
{
}

void Function::set_function_address( void * lvpAddress )
{
	this->lvpFunctionAddress = lvpAddress;
}

void Function::set_function_name( char * lpszName )
{
	this->lpszFunctionName = lpszName;
}

void Function::set_stack_allocation_size( unsigned long ulSize )
{
	this->ulStackAllocationSize = ulSize;
}

void * Function::get_function_address( void )
{
	return this->lvpFunctionAddress;
}

char * Function::get_function_name( void )
{
	return this->lpszFunctionName;
}

unsigned long Function::get_stack_allocation_size( void )
{
	return this->ulStackAllocationSize;
}

void Function::set_function_file_address( void * lvpAddress )
{
	this->lvpFunctionFileAddress = lvpAddress;
}

void * Function::get_function_file_address( void )
{
	return this->lvpFunctionFileAddress;
}

void * Function::get_function_virtual_address( void )
{
	return this->lvpFunctionVirtualAddress;
}

void Function::set_function_virtual_address( void * lpvAddress )
{
	this->lvpFunctionVirtualAddress = lpvAddress;
}

unsigned char * Function::get_function_contents( IMemory * lpcProcessMemory, 
	int nNumberOfBytes )
{
	if( nNumberOfBytes == 0 ) return NULL;

	if( nContentsSize != NULL ) {
		if( nNumberOfBytes == this->nContentsSize ) {
			return this->lpucFunctionContents;
		}
		else {
			free( this->lpucFunctionContents );
			this->lpucFunctionContents = NULL;
		}
	}

	if( ( this->lpucFunctionContents = (unsigned char *) calloc( nNumberOfBytes, 
		sizeof( char ) ) ) == NULL ) {
			PrintError( "Allocation Error" );
			return NULL;
	}

	if( lpcProcessMemory->memory_get_address_contents( 
		(int)lpcProcessMemory->memory_get_process_id(), 
		this->get_function_virtual_address(), (unsigned long)nNumberOfBytes, 
		this->lpucFunctionContents ) == TRUE ) {
			return this->lpucFunctionContents;
	}
	else {
		free( this->lpucFunctionContents );
		this->lpucFunctionContents = NULL;
		return NULL;
	}
}

void Function::set_function_image_name(  char * lpszName )
{
	this->lpszFunctionImageName = lpszName;
}

char * Function::get_function_image_name()
{
	return this->lpszFunctionImageName;
}