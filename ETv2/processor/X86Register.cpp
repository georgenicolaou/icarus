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

#include "X86Register.h"


const char * lplpszRegisterNames[] = {
	"EAX",
	"ECX",
	"EDX",
	"EBX",
	"ESP",
	"EBP",
	"ESI",
	"EDI",
	"EIP"
};

X86Register::X86Register(void)
{
	this->set_register_size( 32 );
	this->bLittleEndian = TRUE;
	this->vpRegisterValue = NULL;
}


X86Register::~X86Register(void)
{
}

void * X86Register::get_register_value( void )
{
	return this->vpRegisterValue;
}

char * X86Register::get_register_name( void )
{
	return this->lpszRegisterName;
}

unsigned long X86Register::get_register_size( void )
{
	return this->ulRegisterSize;
}

void X86Register::set_register_value( void * vpValue )
{
	this->vpRegisterValue = vpValue;
}

void X86Register::set_register_name( IRegister::_GENERAL_REGISTER_ENUM 
	eRegister )
{
	this->lpszRegisterName = (char *)lplpszRegisterNames[eRegister];
	this->eRegisterEnumValue = eRegister;
}

void X86Register::set_register_size( unsigned long ulSize )
{
	this->ulRegisterSize = ulSize;
}

IRegister::_GENERAL_REGISTER_ENUM X86Register::get_register_type( void )
{
	return this->eRegisterEnumValue;
}

BOOL X86Register::is_little_endian()
{
	return this->bLittleEndian;
}

void * X86Register::get_offset_from_base( unsigned long ulBaseAddress )
{
	if( this->vpRegisterValue == NULL ) return NULL;

	return (void *)( ulBaseAddress - *((unsigned long *)this->vpRegisterValue) );
}