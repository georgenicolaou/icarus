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

#include "IRegister.h"

#ifdef ARCH_X86_
#include "X86Register.h"
#endif // ARCH_X86_

IRegister * IRegister::init_get_instance( void )
{
	IRegister * lpsIRegister;
#ifdef ARCH_X86_
	X86Register * sX86Register = new X86Register();
	lpsIRegister = static_cast<IRegister *>(sX86Register);
#endif
	return lpsIRegister;
}

IRegister * IRegister::get_register( vector<IRegister *> * lvpRegisters, 
	_GENERAL_REGISTER_ENUM eRegType )
{
	for( int i = 0; i < (int)lvpRegisters->size(); i++ ) {
		if( lvpRegisters->at(i)->get_register_type() == eRegType ) {
			return lvpRegisters->at(i);
		}
	}
	return NULL;
}

int IRegister::get_register_index( vector<IRegister *> * lpvRegisters, 
	IRegister::_GENERAL_REGISTER_ENUM eRegType )
{
	for( int i = 0; i < (int)lpvRegisters->size(); i++ ) {
		if( lpvRegisters->at(i)->get_register_type() == eRegType ) {
			return i;
		}
	}
	return -1;
}

IRegister::IRegister(void)
{
}


IRegister::~IRegister(void)
{
}
