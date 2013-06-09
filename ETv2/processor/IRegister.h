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

/*
* Add as many registers as u fancy. But make sure you match these with
* the inherited class ENUM definitions. ( See X86Register )
*/
/*
typedef enum _GENERAL_REGISTER_ENUM {
	REG0 = 0,
	REG1,
	REG2,
	REG3,
	REG_SP, //Stack Pointer
	REG5, //Frame Pointer
	REG6,
	REG_PC //Program Counter
} GENERAL_REGISTER_ENUM;
*/

#pragma once
#include "../icarus_include.h"
using namespace std;
#include <vector>

class LIBEXPORT IRegister
{
public:
	const enum _GENERAL_REGISTER_ENUM {
		REG0 = 0,
		REG1,
		REG2,
		REG3,
		REG_SP, //Stack Pointer
		REG_FP, //Frame Pointer
		REG6,
		REG7,
		REG_PC, //Program Counter
		//...
		IREG_SPECIAL_0 = 0x100,
		IREG_SPECIAL_1,
		IREG_SPECIAL_2,
		IREG_SPECIAL_3,
		IREG_SPECIAL_4,
		IREG_SPECIAL_5,
		IREG_SPECIAL_6,
		IREG_SPECIAL_7,
		//...
	};
	IRegister(void);
	~IRegister(void);
	virtual void * get_register_value( void ) = NULL;
	virtual char * get_register_name( void ) = NULL;
	virtual unsigned long get_register_size( void ) = NULL;
	virtual void set_register_value( void * ) = NULL;
	virtual void set_register_name( IRegister::_GENERAL_REGISTER_ENUM ) 
		= NULL;
	virtual void set_register_size( unsigned long ) = NULL; //In bits
	virtual IRegister::_GENERAL_REGISTER_ENUM get_register_type( void ) = NULL;
	virtual BOOL IRegister::is_little_endian() = NULL;
	virtual void * get_offset_from_base( unsigned long ulBaseAddress ) = NULL;
	static IRegister * init_get_instance( void );
	static IRegister * get_register( vector<IRegister *> * , 
		IRegister::_GENERAL_REGISTER_ENUM  );
	static int get_register_index( vector<IRegister *> *, 
		IRegister::_GENERAL_REGISTER_ENUM );
	
};

#define PUSH_REGISTER( vlpRegs, lpsRegister, eGeneralRegName, lpValue ) {\
	lpsRegister = IRegister::init_get_instance(); \
	lpsRegister->set_register_name( eGeneralRegName ); \
	lpsRegister->set_register_value( lpValue ); \
	vlpRegs->push_back( lpsRegister ); \
}

#define CREATE_REGISTER( lpsRegister, lpsRegName, lpRegValue, nRegSize ) { \
	lpsRegister = IRegister::init_get_instance(); \
	lpsRegister->set_register_name( (IRegister::_GENERAL_REGISTER_ENUM)lpsRegName ); \
	lpsRegister->set_register_value( lpRegValue ); \
	lpsRegister->set_register_size( (unsigned long)nRegSize ); \
}