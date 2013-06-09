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
#include "IRegister.h"

class X86Register : public IRegister
{
public:
	const enum _X86_REGISTER_ENUM {
		ECX = 0,
		EAX,
		EDX,
		EBX,
		ESP,
		EBP,
		ESI,
		EDI,
		EIP,

		AH,
		CH,
		DH,
		BH,
		SPH,

		//...
		IREG_ES = 0x100,
		IREG_CS,
		IREG_SS,
		IREG_DS,
		IREG_FS,
		IREG_GS,

		IREG_CR0,
		IREG_CR1,
		IREG_CR2,
		IREG_CR3,
		IREG_CR4,
		IREG_CR5,
		IREG_CR6,
		IREG_CR7,

		IREG_DR0,
		IREG_DR1,
		IREG_DR2,
		IREG_DR3,
		IREG_DR4,
		IREG_DR5,
		IREG_DR6,
		IREG_DR7,



	};

	X86Register(void);
	~X86Register(void);

	virtual void * get_register_value( void );
	virtual char * get_register_name( void );
	virtual unsigned long get_register_size( void );
	virtual void set_register_value( void * );
	virtual void set_register_name( IRegister::_GENERAL_REGISTER_ENUM );
	virtual void set_register_size( unsigned long );
	virtual void * get_offset_from_base( unsigned long ulBaseAddress );
	virtual IRegister::_GENERAL_REGISTER_ENUM get_register_type( void );
	virtual BOOL is_little_endian();
private:
	void * vpRegisterValue;
	char * lpszRegisterName;
	unsigned long ulRegisterSize;
	IRegister::_GENERAL_REGISTER_ENUM eRegisterEnumValue;
	BOOL bLittleEndian;
};

