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
#include "ImageHeaderMemory.h"
class LIBEXPORT IProtections
{
public:
	typedef enum _PROTECTION_FILTER {
		PROTECTION_0 = 0x00000001, // DEP
		PROTECTION_1 = 0x00000002, // /GS
		PROTECTION_2 = 0x00000004, // SEH
		PROTECTION_ASLR = 0x00000008, // ASLR
		PROTECTION_4 = 0x00000016,
		PROTECTION_5 = 0x00000032,
		PROTECTION_ALL = -1
	} PROTECTION_FILTER;
	IProtections(void);
	~IProtections(void);
	static IProtections * init_get_instance( void );
	//XXX define operator | for adding protections together so no warnings pop up
	virtual BOOL apply_protection_filter( IProtections::_PROTECTION_FILTER 
		eProtectionFilter ) = NULL;
	//Check if module is allowed based on the current protection filter
	virtual BOOL filter_module_allowed( ImageHeaderMemory * lpcHeaderMemory ) 
		= NULL;
	
	virtual BOOL is_protection_0() = NULL;
	virtual char * get_protection_0_name() = NULL;
	virtual BOOL is_protection_1() = NULL;
	virtual char * get_protection_1_name() = NULL;
	virtual BOOL is_protection_2() = NULL;
	virtual char * get_protection_2_name() = NULL;
	virtual BOOL is_protection_3() = NULL;
	virtual char * get_protection_3_name() = NULL;
	virtual BOOL is_protection_4() = NULL;
	virtual char * get_protection_4_name() = NULL;
	virtual BOOL is_protection_5() = NULL;
	virtual char * get_protection_5_name() = NULL;
};

