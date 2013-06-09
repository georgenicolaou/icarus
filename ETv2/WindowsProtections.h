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
#include "IProtections.h"

class LIBEXPORT WindowsProtections : public IProtections
{
public:

	typedef enum _WINDOWS_PROTECTION_FILTER {
		PROTECTION_DEP = 0x00000001, // DEP
		PROTECTION_GS = 0x00000002, // /GS
		PROTECTION_SEH = 0x00000004, // SEH
		PROTECTION_ASLR = 0x00000008, // ASLR
		PROTECTION_ALL = -1
	};
	WindowsProtections(void);
	~WindowsProtections(void);
	virtual BOOL apply_protection_filter( IProtections::_PROTECTION_FILTER 
		eProtectionFilter );
	virtual BOOL filter_module_allowed( ImageHeaderMemory * lpcHeaderMemory );
	virtual BOOL is_protection_0();
	virtual char * get_protection_0_name();
	virtual BOOL is_protection_1();
	virtual char * get_protection_1_name();
	virtual BOOL is_protection_2();
	virtual char * get_protection_2_name();
	virtual BOOL is_protection_3();
	virtual char * get_protection_3_name();
	virtual BOOL is_protection_4();
	virtual char * get_protection_4_name();
	virtual BOOL is_protection_5();
	virtual char * get_protection_5_name();
private:
	_WINDOWS_PROTECTION_FILTER eCurrentFilter;
	BOOL bProtection0Dep;
	char * lpszProtection0Dep;
	BOOL bProtection1Gs;
	char * lpszProtection1Gs;
	BOOL bProtection2Seh;
	char * lpszProtection2Seh;
	BOOL bProtection3Aslr;
	char * lpszProtection3Aslr;
};

