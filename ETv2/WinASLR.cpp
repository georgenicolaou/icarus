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

#include "WinASLR.h"
#include "PEParser.h"


WinASLR::WinASLR(void)
{
	this->lpsNtHeaders = NULL;
}


WinASLR::~WinASLR(void)
{
}

BOOL WinASLR::winaslr_is_module_aslr_enabled( 
	ImageHeaderMemory * lpsImageHeader )
{
	PIMAGE_NT_HEADERS lpsNtHeaders = NULL;
	PEParser sPeParser;

	if( this->lpsNtHeaders == NULL ) {
		if( ( lpsNtHeaders = (PIMAGE_NT_HEADERS)sPeParser.get_header( 
			lpsImageHeader ) ) == NULL ) {
				dprintflvl( 2, "Error getting header" );
				return -1;
		}
		this->lpsNtHeaders = lpsNtHeaders;
	}

	if( lpsNtHeaders->OptionalHeader.DllCharacteristics & 
		IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE ) {
			return TRUE;
	}
	else {
		return FALSE;
	}
}

BOOL WinASLR::winaslr_is_module_rebased( ImageHeaderMemory * lpsImageHeader )
{
	PIMAGE_NT_HEADERS lpsNtHeaders = NULL;
	PEParser sPeParser;

	if( sPeParser.read_from_file( lpsImageHeader->get_image_fullname_ascii() ) 
		== FALSE ) {
			return -1;
	}

	lpsNtHeaders = (PIMAGE_NT_HEADERS)sPeParser.get_header();
	
	if( (void *)lpsNtHeaders->OptionalHeader.ImageBase != 
		lpsImageHeader->get_baseaddress() ) {
			return TRUE;
	}
	else {
		return FALSE;
	}
}