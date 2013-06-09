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

#include "GSBufferSec.h"


GSBufferSec::GSBufferSec(void)
{
}


GSBufferSec::~GSBufferSec(void)
{
}

BOOL GSBufferSec::gsbuffersec_module_has_stack_cookie( 
	ImageHeaderMemory * lpsImageHeader)
{
	PEParser sPeParser;
	PIMAGE_NT_HEADERS lpsNtHeaders;
	PIMAGE_DATA_DIRECTORY lpsImageDataDirEntry;
	IMAGE_LOAD_CONFIG_DIRECTORY sImgLoadConfig;
	void * vpVirtualAddress = NULL;
	WindowsMemory cWindowsMemory;
	int i;
	Address * lpsAddress;
	unsigned long * vpSehHandlerTable;

	if( ( lpsNtHeaders = (PIMAGE_NT_HEADERS)sPeParser.get_header( 
		lpsImageHeader ) ) == NULL ) {
			dprintflvl( 2, "Error getting header" );
			return BOOL_ERROR;
	}

	lpsImageDataDirEntry = 
		&lpsNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];

	if( lpsImageDataDirEntry->VirtualAddress == NULL ) return FALSE;

	if( cWindowsMemory.memory_get_address_contents( 
		lpsImageHeader->get_process_id(), 
		(void *)(lpsImageDataDirEntry->VirtualAddress + 
		lpsNtHeaders->OptionalHeader.ImageBase), 
		sizeof(IMAGE_LOAD_CONFIG_DIRECTORY), &sImgLoadConfig ) == FALSE ) {
			dprintflvl( 2, "Error getting config directory entry" );
			return BOOL_ERROR;
	}

	this->vpSecurityCookie = (void *)sImgLoadConfig.SecurityCookie;

	if( sImgLoadConfig.SecurityCookie ) 
		return TRUE; 
	else 
		return FALSE;
}

void * GSBufferSec::gsbuffersec_module_get_stack_cookie( 
	ImageHeaderMemory * lpsImageHeader)
{
	if( this->gsbuffersec_module_has_stack_cookie( lpsImageHeader ) == TRUE ) {
		return this->vpSecurityCookie;
	}
	else {
		return NULL;
	}
}