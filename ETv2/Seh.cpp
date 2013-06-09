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

#include "Seh.h"
#include "WinError.h"
#include "PEParser.h"

Seh::Seh(void)
{
}


Seh::~Seh(void)
{
}

BOOL seh_get_thread_seh_chain( vector<Address *> * lpvSehList, int nProcessId, 
	int nThreadId )
{
	void * vpRemoteThreadTebAddr;
	WindowsMemory cWindowsMemory;
	void * hThread = NULL;
	TEB sTeb = {0};
	EXCEPTION_REGISTRATION_RECORD sExceptionRegRecord;
	void * vpReadAddress = NULL;

	if( ( hThread = OpenThread( THREAD_QUERY_INFORMATION, FALSE, 
		nThreadId ) ) == NULL ) {
			WinError::winerror_print_last_error( __FUNCTION__ );
			return FALSE;
	}

	if( ( vpRemoteThreadTebAddr = 
		cWindowsMemory.windowsmemory_get_remote_thread_teb( hThread ) ) 
		== NULL ) {
			WinError::winerror_print_error( "Unable to get Thread's TEB" );
			return FALSE;
	}

	if( cWindowsMemory.memory_get_address_contents( nProcessId, 
		vpRemoteThreadTebAddr, sizeof(TEB), &sTeb ) == FALSE ) {
			WinError::winerror_print_error( "Error getting contents" );
			return FALSE;
	}

	vpReadAddress = sTeb.Tib.ExceptionList;

	do {
		if( cWindowsMemory.memory_get_address_contents( nProcessId, vpReadAddress, 
			sizeof( EXCEPTION_REGISTRATION_RECORD ), &sExceptionRegRecord ) 
			== FALSE ) {
				WinError::winerror_print_error( "Error getting ExceptionList" );
				return FALSE;
		}
	
		Address * lpsAddress = new Address();
		lpsAddress->set_address( sExceptionRegRecord.Handler );
		lpvSehList->push_back( lpsAddress );
		if( !( cWindowsMemory.memory_is_valid_read_address( nProcessId, 
			sExceptionRegRecord.Next ) && 
			cWindowsMemory.memory_is_valid_code_address( nProcessId,  
			sExceptionRegRecord.Handler ) ) ) {
			dprintflvl( 1, "Possibly corrupted SEH chain, terminating SEH walk" );
			break;
		}
	} while( (unsigned long)sExceptionRegRecord.Next != (unsigned long)-1 );

	return TRUE;	
}

BOOL Seh::seh_get_module_registered_exception_handlers( 
	vector<Address *> lpvSeh, ImageHeaderMemory * lpsImageHeader )
{
	PEParser sPeParser;
	PIMAGE_NT_HEADERS lpsNtHeaders;
	PIMAGE_DATA_DIRECTORY lpsImageDataDirEntry;
	IMAGE_LOAD_CONFIG_DIRECTORY sImgLoadConfig;
	WindowsMemory cWindowsMemory;
	int i;
	Address * lpsAddress;
	unsigned long * vpSehHandlerTable;

	if( ( lpsNtHeaders = (PIMAGE_NT_HEADERS)sPeParser.get_header( 
		lpsImageHeader ) ) == NULL ) {
			dprintflvl( 2, "Error getting header" );
			return (SEH_TYPE)NULL;
	}

	if( lpsNtHeaders->OptionalHeader.DllCharacteristics & 
		IMAGE_DLLCHARACTERISTICS_NO_SEH ) {
			dprintflvl( 3, "NO SEH - Module %s", 
				lpsImageHeader->get_image_name_ascii() );
			return SEH_OFF; 
	}

	lpsImageDataDirEntry = 
		&lpsNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];

	if( cWindowsMemory.memory_get_address_contents( 
		lpsImageHeader->get_process_id(), 
		(void *)lpsImageDataDirEntry->VirtualAddress, 
		sizeof(IMAGE_LOAD_CONFIG_DIRECTORY), &sImgLoadConfig ) == FALSE ) {
			dprintflvl( 2, "Error getting config directory entry" );
			return FALSE;
	}

	if( ( vpSehHandlerTable = (unsigned long *)calloc( 
		sImgLoadConfig.SEHandlerCount, sizeof( unsigned long ) ) ) == NULL ) {
			return FALSE;
	}

	if( cWindowsMemory.memory_get_address_contents( 
		lpsImageHeader->get_process_id(), (void *)sImgLoadConfig.SEHandlerTable, 
		sImgLoadConfig.SEHandlerCount * sizeof( unsigned long ), 
		vpSehHandlerTable ) == FALSE )  {
			dprintflvl( 2, "Error reading seh handler table" );
			return FALSE;
	}

	for( i = 0; i < (int)sImgLoadConfig.SEHandlerCount; i++ ) {
		lpsAddress = new Address();
		lpsAddress->set_address( (void *)vpSehHandlerTable[i] );
		lpvSeh.push_back( lpsAddress );
	}

	free( vpSehHandlerTable );
	return TRUE;
}

SEH_TYPE Seh::seh_get_seh_type( ImageHeaderMemory * lpsImageHeader )
{
	PEParser sPeParser;
	PIMAGE_NT_HEADERS lpsNtHeaders;
	PIMAGE_DATA_DIRECTORY lpsImageDataDirEntry;

	if( ( lpsNtHeaders = (PIMAGE_NT_HEADERS)sPeParser.get_header( 
		lpsImageHeader ) ) == NULL ) {
			dprintflvl( 2, "Error getting header" );
			return (SEH_TYPE)NULL;
	}

	if( lpsNtHeaders->OptionalHeader.DllCharacteristics & 
		IMAGE_DLLCHARACTERISTICS_NO_SEH ) {
			dprintflvl( 3, "NO SEH - Module %s", 
				lpsImageHeader->get_image_name_ascii() );
			return SEH_OFF; 
	}

	lpsImageDataDirEntry = 
		&lpsNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];

	if( lpsImageDataDirEntry->VirtualAddress == NULL ) {
		dprintflvl( 3, "SafeSEH OFF - Module %s", 
			lpsImageHeader->get_image_name_ascii() );
		return SEH_ON;
	} else {
		return SEH_SAFESEH;
	}
}