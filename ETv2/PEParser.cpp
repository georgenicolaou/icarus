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

#include "PEParser.h"
#include "icarus_include.h"
#include <WinNT.h>
#include "WinError.h"
#include "DataEncoder.h"
PEParser::PEParser(void)
{
	this->pImageDosHeader = NULL;
	this->pImageNtHeaders = NULL;
	this->lpcImageHeader = NULL;
	this->lpFileBuffer = NULL;
}


PEParser::~PEParser(void)
{
}

void * PEParser::get_header( ImageHeaderMemory * cHeaderMemory  )
{
	PIMAGE_NT_HEADERS lpNtHeaders = NULL;
	PIMAGE_DOS_HEADER lpDosHeader = NULL;
	WindowsMemory cMemory;
	unsigned char * lpucPageContents = NULL;

	if( cHeaderMemory == NULL ) return NULL;

	if( this->lpcImageHeader != NULL ) {
		if( cHeaderMemory->get_baseaddress() != 
			this->lpcImageHeader->get_baseaddress() ) {
				this->pImageDosHeader = NULL;
				this->pImageNtHeaders = NULL;
				this->lpcImageHeader = cHeaderMemory;
		}
		else if( this->pImageNtHeaders != NULL ) {
			return this->pImageNtHeaders;
		}
	}
	if( this->pImageNtHeaders != NULL ) return this->pImageNtHeaders;
	if( cHeaderMemory->allocate_buffer_for_page() != TRUE ) {
		return NULL;
	}

	if( cMemory.memory_get_memory_page_contents( cHeaderMemory->get_process_id(), 
		cHeaderMemory, cHeaderMemory->get_memory_page_contents_buffer(), 
		cHeaderMemory->get_page_size() ) == FALSE ) {
			return NULL;
	}

	lpucPageContents = cHeaderMemory->get_memory_page_contents_buffer();
	lpDosHeader = (PIMAGE_DOS_HEADER)lpucPageContents;

	lpNtHeaders = (PIMAGE_NT_HEADERS)( lpucPageContents + 
		lpDosHeader->e_lfanew );

	this->pImageDosHeader = lpDosHeader;
	this->pImageNtHeaders = lpNtHeaders;
	this->lpcImageHeader = cHeaderMemory;
	return lpNtHeaders;
}



BOOL PEParser::get_sections( IMemory * lpcProcessMemory,
	ImageHeaderMemory * lpcHeaderMemory )
{
	int nNumberOfSections = 0;
	int i = 0;
	PIMAGE_NT_HEADERS lpNtHeaders = NULL;
	PIMAGE_SECTION_HEADER lpSectionHeader = NULL;
	ImageHeaderMemory * lpcMemoryPage = NULL;

	lpNtHeaders = (PIMAGE_NT_HEADERS)this->get_header( lpcHeaderMemory );
	lpSectionHeader = (PIMAGE_SECTION_HEADER) ( (unsigned char *)lpNtHeaders + 
		sizeof(IMAGE_NT_HEADERS) );
	nNumberOfSections = (int)lpNtHeaders->FileHeader.NumberOfSections;

	while( nNumberOfSections ) {
		lpcMemoryPage = (ImageHeaderMemory *)
			lpcProcessMemory->memory_find_memory_page_addr( 
			lpcProcessMemory->memory_get_memory_pages(), (void *)( 
			lpSectionHeader->VirtualAddress + 
			(DWORD)lpcHeaderMemory->get_baseaddress() ) );
		if( lpcMemoryPage == NULL )
			return FALSE;

		/*
		pecoff.docx
		[..]
		For longer names, this field contains a slash (/) that is followed by an
		ASCII representation of a decimal number that is an offset into the string 
		table. 
		[..]
		*/
		lpcMemoryPage->set_image_section_name( (char *)lpSectionHeader->Name );
		this->vAllSections.push_back( lpcMemoryPage );

		if( lpSectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE || 
			lpSectionHeader->Characteristics & IMAGE_SCN_CNT_CODE ) {

				this->vCodeSections.push_back( lpcMemoryPage );
		}
		else if( 
			lpSectionHeader->Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA || 
			lpSectionHeader->Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA || 
			lpSectionHeader->Characteristics & IMAGE_SCN_MEM_READ || 
			lpSectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE ) {
				this->vDataSections.push_back( lpcMemoryPage );
		}
		nNumberOfSections--;
		lpSectionHeader = (PIMAGE_SECTION_HEADER)( 
			(unsigned long)lpSectionHeader + sizeof(IMAGE_SECTION_HEADER) );
	}
	return TRUE;
}

BOOL PEParser::get_code_sections( IMemory * lpcProcessMemory,
	vector<MemoryPage*> * lpvCodeSections, 
	ImageHeaderMemory * lpcHeaderMemory )
{
	int i;

	if( this->lpcImageHeader == NULL ) {
		if( this->get_header( lpcHeaderMemory ) == NULL ) 
			return FALSE;
	}
	else if( this->lpcImageHeader->get_baseaddress() != 
		lpcHeaderMemory->get_baseaddress() ) {
			if( this->get_header( lpcHeaderMemory ) == NULL )
				return FALSE;
	}

	if( this->vCodeSections.size() == 0 ) {
		this->get_sections( lpcProcessMemory, lpcHeaderMemory );
	}
	for( i = 0; i < (int)this->vCodeSections.size(); i++ ) {
		lpvCodeSections->push_back( this->vCodeSections[i] );
	}

	return TRUE;
}

BOOL PEParser::get_data_sections( IMemory * lpcProcessMemory,
	vector<MemoryPage*> * lpvDataSections, 
	ImageHeaderMemory * lpcHeaderMemory )
{
	int i;

	if( this->lpcImageHeader == NULL ) {
		if( this->get_header( lpcHeaderMemory ) == NULL ) 
			return FALSE;
	}
	else if( this->lpcImageHeader->get_baseaddress() != 
		lpcHeaderMemory->get_baseaddress() ) {
			if( this->get_header( lpcHeaderMemory ) == NULL )
				return FALSE;
	}

	if( this->vCodeSections.size() == 0 ) {
		this->get_sections( lpcProcessMemory, lpcHeaderMemory );
	}
	for( i = 0; i < (int)this->vCodeSections.size(); i++ ) {
		lpvDataSections->push_back( this->vDataSections[i] );
	}

	return TRUE;
}

//XXX Implement me
BOOL PEParser::is_address_in_code( IMemory * lpcProcessMemory,
	ImageHeaderMemory * lpcHeaderMemory, void * lpAddress )
{
	
	return TRUE;
}

BOOL PEParser::get_image_exported_functions( IMemory * lpcProcessMemory,
	vector<Function*> * lpvFunctionsList, 
	ImageHeaderMemory * lpcHeaderMemory )
{
	PIMAGE_NT_HEADERS lpNtHeaders = NULL;
	MemoryPage * lpcMemoryPage = NULL;
	PIMAGE_DATA_DIRECTORY lpsDataDirectory;
	PIMAGE_EXPORT_DIRECTORY lpsExportDirectory;
	unsigned long ulExportDirectoryStartAddr = NULL;
	unsigned long ulExportDirectoryEndAddr = NULL;

	unsigned long * ulpExportNames = NULL;
	unsigned short * uspExportOrdinals = NULL;
	unsigned long * ulExportAddresses = NULL;
	
	int i = 0;

	char * lpszFunctionName;
	unsigned short usFunctionOrdinal = NULL;
	unsigned long * ulFunctionAddress = NULL;
	unsigned long * ulFunctionVAddress = NULL;
	Function * lpcFunction = NULL;

	lpNtHeaders = (PIMAGE_NT_HEADERS)this->get_header( lpcHeaderMemory );
	lpsDataDirectory = (PIMAGE_DATA_DIRECTORY)
		lpNtHeaders->OptionalHeader.DataDirectory;

	if( lpsDataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size == NULL || 
		lpsDataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == NULL )
			return FALSE;

	ulExportDirectoryStartAddr = 
		lpsDataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	ulExportDirectoryEndAddr = 
		lpsDataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size + 
		ulExportDirectoryStartAddr;

	//Retrieve Export directory page
	lpcMemoryPage = lpcProcessMemory->memory_find_memory_page_addr( 
			lpcProcessMemory->memory_get_memory_pages(), (void *)( 
			(unsigned long)lpcHeaderMemory->get_baseaddress() + 
			ulExportDirectoryStartAddr) );
	
	lpcMemoryPage->allocate_buffer_for_page();
	if( lpcProcessMemory->memory_get_memory_page_contents( 
		lpcMemoryPage->get_process_id(), 
		lpcMemoryPage, 
		lpcMemoryPage->get_memory_page_contents_buffer(), 
		lpcMemoryPage->get_page_size() ) == FALSE ) {
			PrintError( __FUNCTION__ 
				"Error Getting Page Contents Address: 0x%08X", 
				lpcMemoryPage->get_baseaddress() );
			return FALSE;
	}
	
	lpsExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(
		lpcMemoryPage->get_memory_page_contents_buffer() + (unsigned long)( 
		( (unsigned long)lpcHeaderMemory->get_baseaddress() + 
		ulExportDirectoryStartAddr ) - 
		(unsigned long)lpcMemoryPage->get_baseaddress() ) );

	dprintflvl( 3, "Export Directory Start: 0x%08X End: 0x%08X", 
		ulExportDirectoryStartAddr, ulExportDirectoryEndAddr );

	//XXX Handle cases where names, ordinals and function address arrays are in
	// a different page. (quite unlikely)
	if( lpcProcessMemory->is_address_in_page( lpcMemoryPage, 
		(void *)lpsExportDirectory->AddressOfNames ) ) {
			dprintf( "Names in external page, not implemented yet" );
			return FALSE;
	}

	if( lpcProcessMemory->is_address_in_page( lpcMemoryPage, 
		(void *)lpsExportDirectory->AddressOfNameOrdinals ) ) {
			dprintf( "Ordinals in external page, not implemented yet" );
			return FALSE;
	}

	if( lpcProcessMemory->is_address_in_page( lpcMemoryPage, 
		(void *)lpsExportDirectory->AddressOfFunctions ) ) {
			dprintf( "Function Addresses in external page, not implemented yet" );
			return FALSE;
	}

	ulpExportNames = (unsigned long *)( 
		lpcMemoryPage->get_memory_page_contents_buffer() + 
		(unsigned long)lpcImageHeader->get_baseaddress() + 
		lpsExportDirectory->AddressOfNames - 
		(unsigned long)lpcMemoryPage->get_baseaddress() );
	uspExportOrdinals = (unsigned short *)( 
		lpcMemoryPage->get_memory_page_contents_buffer() + 
		(unsigned long)lpcImageHeader->get_baseaddress() + 
		lpsExportDirectory->AddressOfNameOrdinals - 
		(unsigned long)lpcMemoryPage->get_baseaddress() );
	ulExportAddresses = (unsigned long *)( 
		lpcMemoryPage->get_memory_page_contents_buffer() + 
		(unsigned long)lpcImageHeader->get_baseaddress() + 
		lpsExportDirectory->AddressOfFunctions - 
		(unsigned long)lpcMemoryPage->get_baseaddress() );

	for( i = 0; i < (int)lpsExportDirectory->NumberOfNames; i++ ) {
		
		usFunctionOrdinal = uspExportOrdinals[i];
		lpszFunctionName = (char *) (
			lpcMemoryPage->get_memory_page_contents_buffer() + 
			(unsigned long)lpcImageHeader->get_baseaddress() + 
			ulpExportNames[i] - 
			(unsigned long)lpcMemoryPage->get_baseaddress() );
		ulFunctionAddress = (unsigned long *)(
			lpcMemoryPage->get_memory_page_contents_buffer() + 
			(unsigned long)lpcImageHeader->get_baseaddress() + 
			ulExportAddresses[usFunctionOrdinal] - 
			(unsigned long)lpcMemoryPage->get_baseaddress() );
		ulFunctionVAddress = (unsigned long *)(
			(unsigned long)lpcHeaderMemory->get_baseaddress() + 
			ulExportAddresses[usFunctionOrdinal]);
		//We only care about exported functions
		if( lpcProcessMemory->memory_is_valid_code_address( 
			(int)lpcProcessMemory->memory_get_process_id(), ulFunctionVAddress ) 
			== FALSE ) {
				continue;
		}

		if( (unsigned long)lpcMemoryPage->get_allocation_baseaddress() <= 
				(unsigned long)ulFunctionVAddress && 
			( (unsigned long)lpcMemoryPage->get_allocation_baseaddress() + 
				lpcMemoryPage->get_page_size() ) >= 
				(unsigned long)ulFunctionVAddress ) {
					if(this->is_export_forwarder( ulFunctionAddress ) ) {
						continue;
					}
		}
		
		if( lpszFunctionName != NULL ) {
		dprintflvl( 3, "Function: %08X : %s", ulFunctionAddress, 
			lpszFunctionName );
		}
		else {
			dprintflvl( 3, "Null name" );
		}
		lpcFunction = new Function();
		lpcFunction->set_function_virtual_address( (void *)( 
			(unsigned long)lpcHeaderMemory->get_baseaddress() + 
			ulExportAddresses[usFunctionOrdinal] ) );
		lpcFunction->set_function_address( (void *)ulFunctionAddress );
		lpcFunction->set_function_name( lpszFunctionName );
		lpcFunction->set_function_image_name( 
			lpcHeaderMemory->get_image_name_ascii() );
		lpvFunctionsList->push_back( lpcFunction );
		//XXX Implement these
		//lpcFunction->set_function_file_address()

	}

	return TRUE;
}

BOOL PEParser::is_export_forwarder( unsigned long * ulExportAddress )
{
	char * lpForwarder = (char *)ulExportAddress;
	BOOL bGotDot = FALSE;
	int nSize = 0;
	while( *lpForwarder ) {
		if( *lpForwarder == '.' ) {
			bGotDot = TRUE;
		}
		else if( !( *lpForwarder >= 'A' && *lpForwarder <= 'Z' || 
				*lpForwarder >= 'a' && *lpForwarder <= 'z' || 
				*lpForwarder >= '0' && *lpForwarder <= '9' ) ) {
					return FALSE;
		}
		nSize++;
		lpForwarder++;
	}
	if( bGotDot && nSize > 6 ) {
		return TRUE;
	}
	return FALSE;
}

unsigned long PEParser::get_virtual_sizeo_if_image( ImageHeaderMemory * 
	lpcHeader )
{
	PIMAGE_NT_HEADERS lpNtHeaders = NULL;

	lpNtHeaders = (PIMAGE_NT_HEADERS)this->get_header( lpcHeader );

	return lpNtHeaders->OptionalHeader.SizeOfImage;
}


ImageHeaderMemory * PEParser::get_section_of_address( void * lvpAddress )
{
	int i;
	if( this->vAllSections.size() == 0 ) {
		dprintflvl( 3, "Headers not initialized" );
		return NULL;
	}

	for( i = 0; i < (int)this->vAllSections.size(); i++ ) {
		if( this->vAllSections[i]->get_baseaddress() <= lvpAddress && 
			( (unsigned long) this->vAllSections[i]->get_baseaddress() + 
			this->vAllSections[i]->get_page_size() ) > 
			(unsigned long)lvpAddress ) {
				return this->vAllSections[i];
		}
	}
	dprintflvl( 3, "Unable to locate Section at 0x%X", lvpAddress );
	return NULL;
}

BOOL PEParser::read_from_file( char * lpszFilePath )
{
	FILE * hFile;
	if( ( hFile = fopen( lpszFilePath, "rb") ) == NULL ) {
		WinError::winerror_print_last_error( __FUNCTION__ );
		return FALSE;
	}

	fseek( hFile, 0, SEEK_END );
	this->nFileSize = ftell( hFile );

	fseek( hFile, 0, SEEK_SET );

	//There is already a file associated with this object
	if( lpFileBuffer != NULL ) {
		return FALSE;
	}

	this->lpFileBuffer = (unsigned char *)malloc( this->nFileSize );
	if( fread( this->lpFileBuffer, 1, this->nFileSize, hFile ) != 
		this->nFileSize ) {
			PrintError( "Error loading file %s", lpszFilePath );
	}
}

void * PEParser::get_header(void)
{
	if( this->lpFileBuffer == NULL ) return NULL;
	if( this->pImageNtHeaders != NULL ) return this->pImageNtHeaders;

	PIMAGE_NT_HEADERS lpNtHeaders = NULL;
	PIMAGE_DOS_HEADER lpDosHeader = NULL;

	lpDosHeader = (PIMAGE_DOS_HEADER)this->lpFileBuffer;
	lpNtHeaders = (PIMAGE_NT_HEADERS)( this->lpFileBuffer + 
		lpDosHeader->e_lfanew );

	this->pImageDosHeader = lpDosHeader;
	this->pImageNtHeaders = lpNtHeaders;

	return lpNtHeaders;
}

BOOL PEParser::get_code_sections( vector<MemoryPage*> * lpvSections )
{
	return FALSE;
}

BOOL PEParser::get_data_sections( vector<MemoryPage*> * lpvDataSections )
{
	return FALSE;
}

BOOL PEParser::get_image_exported_functions( vector<Function*> * lpvFunctionsList ) {
	return FALSE;
}

unsigned long PEParser::get_physical_size_of_file()
{
	if( this->lpFileBuffer == NULL ) return NULL;

	return this->nFileSize;
}