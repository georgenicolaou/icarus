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
using namespace std;
#include "IExeHandler.h"
#include "ImageHeaderMemory.h"
#include "MemoryPage.h"
#include "WindowsMemory.h"
#include "windef.h"
#include <vector>

class PEParser : public IExeHandler
{
public:
	PEParser(void);
	~PEParser(void);
	/*
	In memory functions
	*/
	virtual void * get_header( ImageHeaderMemory * cHeaderMemory  );
	virtual BOOL get_sections( IMemory * lpcProcessMemory,
		ImageHeaderMemory * lpcHeaderMemory );

	virtual BOOL get_code_sections( IMemory * lpcProcessMemory,
		vector<MemoryPage*> * lpvSections, 
		ImageHeaderMemory * lpcHeaderMemory );
	virtual BOOL get_data_sections( IMemory * lpcProcessMemory,
		vector<MemoryPage*> * lpvDataSections, 
		ImageHeaderMemory * lpcHeaderMemory );
	virtual BOOL get_image_exported_functions( IMemory * lpcProcessMemory,
		vector<Function*> * lpvFunctionsList, 
		ImageHeaderMemory * lpcHeaderMemory );
	virtual BOOL is_address_in_code( IMemory * lpcProcessMemory,
		ImageHeaderMemory * lpcHeaderMemory, void * lpAddress );
	virtual unsigned long get_virtual_sizeo_if_image( ImageHeaderMemory * 
		lpcHeader );

	virtual ImageHeaderMemory * get_section_of_address( void * lvpAddress );
	/*
	File functions
	*/
	virtual BOOL read_from_file( char * lpszFilePath );
	virtual void * get_header(void);
	//XXX below functions haven't been implemented
	virtual BOOL get_code_sections( vector<MemoryPage*> * lpvSections );
	virtual BOOL get_data_sections( vector<MemoryPage*> * lpvDataSections );
	virtual BOOL get_image_exported_functions( 
		vector<Function*> * lpvFunctionsList );
	virtual unsigned long get_physical_size_of_file();
private:
	BOOL is_export_forwarder( unsigned long * ulExportAddress );
	PIMAGE_DOS_HEADER pImageDosHeader;
	PIMAGE_NT_HEADERS pImageNtHeaders;
	ImageHeaderMemory * lpcImageHeader;
	vector<ImageHeaderMemory*> vCodeSections;
	vector<ImageHeaderMemory*> vDataSections;
	vector<ImageHeaderMemory *> vAllSections;
	int nFileSize;
	unsigned char * lpFileBuffer;
};

