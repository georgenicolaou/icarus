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
#include "icarus_include.h"
#include "MemoryPage.h"
#include "ImageHeaderMemory.h"
#include "IMemory.h"
#include "Function.h"
#include <vector>

class LIBEXPORT IExeHandler
{
public:

	IExeHandler(void);
	~IExeHandler(void);
	/*
	In memory functions
	*/
	static EXE_TYPE exehandler_get_exe_type( void * vpAFewBytes, 
		int nBytesBufferSize );
	virtual BOOL get_sections( IMemory * lpcProcessMemory,
		ImageHeaderMemory * lpcHeaderMemory ) = NULL;
	static IExeHandler * init_get_instance( ImageHeaderMemory * lpcHeader);

	virtual void * get_header( ImageHeaderMemory * cHeaderMemory  ) = NULL;
	virtual BOOL get_code_sections( IMemory * lpcProcessMemory, 
		vector<MemoryPage*> * lpvCodeSections, 
		ImageHeaderMemory * lpcHeaderMemory ) = NULL;
	virtual BOOL get_data_sections( IMemory * lpcProcessMemory,
		vector<MemoryPage*> * lpvDataSections, 
		ImageHeaderMemory * lpcHeaderMemory ) = NULL;
	virtual BOOL get_image_exported_functions( IMemory * lpcProcessMemory,
		vector<Function*> * lpvFunctionsList, 
		ImageHeaderMemory * lpcHeaderMemory ) = NULL;
	virtual BOOL is_address_in_code( IMemory * lpcProcessMemory,
		ImageHeaderMemory * lpcHeaderMemory, void * lpAddress ) = NULL;
	virtual unsigned long get_virtual_sizeo_if_image( ImageHeaderMemory * 
		lpcHeader ) = NULL;
	virtual ImageHeaderMemory * get_section_of_address( void * lvpAddress ) 
		= NULL;
	/*
	File functions
	*/
	virtual BOOL read_from_file( char * lpszFilePath ) = NULL;
	virtual void * get_header(void) = NULL;
	virtual BOOL get_code_sections( vector<MemoryPage*> * lpvSections ) = NULL;
	virtual BOOL get_data_sections( vector<MemoryPage*> * lpvDataSections ) = NULL;
	virtual BOOL get_image_exported_functions( 
		vector<Function*> * lpvFunctionsList ) = NULL;
	virtual unsigned long get_physical_size_of_file() = NULL;
private:

};

