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
#include "MemoryPage.h"

typedef enum _EXE_TYPE {
	EXE_PE,
	EXE_ELF
} EXE_TYPE;

class LIBEXPORT ImageHeaderMemory : public MemoryPage
{
public:
	ImageHeaderMemory(void);
	~ImageHeaderMemory(void);
	wchar_t * get_image_name( void );
	unsigned long get_image_size( void );
	char * get_image_name_ascii( void );
	EXE_TYPE get_exe_type( void );
	char * get_image_section_name( void );
	wchar_t * get_image_fullname(void);
	char * get_image_fullname_ascii(void);

	void set_image_name( wchar_t * lpszName );
	void set_image_name_ascii( char * lpszName );
	void set_image_fullname( wchar_t * lpszName );
	void set_image_fullname_ascii( char * lpszName );
	void set_image_size( unsigned long ulSize );
	void set_exe_type( EXE_TYPE eExeType );
	void set_image_section_name( char * lpszName );

private:
	wchar_t * lpszImageName;
	wchar_t * lpszImageFullName;
	char * lpszImageNameASCII;
	char * lpszSectionName;
	char * lpszImageFullNameAscii;
	unsigned long ulImageSize;
	EXE_TYPE eExeType;
};

