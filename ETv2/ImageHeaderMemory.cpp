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

#include "ImageHeaderMemory.h"
#include "DataEncoder.h"

ImageHeaderMemory::ImageHeaderMemory(void)
{
	this->lpszImageName = NULL;
	this->lpszImageNameASCII = NULL;
	this->ulImageSize = NULL;
	this->lpszSectionName = NULL;
}


ImageHeaderMemory::~ImageHeaderMemory(void)
{
}

wchar_t * ImageHeaderMemory::get_image_name( void )
{
	return this->lpszImageName;
}

unsigned long ImageHeaderMemory::get_image_size( void )
{
	return this->ulImageSize;
}

char * ImageHeaderMemory::get_image_name_ascii( void )
{
	char * lpszImageAscii;

	if( this->lpszImageNameASCII != NULL ) return this->lpszImageNameASCII;
	if ( ( lpszImageAscii = DataEncoder::wchar_to_ascii( this->lpszImageName ) 
		) == NULL ) {
			return NULL;
	}

	this->lpszImageNameASCII = lpszImageAscii;
	return lpszImageAscii;
}

EXE_TYPE ImageHeaderMemory::get_exe_type( void )
{
	return this->eExeType;
}

void ImageHeaderMemory::set_image_name( wchar_t * lpszName )
{
	this->lpszImageName = lpszName;
}

void ImageHeaderMemory::set_image_name_ascii( char * lpszName ) 
{
	this->lpszImageNameASCII = lpszName;
}
void ImageHeaderMemory::set_image_size( unsigned long ulSize )
{
	this->ulImageSize = ulSize;
}

void ImageHeaderMemory::set_exe_type( EXE_TYPE eExeType )
{
	this->eExeType = eExeType;
}

char * ImageHeaderMemory::get_image_section_name( void )
{
	return this->lpszSectionName;
}

void ImageHeaderMemory::set_image_section_name( char * lpszName )
{
	this->lpszSectionName = lpszName;
}

void ImageHeaderMemory::set_image_fullname( wchar_t * lpszName )
{
	this->lpszImageFullName = lpszName;
}

void ImageHeaderMemory::set_image_fullname_ascii( char * lpszName )
{
	this->lpszImageFullNameAscii = lpszName;
}

wchar_t * ImageHeaderMemory::get_image_fullname(void)
{
	return this->lpszImageFullName;
}

char * ImageHeaderMemory::get_image_fullname_ascii(void)
{
	return this->lpszImageFullNameAscii;
}