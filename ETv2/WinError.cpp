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

#include "WinError.h"
#include <iostream>
#include <Windows.h>
#include "icarus_include.h"

WinError::WinError(void)
{
}


WinError::~WinError(void)
{
}

void WinError::winerror_print_last_error( char * lpszFunctionName )
{
	char * lpMessage;
	DWORD dwLastError;

	dwLastError = GetLastError();

	FormatMessage( FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS, NULL, dwLastError, 
		MAKELANGID( LANG_NEUTRAL, SUBLANG_DEFAULT ), 
		(LPTSTR) &lpMessage, 0, NULL );

	dprintflvl( 1, "%s: Windows Error: %s", lpszFunctionName, lpMessage );
	LocalFree( lpMessage );
}

void WinError::winerror_print_error( char * lpszError )
{
	printf( "%s", lpszError );
}