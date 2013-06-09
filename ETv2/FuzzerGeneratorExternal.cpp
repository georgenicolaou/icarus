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

#include "FuzzerGeneratorExternal.h"
#include "ProcessExecutor.h"
#ifdef OS_WIN_
#include <windows.h> 
#include <tchar.h>
#include <stdio.h> 
#include <strsafe.h>
#include "WinError.h"
#endif

FuzzerGeneratorExternal::FuzzerGeneratorExternal(void)
{
}


FuzzerGeneratorExternal::~FuzzerGeneratorExternal(void)
{
}

BOOL FuzzerGeneratorExternal::setup_generator( char * lpszExeFileLocation, 
	int nNumberOfArgs, ... )
{
	va_list lpVaList;
	ProcessExecutor * lpcProcessExecutor = ProcessExecutor::init_get_instance();
	va_start( lpVaList, nNumberOfArgs );
	if( lpcProcessExecutor->execute_process( lpszExeFileLocation, nNumberOfArgs, 
		lpVaList, TRUE, TRUE ) == FALSE ) {
			dprintflvl(2, "Error Executing Generator Process %s", 
				lpszExeFileLocation );
			return FALSE;
	}
	va_end( lpVaList );

	return TRUE;
}