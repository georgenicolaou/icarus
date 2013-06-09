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

#define PROCESSEXECUTOR_READ_BUFFER_SIZE 2048

class LIBEXPORT ProcessExecutor
{
public:
	ProcessExecutor(void);
	~ProcessExecutor(void);
	static ProcessExecutor * init_get_instance( void );
	virtual BOOL execute_process( char * lpszExeFileLocation, int nNumberOfArgs,
		va_list lpVaList, BOOL bCaptureStdOut, BOOL bCaptureStdIn ) = NULL;
	virtual BOOL write_to_stdin( unsigned char * lpucDataIn, 
		int nSizeofData ) = NULL;

	/*
	** Read from the stdout pipe of the process
	** Arguments:
	**	lpucBuffer - The buffer to read into. If this variable is NULL then the
	**		read buffer can be retrieved by calling the get_read_buffer() 
	**		function
	**	nBufferSize - The allocation size of the buffer in lpucBuffer
	**
	** Return:
	**	int - The number of bytes read from the pipe
	*/
	virtual int read_from_stdout( unsigned char * lpucBuffer, 
		int nBufferSize ) = NULL;
	virtual unsigned char * get_read_buffer() = NULL;
};

