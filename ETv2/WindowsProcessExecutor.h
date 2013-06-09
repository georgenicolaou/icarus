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

#include "ProcessExecutor.h"
#include <Windows.h>
#include <vector>
#include "icarus_include.h"

class WindowsProcessExecutor : public ProcessExecutor
{
public:
	WindowsProcessExecutor(void);
	~WindowsProcessExecutor(void);
	virtual BOOL execute_process( char * lpszExeFileLocation, int nNumberOfArgs,
		va_list lpVaList, BOOL bCaptureStdOut, BOOL bCaptureStdIn );
	virtual BOOL write_to_stdin( unsigned char * lpucDataIn, int nSizeofData );
	virtual int read_from_stdout( unsigned char * lpucBuffer, 
		int nBufferSize );
	virtual unsigned char * get_read_buffer();
private:
	char * lpczProgramName;
	BOOL bCapturingStdIn;
	BOOL bCapturingStdOut;
	vector<char *> vArguments;
	PROCESS_INFORMATION sProcessInformation;
	STARTUPINFO sStartupInfo;
	HANDLE hChildStdinRead;
	HANDLE hChildStdinWrite;
	HANDLE hChildStdoutRead;
	HANDLE hChildStdoutWrite;
	unsigned char * lpucReadBuffer;

	unsigned char * get_read_buffer_internal();
};

