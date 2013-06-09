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

#include "WindowsProcessExecutor.h"
#include "icarus_include.h"
#include <windows.h> 
#include <tchar.h>
#include <stdio.h> 
#include <strsafe.h>
#include "WinError.h"

WindowsProcessExecutor::WindowsProcessExecutor(void)
{
	this->bCapturingStdIn = FALSE;
	this->bCapturingStdOut = FALSE;
	this->lpucReadBuffer = NULL;
}


WindowsProcessExecutor::~WindowsProcessExecutor(void)
{
}

BOOL WindowsProcessExecutor::execute_process( 
	char * lpszExeFileLocation, 
	int nNumberOfArgs, 
	va_list lpVaList, 
	BOOL bCaptureStdOut, 
	BOOL bCaptureStdIn
)
{
	char * lpszTmpVal = NULL;
	char * lpszTmpContainer = NULL;
	int nArgumentsLength = 0;
	int nSingleArgumentLength = 0;
	int nExeFileLocationSize = strlen( lpszExeFileLocation );
	string sStrCommandline = lpszExeFileLocation;

	this->bCapturingStdIn = bCaptureStdIn;
	this->bCapturingStdOut = bCaptureStdOut;

	if( ( this->lpczProgramName = (char *)calloc( strlen( lpszExeFileLocation ), 
		sizeof( char) ) ) == NULL ) {
			dprintflvl( 3, "Allocation Error");
	}
	//va_start( lpVaList, nNumberOfArgs );
	for( int i = 0; i < nNumberOfArgs; i++ ) {
		lpszTmpVal = va_arg( lpVaList, char * );
		sStrCommandline += " ";
		sStrCommandline += lpszTmpVal;
	}

	
	//char * lpTmpPtr = lpszArgumentString;
	SECURITY_ATTRIBUTES sSecurityAttr;

	//Create Pipes to redirect stdout
	sSecurityAttr.nLength = sizeof( SECURITY_ATTRIBUTES );
	sSecurityAttr.bInheritHandle = TRUE;
	sSecurityAttr.lpSecurityDescriptor = NULL;

	if( bCaptureStdOut ) {
		dprintflvl( 3, "Creating stdout pipe" );
		if( !CreatePipe( &hChildStdoutRead, &hChildStdoutWrite, &sSecurityAttr, 
			0 ) ) {
				WinError::winerror_print_last_error( __FUNCTION__ );
		}
		if( !SetHandleInformation( hChildStdoutRead, HANDLE_FLAG_INHERIT, 
			0 ) ) {
				WinError::winerror_print_last_error( __FUNCTION__ );
		}
	}

	if( bCapturingStdIn ) {
		dprintflvl( 3, "Creating stdin pipe" );
		if( !CreatePipe( &hChildStdinRead, &hChildStdinWrite, &sSecurityAttr, 
			0 ) ) {
				WinError::winerror_print_error( __FUNCTION__ );
		}
		if( !SetHandleInformation( hChildStdinWrite, HANDLE_FLAG_INHERIT, 
			0 ) ) {
				WinError::winerror_print_last_error( __FUNCTION__ );
		}
	}

	//Create Child process
	memset( &sProcessInformation, 0, sizeof( PROCESS_INFORMATION ) );
	memset( &sStartupInfo, 0, sizeof( STARTUPINFO ) );

	sStartupInfo.cb = sizeof( STARTUPINFO );
	sStartupInfo.hStdOutput = ( bCaptureStdOut ) ? hChildStdoutWrite : NULL;
	sStartupInfo.hStdInput = ( bCaptureStdIn ) ? hChildStdinRead : NULL;
	sStartupInfo.dwFlags |= STARTF_USESTDHANDLES;

	char * lpszArgumentString = (char *)sStrCommandline.c_str();
	if( !CreateProcessA( 
		lpszExeFileLocation, 
		lpszArgumentString,
		NULL, 
		NULL, 
		TRUE, 
		0, 
		NULL, 
		NULL, 
		&sStartupInfo, 
		&sProcessInformation  ) ) {
			WinError::winerror_print_last_error( __FUNCTION__ );
			return FALSE;
	}
	return TRUE;
}

BOOL WindowsProcessExecutor::write_to_stdin( unsigned char * lpucDataIn, 
	int nSizeofData )
{
	DWORD dwWritten;

	if( !this->bCapturingStdIn ) {
		dprintflvl( 1, "StdIn not captured for %s", this->lpczProgramName);
		return FALSE;
	}

	if( !WriteFile( hChildStdinWrite, lpucDataIn, nSizeofData, &dwWritten, 
		NULL ) ) {
			WinError::winerror_print_last_error( __FUNCTION__ );
			return FALSE;
	}

	//CloseHandle( hChildStdinWrite );
	//hChildStdinWrite = NULL;
	return TRUE;
}

int WindowsProcessExecutor::read_from_stdout( unsigned char * lpucBuffer, 
	int nBufferSize )
{
	DWORD dwRead, dwPeakRead, dwTotalBytesAvail, dwBytesLeft;
	int nReadSum = 0;
	BOOL bSuccess;
	unsigned char * lpucBufferTmp;

	if( !this->bCapturingStdOut ) {
		dprintflvl( 1, "StdOut not captured for %s", this->lpczProgramName);
		return NULL;
	}

	if( lpucBuffer == NULL ) {
		lpucBuffer = this->get_read_buffer_internal();
		nBufferSize = PROCESSEXECUTOR_READ_BUFFER_SIZE;
	}

	lpucBufferTmp = lpucBuffer;

	//XXX should handle console processes using CreateConsoleScreenBuffer(), 
	//ReadConsoleOutput() and WriteConsoleInput() in case of scanf() and such

	do {
		PeekNamedPipe( hChildStdoutRead, NULL, nBufferSize, NULL,
			&dwTotalBytesAvail, NULL  );
		
		if( !dwTotalBytesAvail )
			return 0;

		bSuccess = ReadFile( hChildStdoutRead, lpucBufferTmp, nBufferSize, 
			&dwRead, NULL );
		lpucBufferTmp += dwRead;
		nBufferSize -= dwRead;
		nReadSum += dwRead;
	} while( !bSuccess || dwRead == 0 );

	return nReadSum;
}

unsigned char * WindowsProcessExecutor::get_read_buffer_internal()
{
	if( this->lpucReadBuffer == NULL ) {
		this->lpucReadBuffer = 
			(unsigned char *)malloc( PROCESSEXECUTOR_READ_BUFFER_SIZE );
	}
	return this->lpucReadBuffer;
}

unsigned char * WindowsProcessExecutor::get_read_buffer()
{
	if( this->lpucReadBuffer == NULL ) {
		dprintflvl( 1, "No read operation yet" );
	}

	return this->lpucReadBuffer;
}