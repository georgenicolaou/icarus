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

typedef enum {
	ICARUS_EXCEPTION_UNINITIALIZED = 0,
	ICARUS_ACCESS_VIOLATION,
	ICARUS_DATATYPE_MISALIGNMENT,     
	ICARUS_BREAKPOINT,
	ICARUS_SINGLE_STEP,
	ICARUS_ARRAY_BOUNDS_EXCEEDED,
	ICARUS_FLT_DENORMAL_OPERAND,    
	ICARUS_FLT_DIVIDE_BY_ZERO,
	ICARUS_FLT_INEXACT_RESULT,
	ICARUS_FLT_INVALID_OPERATION,
	ICARUS_FLT_OVERFLOW,
	ICARUS_FLT_STACK_CHECK,
	ICARUS_FLT_UNDERFLOW,
	ICARUS_INT_DIVIDE_BY_ZERO,
	ICARUS_INT_OVERFLOW,
	ICARUS_PRIV_INSTRUCTION,
	ICARUS_IN_PAGE_ERROR,
	ICARUS_ILLEGAL_INSTRUCTION,
	ICARUS_NONCONTINUABLE_EXCEPTION,
	ICARUS_STACK_OVERFLOW,
	ICARUS_INVALID_DISPOSITION,
	ICARUS_GUARD_PAGE,
	ICARUS_INVALID_HANDLE,
	ICARUS_POSSIBLE_DEADLOCK,
	ICARUS_CONTROL_C
} ICARUS_CODE_ENUM;

class LIBEXPORT ExceptionSignal
{
public:
	ExceptionSignal(void);
	~ExceptionSignal(void);

	void set_exception_address( void * );
	void set_process_id( int );
	void set_thread_id( int );
	void set_exception_code( ICARUS_CODE_ENUM );
	void set_continuable( BOOL );
	void set_extra_info( void * );
	void set_encountered_before( BOOL );
	void set_process_exit_code( unsigned long );
	
	void * get_exception_address();
	int get_process_id();
	int get_thread_id();
	ICARUS_CODE_ENUM get_exception_code();
	BOOL is_continuable();
	void * get_extra_info();
	BOOL encountered_before();
	unsigned long get_process_exit_code();
	char * ExceptionSignal::get_exception_name();
private:
	void * lvpExceptionAddress;
	int nProcessId;
	int nThreadId;
	BOOL bEncounteredBefore;
	ICARUS_CODE_ENUM eExceptionCode;
	BOOL bContinuable;
	void * lpExtraInfo;
	unsigned long ulProcExitCode;
};

