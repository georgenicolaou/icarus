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

#include "ExceptionSignal.h"
#ifdef OS_WIN_
#include <Windows.h>
#include <WinNT.h>
#include <ntstatus.h>
#endif // OS_WIN_


ExceptionSignal::ExceptionSignal(void)
{
	this->bContinuable = -1;
	this->eExceptionCode = ICARUS_EXCEPTION_UNINITIALIZED;
	this->lvpExceptionAddress = NULL;
	this->lpExtraInfo = (void *) -1;
	this->nProcessId = -1;
	this->nThreadId = -1;
	this->bEncounteredBefore = -1;
	this->ulProcExitCode = -1;
}


ExceptionSignal::~ExceptionSignal(void)
{
}

void ExceptionSignal::set_exception_address( void * lpAddress )
{
	if( this->lvpExceptionAddress == NULL )
		this->lvpExceptionAddress = lpAddress;
}

void ExceptionSignal::set_process_id( int nProcId )
{
	if( this->nProcessId == -1 )
		this->nProcessId = nProcId;
}
void ExceptionSignal::set_thread_id( int nThreadId )
{
	if( this->nThreadId == -1 )
		this->nThreadId = nThreadId;
}

void ExceptionSignal::set_exception_code( ICARUS_CODE_ENUM eCode )
{
	if( this->eExceptionCode == ICARUS_EXCEPTION_UNINITIALIZED )
		this->eExceptionCode = eCode;
}

void ExceptionSignal::set_continuable( BOOL bContinuable )
{
	if( this->bContinuable == -1 )
		this->bContinuable = bContinuable;
}

void ExceptionSignal::set_extra_info( void * lpExtra )
{
	if( this->lpExtraInfo == (void *)-1 ) {
		this->lpExtraInfo = lpExtra;
	}
}

void ExceptionSignal::set_encountered_before( BOOL bEncountered )
{
	if( this->bEncounteredBefore == -1 ) {
		this->bEncounteredBefore = bEncountered;
	}
}

void ExceptionSignal::set_process_exit_code( unsigned long ulCode )
{
	if( this->ulProcExitCode == -1 ) {
		this->ulProcExitCode = ulCode;
	}
}


//Getters ------------------------------------------------------------------

void * ExceptionSignal::get_exception_address()
{
	return this->lvpExceptionAddress;
}

int ExceptionSignal::get_process_id()
{
	return this->nProcessId;
}

ICARUS_CODE_ENUM ExceptionSignal::get_exception_code()
{
	return this->eExceptionCode;
}

BOOL ExceptionSignal::is_continuable()
{
	return this->bContinuable;
}

void * ExceptionSignal::get_extra_info()
{
	return this->lpExtraInfo;
}

BOOL ExceptionSignal::encountered_before()
{
	return this->bEncounteredBefore;
}

unsigned long ExceptionSignal::get_process_exit_code()
{
	return this->ulProcExitCode;
}

int ExceptionSignal::get_thread_id()
{
	return this->nThreadId;
}

char * ExceptionSignal::get_exception_name()
{
	switch( this->eExceptionCode ) {
	case ICARUS_EXCEPTION_UNINITIALIZED: return "Not Set";
	case ICARUS_ACCESS_VIOLATION: return "Access Violation";
	case ICARUS_DATATYPE_MISALIGNMENT: return "Datatype Misalignment";
	case ICARUS_BREAKPOINT: return "Breakpoint";
	case ICARUS_SINGLE_STEP: return "Single Step";
	case ICARUS_ARRAY_BOUNDS_EXCEEDED: return "Array Bounds Exceeded";
	case ICARUS_FLT_DENORMAL_OPERAND: return "Denormal Operand";
	case ICARUS_FLT_DIVIDE_BY_ZERO: return "Float Divide by Zero";
	case ICARUS_FLT_INEXACT_RESULT: return "Inexact Result";
	case ICARUS_FLT_INVALID_OPERATION: return "Invalid Operation";
	case ICARUS_FLT_OVERFLOW: return "Overflow";
	case ICARUS_FLT_STACK_CHECK: return "Stack Check";
	case ICARUS_FLT_UNDERFLOW: return "Underflow";
	case ICARUS_INT_DIVIDE_BY_ZERO: return "Divide by Zero";
	case ICARUS_INT_OVERFLOW: return "Integer Overflow";
	case ICARUS_PRIV_INSTRUCTION: return "Privileged instruction";
	case ICARUS_IN_PAGE_ERROR: return "In Page Error";
	case ICARUS_ILLEGAL_INSTRUCTION: return "Illegal Instruction";
	case ICARUS_NONCONTINUABLE_EXCEPTION: return "Non Continuable Exception";
	case ICARUS_STACK_OVERFLOW: return "Stack Overflow";
	case ICARUS_INVALID_DISPOSITION: return "Invalid Disposition";
	case ICARUS_GUARD_PAGE: return "Guard Page";
	case ICARUS_INVALID_HANDLE: return "Invalid Handle";
	case ICARUS_POSSIBLE_DEADLOCK: return "Possible Deadlock";
	case ICARUS_CONTROL_C: return "Ctrl+C";
	}
}