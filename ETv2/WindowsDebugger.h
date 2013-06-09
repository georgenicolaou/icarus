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
#pragma warning( push, 0 )
#include <vector>
#pragma warning( pop )

#include "icarus_include.h"
#include "windef.h"
#include "processor/IRegister.h"
#include "IDebugger.h"
#include "ExceptionSignal.h"
#include "IMemory.h"
class WindowsDebugger : public IDebugger
{
public:
	WindowsDebugger(void);
	~WindowsDebugger(void);

	virtual int get_process_id( void );
	virtual ExceptionSignal * get_current_exception( void );
	virtual BOOL debugger_enter_loop( void );
	virtual BOOL debugger_get_registers( vector<IRegister*> * vlpRegisters, 
		int nThreadId );
	virtual void debugger_get_thread_info();
	virtual BOOL debugger_attach( int nProcessId );
	virtual BOOL debugger_attach( int nProcessId, BOOL bPause );
	virtual BOOL debugger_open_for_debugging( char * lpszExeFilename );
	virtual BOOL debugger_open_for_debugging( char * lpszExeFilename, BOOL bResume );
	virtual void * debugger_get_last_exception_thread();
	virtual BOOL debugger_detach();
	virtual BOOL is_attached();
	virtual BOOL debuger_pause_execution();

	virtual void debugger_set_exception_handler( EXCEPTION_CALLBACK );
	virtual void debugger_set_breakpoint_handler( BREAKPOINT_CALLBACK );
	virtual void debugger_set_termination_handler( TERMINATION_CALLBACK );

	virtual void debugger_set_exception_handler( ICallback * );
	virtual void debugger_set_breakpoint_handler( ICallback * );
	virtual void debugger_set_termination_handler( ICallback * );

	virtual BOOL debugger_set_breakpoint( unsigned long ulAddress );
	virtual BOOL debugger_clear_breakpoint( unsigned long ulAddress );
	virtual BOOL debugger_clear_breakpoint( DEBUGGER_BREAKPOINT * );
	virtual BOOL debugger_disable_breakpoint( unsigned long ulAddress );
	virtual BOOL debugger_disable_breakpoint( DEBUGGER_BREAKPOINT * );
	virtual BOOL debugger_enable_breakpoint( unsigned long ulAddress );
	virtual BOOL debugger_enable_breakpoint( DEBUGGER_BREAKPOINT * );
	virtual BOOL debugger_clear_all_breakpoints();
	//virtual BOOL debugger_get_breakpoints();

	virtual BOOL debugger_set_trap_breakpoint( void * hThread );
	virtual BOOL debugger_clear_trap_breakpoint( void * hThread );

	virtual EVENT_CONTROL debugger_step_breakpoint( unsigned long ulAddress, 
		void * hThread );

	//XXX MSR with this
	BOOL debugger_set_trap_on_branch();
	BOOL debugger_enable_branch_logging( void * );

	EVENT_CONTROL windowsdebugger_step_breakpoint( DEBUGGER_BREAKPOINT *, 
		void * hThread, LPCONTEXT );

	BOOL windowsdebugger_set_trap_breakpoint( void *, LPCONTEXT );
	BOOL windowsdebugger_clear_trap_breakpoint( void *, LPCONTEXT );

	BOOL windowsdebugger_token_privilege( char * lpszPrivilegeName, 
		BOOL bFlag );
	IMemory * windowsdebugger_get_proc_memory();
	DEBUGGER_BREAKPOINT * get_breakpoint_from_address( unsigned long );

	//Debugger specific event functions
	EVENT_CONTROL exception_event( DEBUG_EVENT * lpEvent );
	EVENT_CONTROL createprocess_event( DEBUG_EVENT * lpEvent );
	EVENT_CONTROL exit_process_event( DEBUG_EVENT * lpEvent );
	EVENT_CONTROL exit_thread_event( DEBUG_EVENT * lpEvent );

	BOOL populate_exceptionsignal( ExceptionSignal * lpException, 
		DEBUG_EVENT * lpEvent );

	
private:
	int nProcessId;
	BOOL bAttachedToProcess;
	BOOL bPauseOnAttach;
	BOOL bKeepLooping;
	HANDLE hProcess;
	//Volatile per method call
	DEBUG_EVENT sDebugEvent;
	PEXCEPTION_RECORD lpsLastException;
	//An instance global since we are cross-referencing register values
	//using pointers to this structure
	CONTEXT sThreadContext;
	ExceptionSignal * lpsExceptionSignal;
	EXCEPTION_CALLBACK lpExceptionCallback;
	BREAKPOINT_CALLBACK lpBreakpointCallback;
	TERMINATION_CALLBACK lpTerminationCallback;
	ICallback * lpExceptionICallback;
	ICallback * lpBreakpointICallback;
	ICallback * lpTerminationICallback;
	vector<DEBUGGER_BREAKPOINT *> vBreakpoints;
	IMemory * lpProcMemory;
	BOOL bGotCreateProcess;
};

