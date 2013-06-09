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
#include "processor/IRegister.h"

#include "icarus_include.h"
#include "ExceptionSignal.h"
#include "ICallback.h"


typedef struct _DEBUGGER_BREAKPOINT {
	unsigned long ulAddress;
	int nTimesHit;
	BOOL bEnabled;
	void * lpOriginalCode;
} DEBUGGER_BREAKPOINT, PDEBUGGER_BREAKPOINT;

typedef enum  {
	EVENT_NOT_HANDLED,
	EVENT_HANDLE,
	EVENT_DIE
} EVENT_CONTROL;

class LIBEXPORT IDebugger
{

public:
	/*
	** on_exception_callback Callback Function
	** Arguments:
	**	ExecutionMonitor * - A pointer to the current execution monitor
	**	ExceptionSignal * - A pointer to an ExceptionSignal instance
	** Returns:
	**	TRUE - If handler wishes to continue debugging the program
	**	FALSE - If handler wishes to stop debugging the program
	*/
	typedef EVENT_CONTROL (* EXCEPTION_CALLBACK ) ( IDebugger *, ExceptionSignal * );

	/*
	** on_breakpoint_callback Callback Function
	** Arguments:
	**	IDebugger * - The debugger interface
	**	ExceptionSignal - Information about the breakpoint that just occurred
	** Returns:
	**	TRUE - If handler wishes to continue debugging the program
	**	FALSE - If handler wishes to stop debugging the program
	*/
	typedef EVENT_CONTROL (* BREAKPOINT_CALLBACK )( IDebugger *, ExceptionSignal * );

	/*
	** on_exception_callback Callback Function
	** Arguments:
	**	None
	** Returns:
	**	TRUE - If handler wishes to restart the program and monitor it
	**	FALSE - If handler wishes to stop debugging the program
	*/
	typedef EVENT_CONTROL (* TERMINATION_CALLBACK ) ( IDebugger *, ExceptionSignal * );


	IDebugger(void);
	~IDebugger(void);

	static IDebugger * init_get_instance();
	virtual int get_process_id( void ) = NULL;
	virtual ExceptionSignal * get_current_exception( void ) = NULL;
	virtual BOOL debugger_enter_loop( void ) = NULL;
	virtual BOOL debugger_get_registers( vector<IRegister *> * vlpRegister,
		int nThreadId ) = NULL;
	virtual void debugger_get_thread_info() = NULL;
	virtual BOOL debugger_attach( int nProcessId ) = NULL;
	virtual BOOL debugger_attach( int nProcessId, BOOL bPause ) = NULL;

	//XXX arguments?
	virtual BOOL debugger_open_for_debugging( char * lpszExeFilename ) = NULL;
	virtual BOOL debugger_open_for_debugging( char * lpszExeFilename, BOOL bResume ) = NULL;

	virtual void * debugger_get_last_exception_thread() = NULL;
	virtual BOOL debugger_detach() = NULL;
	virtual BOOL is_attached() = NULL;
	virtual BOOL debuger_pause_execution() = NULL;

	virtual void debugger_set_exception_handler( EXCEPTION_CALLBACK ) = NULL;
	virtual void debugger_set_breakpoint_handler( BREAKPOINT_CALLBACK ) = NULL;
	virtual void debugger_set_termination_handler( TERMINATION_CALLBACK ) = NULL;

	//Callbacks receive only ExceptionSignal * as argument.
	virtual void debugger_set_exception_handler( ICallback * ) = NULL;
	virtual void debugger_set_breakpoint_handler( ICallback * ) = NULL;
	virtual void debugger_set_termination_handler( ICallback * ) = NULL;

	virtual BOOL debugger_set_breakpoint( unsigned long ulAddress ) = NULL;
	virtual BOOL debugger_clear_breakpoint( unsigned long ulAddress ) = NULL;
	virtual BOOL debugger_clear_breakpoint( DEBUGGER_BREAKPOINT * ) = NULL;
	virtual BOOL debugger_disable_breakpoint( unsigned long ulAddress ) = NULL;
	virtual BOOL debugger_disable_breakpoint( DEBUGGER_BREAKPOINT * ) = NULL;
	virtual BOOL debugger_enable_breakpoint( unsigned long ulAddress ) = NULL;
	virtual BOOL debugger_enable_breakpoint( DEBUGGER_BREAKPOINT * ) = NULL;

	virtual BOOL debugger_clear_all_breakpoints() = NULL;

	virtual BOOL debugger_set_trap_breakpoint( void * hThread ) = NULL;
	virtual BOOL debugger_clear_trap_breakpoint( void * hThread ) = NULL;

	virtual EVENT_CONTROL debugger_step_breakpoint( unsigned long ulAddress, 
		void * hThread ) = NULL;
	//virtual BOOL debugger_get_breakpoints() = NULL;

	//XXX implement this
	//virtual BOOL debugger_set_trap_on_branch() = NULL;

};

