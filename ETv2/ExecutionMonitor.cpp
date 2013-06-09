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

#include "ExecutionMonitor.h"
#include "IExeHandler.h"

#ifdef OS_WIN_
static char * lplpszDangerousFunctions[] = {

	"strcpy", "StringCchCopy", "strcat", "StrCatBuff", "StringCchCat", "sprintf",
	"vsprintf", "StringCchVPrintf", "memcpy", "scanf", "fscanf", "gets", 
	"StringCchGets", "fgets", "gets_s", "vfscanf", "vscanf", "streadd", "strecpy",
	"getc", "bcopy", "Memcpy", "CopyMemory", "mommove", "MoveMemory", "ShellExecute",
	"ShellExecuteEx", "WinExec", "system", "_wsystem", 
};

static char * lplpBlacklistedFunctions[] = {
	"DbgBreakPoint"
};
#endif //OS_WIN_

ExecutionMonitor::ExecutionMonitor(void)
{
	this->lpDebugger = NULL;
	this->eMonitorOptions = MONITOR_NOTHING;
}


ExecutionMonitor::~ExecutionMonitor(void)
{
}

BOOL ExecutionMonitor::attach_and_monitor( int nProcessId, 
	MONITOR_OPTIONS eOptions )
{
	if( this->lpDebugger != NULL ) {
		PrintError( "Debugger already attached" );
		return FALSE;
	}

	this->lpDebugger = IDebugger::init_get_instance();

	if( this->lpDebugger->debugger_attach( nProcessId ) == FALSE ) {
		return FALSE;
	}
	this->eMonitorOptions = eOptions;
	this->begin_monitoring();
}

BOOL ExecutionMonitor::create_and_monitor( char * lpszExecutable, 
	char * lpArguments, MONITOR_OPTIONS eOptions )
{
	if( this->lpDebugger != NULL && this->lpDebugger->is_attached() ) {
		this->lpDebugger->debugger_detach();
	}
	if( this->lpDebugger->debugger_open_for_debugging( lpszExecutable ) == 
		FALSE ) {
			return FALSE;
	}
	this->eMonitorOptions = eOptions;
	this->begin_monitoring();
}

void ExecutionMonitor::set_monitor_callback( MONITOR_CALLBACK fCallback )
{
	this->fMonitorCallback = fCallback;
}

BOOL ExecutionMonitor::begin_monitoring()
{
	if( this->lpDebugger == NULL || this->lpDebugger->is_attached() == FALSE ) {
		PrintError( "Debugger not attached" );
		return FALSE;
	}

	if( this->eMonitorOptions == MONITOR_NOTHING ) {
		PrintError( "No monitor options set" );
		return FALSE;
	}

	//XXX should probably do some cleanup


	//monitoring all function calls always supersedes dangerous functions
	if( this->eMonitorOptions & MONITOR_LIBRARY_INTERACTIONS ) {
		if( this->setup_api_hooks( MONITOR_LIBRARY_INTERACTIONS ) == FALSE ) {
			lpDebugger->debugger_detach();
			return FALSE;
		}
	}
	else if( this->eMonitorOptions & MONITOR_DANGEROUS_FUNCTIONS ) {
		if( this->setup_api_hooks( MONITOR_DANGEROUS_FUNCTIONS ) == FALSE ) {
			lpDebugger->debugger_detach();
			return FALSE;
		}
	}

	if( this->eMonitorOptions & MONITOR_EXCEPTIONS ) {
		if( this->setup_exception_monitoring() == FALSE ) {
			lpDebugger->debugger_detach();
			return FALSE;
		}
	}

	return lpDebugger->debugger_enter_loop();
}

BOOL ExecutionMonitor::setup_api_hooks( MONITOR_OPTIONS eOption )
{
	vector<ImageHeaderMemory *> vHeaders;
	IMemory * lpMemory = IMemory::init_get_instance();
	this->lpMemory = lpMemory;
	vector<Function *> vExportedFunctions;
	IDebugger * lpDebugger = this->lpDebugger;

	lpDebugger->debugger_set_breakpoint_handler( (ICallback *)this );

	if( lpMemory->memory_get_module_headers( &vHeaders, 
		lpDebugger->get_process_id() ) == FALSE ) {
			return FALSE;
	}

	IExeHandler * lpExeHandler = IExeHandler::init_get_instance( vHeaders[0] );
	
	for( int i = 0; i < (int)vHeaders.size(); i++ ) {
		if( lpExeHandler->get_image_exported_functions( lpMemory, 
			&vExportedFunctions, vHeaders[i] ) == FALSE ) {
				continue;
		}
	}
	for( int j = 0; j < (int)vExportedFunctions.size(); j++ ) {
		if( eOption == MONITOR_DANGEROUS_FUNCTIONS ) {
			if( this->is_dangerous( 
				vExportedFunctions[j]->get_function_name() ) == FALSE ) {
					delete vExportedFunctions[j];
					continue;
			}
		}

		if( this->is_blacklisted( vExportedFunctions[j]->get_function_name() ) ) {
			delete vExportedFunctions[j];
			continue;
		}

		this->vHookedFunctions.push_back( vExportedFunctions[j] );
			
		dprintflvl( 3, "Setting breakpoint at %s:%s (%#X)", 
			vExportedFunctions[j]->get_function_image_name(), 
			vExportedFunctions[j]->get_function_name(),
			vExportedFunctions[j]->get_function_virtual_address() );
		//XXX if this
		lpDebugger->debugger_set_breakpoint( 
			(unsigned long)vExportedFunctions[j]->get_function_virtual_address() );
	}

	vHeaders.clear();
	return TRUE;
}

BOOL ExecutionMonitor::is_blacklisted( char * lpFunctionName )
{
	for( int i = 0; i < sizeof( lplpBlacklistedFunctions ) / sizeof( char *); i++ ) {
		if( strcmp( lplpBlacklistedFunctions[i], lpFunctionName ) == 0 )
			return TRUE;
	}
	return FALSE;
}

BOOL ExecutionMonitor::is_dangerous( char * lpFunctionName )
{
	for( int i = 0; i < sizeof( lplpszDangerousFunctions ) / sizeof( char * ); i++ ) {
		if( strcmp( lplpszDangerousFunctions[i], lpFunctionName ) == 0 ) {
			return TRUE;
		}
	}
	return FALSE;
}

BOOL ExecutionMonitor::setup_exception_monitoring()
{
	this->lpDebugger->debugger_set_exception_handler( this );
	return TRUE;
}

void ExecutionMonitor::fcallback( void * lpArg ) 
{
	return;
	//dont need it
}

BOOL ExecutionMonitor::fbCallback( void * lpArg )
{
	ExceptionSignal * lpException = (ExceptionSignal *)lpArg;
	MONITOR_EVENT_INFO sInfo;

	sInfo.nThreadId = lpException->get_thread_id();
	sInfo.ulEventAddress = 
		(unsigned long)lpException->get_exception_address();

	if( lpException->get_exception_code() == ICARUS_BREAKPOINT ) {
		sInfo.eType = EVENT_FUNCTION_CALL;
		sInfo.uType.lpFunction = NULL;
		for( int i = 0; i < (int)this->vHookedFunctions.size(); i++ ) {
			if( (unsigned long)this->vHookedFunctions[i]->get_function_virtual_address() 
				== sInfo.ulEventAddress ) {
					sInfo.uType.lpFunction = this->vHookedFunctions[i];
					break;
			}
		}
		//need to peak the stack for return address
		return this->fMonitorCallback( &sInfo );
	}
	else {
		sInfo.eType = EVENT_EXCEPTION;
		sInfo.uType.lpException = lpException;
		return this->fMonitorCallback( &sInfo );
	}
}

IDebugger * ExecutionMonitor::get_debugger()
{
	return this->lpDebugger;
}