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
#include "ExceptionSignal.h"
#include "IDebugger.h"
#include "Function.h"


class LIBEXPORT ExecutionMonitor : public ICallback
{

public:
	typedef enum {
		MONITOR_NOTHING = 0,
		MONITOR_DANGEROUS_FUNCTIONS		= 0x00000001,
		MONITOR_EXCEPTIONS				= 0x00000002,
		MONITOR_LIBRARY_INTERACTIONS	= 0x00000004,
	} MONITOR_OPTIONS;

	typedef enum {
		EVENT_FUNCTION_CALL,
		EVENT_EXCEPTION
	} EVENT_TYPE;

	typedef struct {
		EVENT_TYPE eType;
		int nThreadId;
		unsigned long ulEventAddress;
		union {
			Function * lpFunction;
			ExceptionSignal * lpException;
		} uType;
	} MONITOR_EVENT_INFO;

	typedef BOOL ( * MONITOR_CALLBACK )( MONITOR_EVENT_INFO * );


	ExecutionMonitor(void);
	~ExecutionMonitor(void);

	//ICallback functions
	virtual void fcallback( void * );
	virtual BOOL fbCallback( void * );

	BOOL attach_and_monitor( int nProcessId, MONITOR_OPTIONS eOptions );
	BOOL create_and_monitor( char * lpszExecutable, char * lpArguments, 
		MONITOR_OPTIONS eOptions );
	void set_monitor_callback( MONITOR_CALLBACK );

	IDebugger * get_debugger();
	//ExploitabilityAnalysis * run_exploitability_analysis( DWORD dwFlags );
private:
	BOOL begin_monitoring();

	BOOL setup_api_hooks( MONITOR_OPTIONS );
	BOOL setup_exception_monitoring();

	BOOL is_dangerous( char * lpFunctionName );
	BOOL ExecutionMonitor::is_blacklisted( char * lpFunctionName );
	MONITOR_CALLBACK fMonitorCallback;
	MONITOR_OPTIONS eMonitorOptions;
	IDebugger * lpDebugger;
	IMemory * lpMemory;
	vector<Function *> vHookedFunctions;
};

