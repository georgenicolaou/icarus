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

#include "WindowsDebugger.h"
#include "WinError.h"
#include "processor/IRegister.h"
#include <Windows.h>
#include <ntstatus.h>
//#include "../iDisasm/iDisasm/types.h"

char lpBpInstruction[] = { '\xCC' };

WindowsDebugger::WindowsDebugger(void)
{
	this->nProcessId = 0;
	this->bAttachedToProcess = FALSE;
	memset( (void *)&this->sDebugEvent, 0, sizeof( DEBUG_EVENT ) );
	this->lpsLastException = NULL;
	memset( &this->sThreadContext, 0, sizeof(CONTEXT) );
	this->lpsExceptionSignal = NULL;
	this->hProcess = NULL;
	this->lpProcMemory = NULL;
	this->bGotCreateProcess = FALSE;
	this->lpExceptionICallback = NULL;
	this->lpTerminationICallback = NULL;
	this->lpBreakpointICallback = NULL;
	this->bPauseOnAttach = FALSE;
	this->lpTerminationCallback = NULL;
	this->lpExceptionCallback = NULL;
	this->lpBreakpointCallback = NULL;
}


WindowsDebugger::~WindowsDebugger(void)
{
}

BOOL WindowsDebugger::windowsdebugger_token_privilege( 
	char * lpszPrivilegeName, BOOL bFlag )
{
	LUID sLuid;
	TOKEN_PRIVILEGES sTokenPrivileges;
	HANDLE hToken;

	if( OpenProcessToken( GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, 
		&hToken ) == FALSE ) {
			WinError::winerror_print_last_error( __FUNCTION__ );
			return FALSE;
	}

	if( LookupPrivilegeValueA( NULL, lpszPrivilegeName, &sLuid ) 
		== FALSE ) {
			dprintflvl( 2, "Privilege lookup error" );
			CloseHandle( hToken );
			return FALSE;
	}

	sTokenPrivileges.PrivilegeCount = 1;
	sTokenPrivileges.Privileges[0].Luid = sLuid;
	sTokenPrivileges.Privileges[0].Attributes = bFlag ? 
		SE_PRIVILEGE_ENABLED : NULL;

	if( AdjustTokenPrivileges( (HANDLE)hToken, FALSE, 
		(PTOKEN_PRIVILEGES)&sTokenPrivileges, 
		(DWORD)sizeof( sTokenPrivileges ), (PTOKEN_PRIVILEGES)NULL, 
		(PDWORD)NULL ) == FALSE ) {
			CloseHandle( hToken );
			WinError::winerror_print_last_error( __FUNCTION__ );
			dprintflvl( 2, "Error adjusting token" );
			return FALSE;
	}

	CloseHandle( hToken );
	return TRUE;
}

BOOL WindowsDebugger::debugger_enter_loop( void )
{
	DWORD dwContinueStatus = DBG_CONTINUE;
	PEXCEPTION_RECORD lpExceptionRecord = NULL;
	this->bKeepLooping = TRUE;
	if( this->bAttachedToProcess == FALSE ) {
		dprintflvl( 2, "Not attached" );
		return FALSE;
	}
	if( this->lpsLastException != NULL && this->sDebugEvent.dwDebugEventCode != 
		NULL ) {
			ContinueDebugEvent( this->sDebugEvent.dwProcessId, 
				this->sDebugEvent.dwThreadId, dwContinueStatus );
	}

	memset( &this->sDebugEvent, 0, sizeof( DEBUG_EVENT ) );
	this->lpsLastException = NULL;
	dprintflvl( 4, "Entering debug loop" );
	do {
		if( this->lpsExceptionSignal != NULL ) {
			delete this->lpsExceptionSignal;
			this->lpsExceptionSignal = NULL;
		}

		WaitForDebugEvent( &this->sDebugEvent, INFINITE );

		dprintflvl( 4, "Got Event: %d", this->sDebugEvent.dwDebugEventCode );
		switch( this->sDebugEvent.dwDebugEventCode ) {
		case EXCEPTION_DEBUG_EVENT:
			dprintflvl( 4, "Event is Exception, calling handler" );
			switch ( this->exception_event( &this->sDebugEvent ) ) {
			case EVENT_HANDLE:
				dwContinueStatus = DBG_CONTINUE;
				break;
			case EVENT_NOT_HANDLED:
				dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
				break;
			case EVENT_DIE:
				dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
				bKeepLooping = FALSE;
				break;
			}
				
			break;
		case CREATE_PROCESS_DEBUG_EVENT:
			dprintflvl( 4, "Event is Create process" );
			this->createprocess_event( &this->sDebugEvent );
			dwContinueStatus = DBG_CONTINUE;
			break;
		case CREATE_THREAD_DEBUG_EVENT:
			dprintflvl( 4, "Event is create thread" );
			void * hThread;
			if( ( hThread = (void *)OpenThread( THREAD_GET_CONTEXT + 
				THREAD_SET_CONTEXT + THREAD_QUERY_INFORMATION, FALSE, 
				this->sDebugEvent.dwThreadId ) ) == NULL ) {
					WinError::winerror_print_last_error( __FUNCTION__ );
					break;
			}
			//this->debugger_enable_branch_logging( hThread );
			break;
		case EXIT_PROCESS_DEBUG_EVENT:
			dprintflvl( 4, "Exit Process: %d", 
				this->sDebugEvent.u.ExitProcess.dwExitCode );
			this->exit_process_event( &this->sDebugEvent  );
			dwContinueStatus = DBG_CONTINUE;
			bKeepLooping = FALSE;
			break;
		case EXIT_THREAD_DEBUG_EVENT:
			dprintflvl( 4, "Exit Thread %X: %d", this->sDebugEvent.dwThreadId, 
				this->sDebugEvent.u.ExitThread.dwExitCode );
			this->exit_thread_event( &this->sDebugEvent  );
			dwContinueStatus = DBG_CONTINUE;
			break;
		}

		if( dwContinueStatus != NULL ) {
			dprintflvl( 4, "Continuing Event" );
			ContinueDebugEvent( this->sDebugEvent.dwProcessId, 
				this->sDebugEvent.dwThreadId, dwContinueStatus );
		}
	} while( bKeepLooping && dwContinueStatus != NULL );
	this->debugger_detach();
	return TRUE;
}

BOOL WindowsDebugger::debugger_get_registers( 
	vector<IRegister*> * vlpRegisters, int nThreadId )
{
	void * hThread;
	IRegister * lpsRegister;
	memset( &this->sThreadContext, 0, sizeof(CONTEXT) );
	if( this->bAttachedToProcess == FALSE ) return FALSE;
	sThreadContext.ContextFlags = CONTEXT_FULL;

	if( ( hThread = (void *)OpenThread( THREAD_GET_CONTEXT + 
		THREAD_QUERY_INFORMATION, FALSE, (DWORD)nThreadId ) ) == NULL ) {
			WinError::winerror_print_last_error( __FUNCTION__ );
			return FALSE;
	}
	
	if( GetThreadContext( (HANDLE)hThread, &sThreadContext ) == NULL ) {
		WinError::winerror_print_last_error( __FUNCTION__ );
		return FALSE;
	}

	//XXX have to make sure we handle other architectures as well here

	/*
	#define PUSH_REGISTER( vlpRegs, lpsRegister, eGeneralRegName, lpValue ) {\
	lpsRegister = IRegister::init_get_instance(); \
	lpsRegister->set_register_name( eGeneralRegName ); \
	lpsRegister->set_register_value( lpValue ); \
	vlpRegs->push_back( lpsRegister ); \
	}
	*/
#ifdef ARCH_X86_
	PUSH_REGISTER( vlpRegisters, lpsRegister, IRegister::REG0, 
		&sThreadContext.Eax );
	PUSH_REGISTER( vlpRegisters, lpsRegister, IRegister::REG1, 
		&sThreadContext.Ecx );
	PUSH_REGISTER( vlpRegisters, lpsRegister, IRegister::REG2, 
		&sThreadContext.Edx );
	PUSH_REGISTER( vlpRegisters, lpsRegister, IRegister::REG3, 
		&sThreadContext.Ebx );
	PUSH_REGISTER( vlpRegisters, lpsRegister, IRegister::REG_SP, 
		&sThreadContext.Esp );
	PUSH_REGISTER( vlpRegisters, lpsRegister, IRegister::REG_FP, 
		&sThreadContext.Ebp );
	PUSH_REGISTER( vlpRegisters, lpsRegister, IRegister::REG6, 
		&sThreadContext.Esi );
	PUSH_REGISTER( vlpRegisters, lpsRegister, IRegister::REG7, 
		&sThreadContext.Edi );
	PUSH_REGISTER( vlpRegisters, lpsRegister, IRegister::REG_PC, 
		&sThreadContext.Eip );
#endif // ARCH_X86

	CloseHandle( (HANDLE)hThread );
	return TRUE;


}

IMemory * WindowsDebugger::windowsdebugger_get_proc_memory()
{
	if( this->lpProcMemory == NULL ) {
		this->lpProcMemory = IMemory::init_get_instance();
		this->lpProcMemory->memory_set_process_id( (void *)this->nProcessId );
	}
	return this->lpProcMemory;
}

void WindowsDebugger::debugger_get_thread_info()
{
	//what info?
}

BOOL WindowsDebugger::debugger_detach()
{
	if( !this->bAttachedToProcess ) {
		dprintflvl( 2, "Not attached to a process" );
		return FALSE;
	}

	if( DebugActiveProcessStop( this->nProcessId ) == NULL ) {
		WinError::winerror_print_last_error( __FUNCTION__ );
		dprintflvl( 2, "Unable to detach" );
		return FALSE;
	}

	this->bAttachedToProcess = FALSE;
	return TRUE;

}

BOOL WindowsDebugger::debugger_attach( int nProcessId )
{
	return this->debugger_attach( nProcessId, FALSE );
}

BOOL WindowsDebugger::debugger_attach( int nProcessId, BOOL bPause )
{
	if( this->windowsdebugger_token_privilege( SE_DEBUG_NAME, TRUE ) 
		== FALSE ) {
			return FALSE;
	}

	this->bPauseOnAttach = bPause;

	if( DebugActiveProcess( nProcessId ) == FALSE ) {
		WinError::winerror_print_last_error( __FUNCTION__ );
		dprintflvl( 2, "Unable to debug: %d", nProcessId );
		return FALSE;
	}

	this->bAttachedToProcess = TRUE;
	this->nProcessId = nProcessId;

	return TRUE;
}

BOOL WindowsDebugger::debugger_open_for_debugging( char * lpszExeFilename )
{
	return this->debugger_open_for_debugging( lpszExeFilename, TRUE );
}

BOOL WindowsDebugger::debugger_open_for_debugging( char * lpszExeFilename, 
	BOOL bResume )
{
	STARTUPINFO sStartupInfo = { sizeof(STARTUPINFO) };
	PROCESS_INFORMATION sProcessInformation;

	if( CreateProcess( lpszExeFilename, NULL, NULL, NULL, FALSE, 
		CREATE_SUSPENDED + CREATE_NEW_CONSOLE, NULL, NULL, &sStartupInfo, 
		&sProcessInformation ) == NULL ) {
			WinError::winerror_print_error( __FUNCTION__ );
			return FALSE;
	}

	this->nProcessId = (int)sProcessInformation.dwProcessId;
	this->hProcess = sProcessInformation.hProcess;
	this->debugger_attach( sProcessInformation.dwProcessId );

	if( bResume )
		ResumeThread( sProcessInformation.hThread );

	return TRUE;
}

int WindowsDebugger::get_process_id( void )
{
	return this->nProcessId;
}

ExceptionSignal * WindowsDebugger::get_current_exception( void )
{
	return this->lpsExceptionSignal;
}

void * WindowsDebugger::debugger_get_last_exception_thread()
{
	return (void *) this->sDebugEvent.dwThreadId;
}

BOOL WindowsDebugger::is_attached()
{
	return this->bAttachedToProcess;
}

BOOL WindowsDebugger::debuger_pause_execution()
{
	if( this->hProcess == NULL )
		return FALSE;

	return DebugBreakProcess( this->hProcess );
}


void WindowsDebugger::debugger_set_exception_handler( 
	EXCEPTION_CALLBACK lpCallback )
{
	this->lpExceptionCallback = lpCallback;
}

void WindowsDebugger::debugger_set_breakpoint_handler( 
	BREAKPOINT_CALLBACK lpCallback )
{
	this->lpBreakpointCallback = lpCallback;
}

void WindowsDebugger::debugger_set_termination_handler( 
	TERMINATION_CALLBACK lpCallback )
{
	this->lpTerminationCallback = lpCallback;
}

DEBUGGER_BREAKPOINT * WindowsDebugger::get_breakpoint_from_address( 
	unsigned long ulAddress )
{
	for( int i = 0; i < (int)this->vBreakpoints.size(); i++ ) {
		if( this->vBreakpoints[i]->ulAddress == ulAddress ) {
			return this->vBreakpoints[i];
		}
	}
	dprintflvl( 3, "Unable to locate breakpoint at address %#X", ulAddress );
	return NULL;
}

BOOL WindowsDebugger::debugger_set_breakpoint( 
	unsigned long ulAddress )
{
	IMemory * lpMemory = this->windowsdebugger_get_proc_memory();
	DEBUGGER_BREAKPOINT * lpBp = new DEBUGGER_BREAKPOINT();

	lpBp->ulAddress = ulAddress;
	lpBp->nTimesHit = 0;

	if( lpMemory->memory_get_address_contents( this->nProcessId, 
		(void *)ulAddress, 1, &lpBp->lpOriginalCode ) == FALSE ) {
			PrintError( "Error Reading Breakpoint address" );
			return FALSE;
	}

	lpBp->bEnabled = TRUE;
	this->vBreakpoints.push_back(lpBp);
	
	if( lpMemory->memory_write_to_address( this->nProcessId, (void *)ulAddress, 
		lpBpInstruction, sizeof(lpBpInstruction ) ) == FALSE ) {
			PrintError( "Unable to set breakpoint" );
			lpBp->bEnabled = FALSE;
			this->debugger_clear_breakpoint( ulAddress );
			return FALSE;
	}

	FlushInstructionCache( this->hProcess, (LPCVOID)lpBp->ulAddress, 
		sizeof(lpBpInstruction) );

	return TRUE;
}

BOOL WindowsDebugger::debugger_clear_breakpoint( 
	unsigned long ulAddress )
{
	return this->debugger_clear_breakpoint( 
		this->get_breakpoint_from_address( ulAddress ) );
}

BOOL WindowsDebugger::debugger_clear_breakpoint( DEBUGGER_BREAKPOINT * lpBp )
{
	if( lpBp->bEnabled == TRUE ) {
		IMemory * lpMemory = this->windowsdebugger_get_proc_memory();
		if( lpMemory->memory_write_to_address( this->nProcessId, 
			(void *)lpBp->ulAddress, &lpBp->lpOriginalCode, 
			sizeof(lpBpInstruction) ) == FALSE ) {
				PrintError( "Unable to remove breakpoint" );
				return FALSE;
		}
	}
	FlushInstructionCache( this->hProcess, (LPCVOID)lpBp->ulAddress, 
		sizeof(lpBpInstruction) );

	delete lpBp;
	return TRUE;
}

BOOL WindowsDebugger::debugger_disable_breakpoint( unsigned long ulAddress )
{
	return this->debugger_disable_breakpoint( this->get_breakpoint_from_address( 
		ulAddress ) );
}

BOOL WindowsDebugger::debugger_disable_breakpoint( DEBUGGER_BREAKPOINT * lpBp )
{
	if( lpBp == NULL ) return FALSE;

	if( lpBp->bEnabled == FALSE ) return TRUE;

	IMemory * lpMemory = this->windowsdebugger_get_proc_memory();

	if( lpMemory->memory_write_to_address( this->nProcessId, 
		(void *)lpBp->ulAddress, &lpBp->lpOriginalCode, 
		sizeof(lpBpInstruction) ) == FALSE ) {
			PrintError( "Unable to disable breakpoint" );
			return FALSE;
	}
	
	FlushInstructionCache( this->hProcess, (LPCVOID)lpBp->ulAddress, 
		sizeof(lpBpInstruction) );

	lpBp->bEnabled = FALSE;
	return TRUE;
}

BOOL WindowsDebugger::debugger_clear_all_breakpoints()
{
	BOOL bReturn = TRUE;
	for( int i = 0; i < (int)this->vBreakpoints.size(); i++ ) {
		if( this->debugger_clear_breakpoint( vBreakpoints[i] ) == FALSE ) {
			bReturn = FALSE;
		} 
	}
	return bReturn;
}

BOOL WindowsDebugger::debugger_set_trap_breakpoint( void * hThread )
{
	CONTEXT sContext = {0};
	sContext.ContextFlags = CONTEXT_FULL;
	if( GetThreadContext( hThread, &sContext ) == FALSE ) {
		WinError::winerror_print_last_error( __FUNCTION__ );
		return FALSE;
	}

	return this->windowsdebugger_set_trap_breakpoint( hThread, &sContext );
}

BOOL WindowsDebugger::debugger_clear_trap_breakpoint( void * hThread )
{
	CONTEXT sContext = {0};
	sContext.ContextFlags = CONTEXT_FULL;
	if( GetThreadContext( hThread, &sContext ) == FALSE ) {
		WinError::winerror_print_last_error( __FUNCTION__ );
		return FALSE;
	}

	return this->windowsdebugger_clear_trap_breakpoint( hThread, &sContext );
}


BOOL WindowsDebugger::windowsdebugger_set_trap_breakpoint( void * hThread, 
	LPCONTEXT lpContext )
{
	lpContext->EFlags |= 0x100;
	if( SetThreadContext( hThread, lpContext ) == FALSE ) {
		WinError::winerror_print_last_error( __FUNCTION__ );
		return FALSE;
	}
	return TRUE;
}

BOOL WindowsDebugger::windowsdebugger_clear_trap_breakpoint( void * hThread, 
	LPCONTEXT lpContext )
{
	lpContext->EFlags &= ~0x100;
	SetThreadContext( hThread, lpContext );
	return TRUE;
}

EVENT_CONTROL WindowsDebugger::debugger_step_breakpoint( unsigned long ulAddress, 
	void * hThread )
{
	CONTEXT sContext = {0};
	sContext.ContextFlags = CONTEXT_FULL;
	if( GetThreadContext( hThread, &sContext ) == FALSE ) {
		WinError::winerror_print_last_error( __FUNCTION__ );
		return EVENT_NOT_HANDLED;
	}

	dprintflvl( 4, "Stepping through breakpoint" );
	return this->windowsdebugger_step_breakpoint( 
		this->get_breakpoint_from_address( ulAddress ), hThread, &sContext );
}

EVENT_CONTROL WindowsDebugger::windowsdebugger_step_breakpoint( 
	DEBUGGER_BREAKPOINT * lpBp, void * hThread, LPCONTEXT lpContext )
{
	if( lpBp == NULL ) 
		return EVENT_HANDLE;

	lpBp->nTimesHit++;

	dprintflvl( 4, "Breakpoint: %#X (hits: %d) Stepping", lpBp->ulAddress, 
		lpBp->nTimesHit );

	//We've hit a bp that's disabled (probably an INT3 instruction)
	if( lpBp->bEnabled == FALSE ) {
		return EVENT_HANDLE;
	}

	//Disable the breakpoint
	if( this->debugger_disable_breakpoint( lpBp ) == FALSE ) {
		PrintError( "Error disabling breakpoint" );
		return EVENT_NOT_HANDLED;
	}

	//Reduce EIP by size of breakpoint instruction
	lpContext->Eip -= sizeof(lpBpInstruction);

	dprintflvl( 4, "Setting trap" );
	this->windowsdebugger_set_trap_breakpoint( hThread, lpContext );

	//XXX need to make sure what im doing here is thread safe
	dprintflvl( 3, "Continuing last event of this thread" );
	ContinueDebugEvent( this->get_process_id(), 
		(DWORD)this->debugger_get_last_exception_thread(), DBG_CONTINUE );

	DEBUG_EVENT sDbgEvent;

	BOOL bHandledTrap = FALSE;
	while( bHandledTrap == FALSE ) {
		if( WaitForDebugEvent( &sDbgEvent, INFINITE ) == FALSE ) {
			WinError::winerror_print_last_error( __FUNCTION__ );
			return EVENT_NOT_HANDLED;
		}

		dprintflvl( 4, "Got expected Exception with code: %d", 
			sDbgEvent.dwDebugEventCode );

		if( sDbgEvent.dwDebugEventCode == EXCEPTION_DEBUG_EVENT ) {
			if( sDbgEvent.u.Exception.ExceptionRecord.ExceptionCode == 
				EXCEPTION_SINGLE_STEP ) {
					dprintflvl( 5, "Got expected SINGLE_STEP exception at: %#X", 
						sDbgEvent.u.Exception.ExceptionRecord.ExceptionAddress );
					dprintflvl( 5, "Enabling breakpoint" );
					this->debugger_enable_breakpoint( lpBp );
					dprintflvl( 5, "Clearing trap" );
					this->debugger_clear_trap_breakpoint( hThread );
					bHandledTrap = TRUE;
					//ContinueDebugEvent( sDbgEvent.dwProcessId, 
						//sDbgEvent.dwThreadId, DBG_CONTINUE );
					return EVENT_HANDLE;
			}
			else {
				dprintflvl( 4, "Unexpected breakpoint event, continuing" );
				ContinueDebugEvent( sDbgEvent.dwProcessId, sDbgEvent.dwThreadId, 
					DBG_CONTINUE );
			}
		}
		else {
			dprintflvl( 4, "Skipping unexpected event" );
			ContinueDebugEvent( sDbgEvent.dwProcessId, sDbgEvent.dwThreadId, 
				DBG_EXCEPTION_NOT_HANDLED );
			//return FALSE;
		}
	}
}

BOOL WindowsDebugger::debugger_enable_breakpoint( unsigned long ulAddress )
{
	return this->debugger_enable_breakpoint( 
		this->get_breakpoint_from_address( ulAddress ) );
}

BOOL WindowsDebugger::debugger_enable_breakpoint( DEBUGGER_BREAKPOINT * lpBp )
{
	if( lpBp == NULL ) return FALSE;
	if( lpBp->bEnabled == TRUE ) return TRUE;

	IMemory * lpMemory = this->windowsdebugger_get_proc_memory();

	if( lpMemory->memory_write_to_address( this->nProcessId, 
		(void *)lpBp->ulAddress, lpBpInstruction, sizeof(lpBpInstruction) ) == 
		FALSE ) {
			PrintError( "Error enabling breakpoint at %#X", lpBp->ulAddress );
			return FALSE;
	}

	FlushInstructionCache( this->hProcess, (LPCVOID)lpBp->ulAddress, 
		sizeof( lpBpInstruction ) );

	lpBp->bEnabled = TRUE;
	return TRUE;
}


EVENT_CONTROL WindowsDebugger::exception_event( DEBUG_EVENT * lpEvent )
{
	this->lpsExceptionSignal = new ExceptionSignal();
	this->populate_exceptionsignal( lpsExceptionSignal, lpEvent );

	if( this->lpsExceptionSignal->get_exception_code() == ICARUS_BREAKPOINT ) {
			BOOL bBpContinue = FALSE;
			if( this->lpBreakpointICallback != NULL ) {
				dprintflvl( 4, "Calling ICallback breakpoint handler at %#X", 
					this->lpBreakpointICallback );
				bBpContinue = this->lpBreakpointICallback->fbCallback( 
					this->lpsExceptionSignal );
			}
			else if( this->lpBreakpointCallback != NULL ) {
				dprintflvl( 4, "Calling native breakpoint handler at %#X", 
					this->lpBreakpointCallback );
				bBpContinue = this->lpBreakpointCallback( (IDebugger *)this, 
					this->lpsExceptionSignal );
			}
			if( bBpContinue == EVENT_HANDLE ) {
				dprintflvl( 4, "Got signal to continue execution" );
				void * hThread;
				if( ( hThread = (void *)OpenThread( THREAD_GET_CONTEXT + 
					THREAD_SET_CONTEXT + THREAD_QUERY_INFORMATION, FALSE, 
					lpEvent->dwThreadId ) ) == NULL ) {
						WinError::winerror_print_last_error( __FUNCTION__ );
						return EVENT_HANDLE;
				}

				if( this->debugger_step_breakpoint( 
					(unsigned long)lpEvent->u.Exception.ExceptionRecord.ExceptionAddress, 
					hThread ) == EVENT_NOT_HANDLED ) {
						dprintflvl( 4, "Unable to step bp, we didn't set it");
						//Attempt to pass through it
						return EVENT_HANDLE;
				}

				CloseHandle( (HANDLE)hThread );
				return EVENT_HANDLE;
			}
	}
	if( this->lpExceptionICallback != NULL ) {
		return (EVENT_CONTROL)this->lpExceptionICallback->fbCallback( 
			this->lpsExceptionSignal );
	}
	else if( this->lpExceptionCallback != NULL ) {
		return this->lpExceptionCallback( (IDebugger *)this, 
			this->lpsExceptionSignal );

	}
	return EVENT_NOT_HANDLED;
}

EVENT_CONTROL WindowsDebugger::createprocess_event( DEBUG_EVENT * lpEvent )
{
	if( this->bGotCreateProcess == FALSE ) {
		dprintflvl( 4, "Got initial CREATE_PROCESS_DEBUG_EVENT" );
		if( this->hProcess == NULL ) {
			this->hProcess = sDebugEvent.u.CreateProcessInfo.hProcess;
		}
		this->bGotCreateProcess = TRUE;
	}
	return EVENT_HANDLE;
}

EVENT_CONTROL WindowsDebugger::exit_process_event( DEBUG_EVENT * lpEvent )
{
	this->lpsExceptionSignal = new ExceptionSignal();
	if( this->lpTerminationCallback != NULL || 
		this->lpTerminationICallback != NULL ) {
			this->lpsExceptionSignal->set_continuable( FALSE );
			this->lpsExceptionSignal->set_process_id( lpEvent->dwProcessId );
			this->lpsExceptionSignal->set_thread_id( lpEvent->dwThreadId );
			this->lpsExceptionSignal->set_process_exit_code( 
				lpEvent->u.ExitProcess.dwExitCode );
		if( this->lpTerminationICallback != NULL ) {
			return (EVENT_CONTROL)this->lpTerminationICallback->fbCallback( 
				this->lpsExceptionSignal );
		}
		else if( this->lpTerminationCallback != NULL ) {
			return this->lpTerminationCallback( (IDebugger *)this, 
				this->lpsExceptionSignal );
		}
			
	}
	return EVENT_HANDLE;
}

EVENT_CONTROL WindowsDebugger::exit_thread_event( DEBUG_EVENT * lpEvent )
{
	dprintflvl( 4, "Thread Exited: %#X (%d) with %#X", lpEvent->dwThreadId, 
		lpEvent->dwThreadId, lpEvent->u.ExitThread.dwExitCode );
	return EVENT_HANDLE;
}

BOOL WindowsDebugger::populate_exceptionsignal( ExceptionSignal * lpException, 
	DEBUG_EVENT * lpEvent )
{
	EXCEPTION_RECORD * lpExceptionRecord = &lpEvent->u.Exception.ExceptionRecord;

	lpException->set_process_id( lpEvent->dwProcessId );
	lpException->set_thread_id( lpEvent->dwThreadId );
	lpException->set_encountered_before( 
		( lpEvent->u.Exception.dwFirstChance ) ? FALSE : TRUE );
	lpException->set_exception_address( lpExceptionRecord->ExceptionAddress );
	
	if( lpExceptionRecord->ExceptionFlags == EXCEPTION_NONCONTINUABLE || 
		lpExceptionRecord->ExceptionFlags == EXCEPTION_NONCONTINUABLE_EXCEPTION ) {
			lpException->set_continuable( FALSE );
	}
	else {
		lpException->set_continuable( TRUE );
	}

	switch( lpExceptionRecord->ExceptionCode ) {
	case EXCEPTION_ACCESS_VIOLATION: 
		lpException->set_exception_code( ICARUS_ACCESS_VIOLATION );
		break;
	case EXCEPTION_DATATYPE_MISALIGNMENT: 
		lpException->set_exception_code( ICARUS_DATATYPE_MISALIGNMENT );
		break;
	case EXCEPTION_BREAKPOINT: 
		lpException->set_exception_code( ICARUS_BREAKPOINT );
		break;
	case EXCEPTION_SINGLE_STEP: 
		lpException->set_exception_code( ICARUS_SINGLE_STEP );
		break;
	case EXCEPTION_ARRAY_BOUNDS_EXCEEDED: 
		lpException->set_exception_code( ICARUS_ARRAY_BOUNDS_EXCEEDED );
		break;
	case EXCEPTION_FLT_DENORMAL_OPERAND: 
		lpException->set_exception_code( ICARUS_FLT_DENORMAL_OPERAND );
		break;
	case EXCEPTION_FLT_DIVIDE_BY_ZERO: 
		lpException->set_exception_code( ICARUS_FLT_DIVIDE_BY_ZERO );
		break;
	case EXCEPTION_FLT_INEXACT_RESULT: 
		lpException->set_exception_code( ICARUS_FLT_INEXACT_RESULT );
		break;
	case EXCEPTION_FLT_INVALID_OPERATION: 
		lpException->set_exception_code( ICARUS_FLT_INVALID_OPERATION );
		break;
	case EXCEPTION_FLT_OVERFLOW: 
		lpException->set_exception_code( ICARUS_FLT_OVERFLOW );
		break;
	case EXCEPTION_FLT_STACK_CHECK: 
		lpException->set_exception_code( ICARUS_FLT_STACK_CHECK );
		break;
	case EXCEPTION_FLT_UNDERFLOW: 
		lpException->set_exception_code( ICARUS_FLT_UNDERFLOW );
		break;
	case EXCEPTION_INT_DIVIDE_BY_ZERO: 
		lpException->set_exception_code( ICARUS_INT_DIVIDE_BY_ZERO );
		break;
	case EXCEPTION_INT_OVERFLOW: 
		lpException->set_exception_code( ICARUS_INT_OVERFLOW );
		break;
	case EXCEPTION_PRIV_INSTRUCTION: 
		lpException->set_exception_code( ICARUS_PRIV_INSTRUCTION );
		break;
	case EXCEPTION_IN_PAGE_ERROR: 
		lpException->set_exception_code( ICARUS_IN_PAGE_ERROR );
		break;
	case EXCEPTION_ILLEGAL_INSTRUCTION: 
		lpException->set_exception_code( ICARUS_ILLEGAL_INSTRUCTION );
		break;
	case EXCEPTION_NONCONTINUABLE_EXCEPTION: 
		lpException->set_exception_code( ICARUS_NONCONTINUABLE_EXCEPTION );
		break;
	case EXCEPTION_STACK_OVERFLOW: 
		lpException->set_exception_code( ICARUS_STACK_OVERFLOW );
		break;
	case EXCEPTION_INVALID_DISPOSITION: 
		lpException->set_exception_code( ICARUS_INVALID_DISPOSITION );
		break;
	case EXCEPTION_GUARD_PAGE: 
		lpException->set_exception_code( ICARUS_GUARD_PAGE );
		break;
	case EXCEPTION_INVALID_HANDLE: 
		lpException->set_exception_code( ICARUS_INVALID_HANDLE );
		break;
	case EXCEPTION_POSSIBLE_DEADLOCK: 
		lpException->set_exception_code( ICARUS_POSSIBLE_DEADLOCK );
		break;
	case CONTROL_C_EXIT: 
		lpException->set_exception_code( ICARUS_CONTROL_C );
		break;
	}

	lpException->set_extra_info( lpExceptionRecord );

	return TRUE;
}

void WindowsDebugger::debugger_set_exception_handler( ICallback * lpCallback )
{
	this->lpExceptionICallback = lpCallback;
}
void WindowsDebugger::debugger_set_breakpoint_handler( ICallback * lpCallback )
{
	this->lpBreakpointICallback = lpCallback;
}
void WindowsDebugger::debugger_set_termination_handler( ICallback * lpCallback )
{
	this->lpTerminationICallback = lpCallback;
}



typedef enum _DEBUG_CONTROL_CODE {

	DebugSysGetTraceInformation=1,
	DebugSysSetInternalBreakpoint,
	DebugSysSetSpecialCall,
	DebugSysClerSpecialCalls, 
	DebugSysQuerySpecialCalls,
	DebugSysBreakpointWithStatus,
	DebugSysGetVersion,
	DebugSysReadVirtual = 8, 
	DebugSysWriteVirtual = 9,
	DebugSysReadPhysical = 10,
	DebugSysWritePhysical = 11, 
	DebugSysReadControlSpace=12,
	DebugSysWriteControlSpace,
	DebugSysReadIoSpace,
	DebugSysSysWriteIoSpace,
	DebugSysReadMsr,
	DebugSysWriteMsr,
	DebugSysReadBusData,
	DebugSysWriteBusData,
	DebugSysCheckLowMemory,
} DEBUG_CONTROL_CODE;

typedef struct {
	ULONG Address;
	ULONGLONG * Data;
} SYSDBG_MSR;

#define IA32_DEBUGCTL 0x1D9

/*
LBR (last branch/interrupt/exception) flag (bit 0) — When set, the processor records a running trace of
the most recent branches, interrupts, and/or exceptions taken by the processor (prior to a debug exception
being generated) in the last branch record (LBR) stack. For more information, see the Section 17.5.1, “LBR
Stack” (Intel® Core™2 Duo and Intel® Atom™ Processor Family) and Section 17.6.1, “LBR Stack” (processors
based on Intel® Microarchitecture code name Nehalem).

BTF (single-step on branches) flag (bit 1) — When set, the processor treats the TF flag in the EFLAGS
register as a “single-step on branches” flag rather than a “single-step on instructions” flag. This mechanism
allows single-stepping the processor on taken branches. See Section 17.4.3, “Single-Stepping on Branches,”
for more information about the BTF flag.

Note that AMD+Intel define LBR BTF as being the same. Other flags are different
*/
typedef enum {
	LBR = 0x00000001,
	BTF = 0x00000002
} IA32_DBGCTL_FLAGS;

//XXX WARNING these are set on AMD and Intel P6 (on older and different arch eg Xeon are different)
#define LastBranchFromIP 0x1DB
#define LastBranchToIP 0x1DC

typedef NTSTATUS ( WINAPI * NtSystemDebugControl ) ( DEBUG_CONTROL_CODE Command,
	PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer,
	ULONG OutputBufferLength, PULONG ReturnLength );

BOOL WindowsDebugger::debugger_enable_branch_logging( void * hThread )
{

	this->debugger_set_trap_breakpoint( hThread );
	SYSDBG_MSR lpsMSR;
	lpsMSR.Address = 0x1D9;
	ULONGLONG Flagval = BTF;
	lpsMSR.Data = &Flagval;
	SYSDBG_MSR * lpsOldMSR = new SYSDBG_MSR();
	NtSystemDebugControl fNtSystemDebugControl = NULL;

	fNtSystemDebugControl = (NtSystemDebugControl)GetProcAddress( 
		LoadLibraryA("ntdll.dll"), "NtSystemDebugControl" );
	NTSTATUS status; 
	status = fNtSystemDebugControl( DebugSysReadMsr, &lpsMSR, sizeof( SYSDBG_MSR ), 
		&lpsMSR, sizeof(lpsMSR), 0 );
	
	dprintflvl( 3, "Status %#X", status );
	
	/*//Restore MSR
	status = fNtSystemDebugControl( DebugSysWriteMsr, lpsOldMSR, sizeof( SYSDBG_MSR ), 
		lpsMSR, sizeof( SYSDBG_MSR ), 0 );*/

	return TRUE;
}

BOOL WindowsDebugger::debugger_set_trap_on_branch()
{
	SYSDBG_MSR * lpsMsr = new SYSDBG_MSR();
	NtSystemDebugControl fNtSystemDebugControl = NULL;
	lpsMsr->Address = 0x1D9; //XXX this is processor specific
	ULONGLONG val = 2;
	lpsMsr->Data = &val;

	fNtSystemDebugControl = (NtSystemDebugControl)GetProcAddress( 
		LoadLibraryA("ntdll.dll"), "NtSystemDebugControl" );

	fNtSystemDebugControl( DebugSysWriteMsr, lpsMsr, sizeof( SYSDBG_MSR ), 
		lpsMsr, sizeof( SYSDBG_MSR ), 0 );

	return TRUE;
}