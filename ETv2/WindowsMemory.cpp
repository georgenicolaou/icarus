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

#include "WindowsMemory.h"
#include "WinError.h"
#include "MemoryPage.h"
#include "icarus_include.h"
#include <Windows.h>
#include <TlHelp32.h>
//#include <winternl.h>
#include "windef.h"
#include "ThreadStack.h"
#include "ImageHeaderMemory.h"
#include "DataEncoder.h"

#define INVALID_PROCID -1

WindowsMemory::WindowsMemory(void)
{
	SYSTEM_INFO sSystemInfo;
	GetSystemInfo( &sSystemInfo );
	this->set_min_allowed_memory_address( 
		(void *)sSystemInfo.lpMinimumApplicationAddress );
	this->set_max_allowed_memory_address( 
		(void *)sSystemInfo.lpMaximumApplicationAddress );
	this->nPageSize = sSystemInfo.dwPageSize;
	this->nMaxAllocPageSize = sSystemInfo.dwPageSize - 76; //bah, don't ask how.
	this->nProcessIdCurrent = INVALID_PROCID;
	this->hProcess = NULL;
	this->hWriteProcess = NULL;
}


WindowsMemory::~WindowsMemory(void)
{
}

void * WindowsMemory::get_min_allowed_memory_address( void )
{
	return this->lpvMinimumMemAddr;
}

void * WindowsMemory::get_max_allowed_memory_address( void )
{
	return this->lpvMaximumMemAddr;
}

void WindowsMemory::set_min_allowed_memory_address( void * lpvMinimumMemAddr )
{
	this->lpvMinimumMemAddr = lpvMinimumMemAddr;
}

void WindowsMemory::set_max_allowed_memory_address( void * lpvMaximumMemAddr )
{
	this->lpvMaximumMemAddr = lpvMaximumMemAddr;
}

BOOL WindowsMemory::memory_get_address_contents( int nProcessId, void * vpAddress, 
	unsigned long ulSize, void * vpBuffer )
{
	SIZE_T stNoBytesRead = NULL;

	if( this->nProcessIdCurrent != nProcessId || this->hProcess == NULL ) {
		this->nProcessIdCurrent = nProcessId;
		if( ( hProcess = OpenProcess( PROCESS_QUERY_INFORMATION + 
			PROCESS_VM_READ, FALSE, (DWORD)nProcessId ) ) == NULL ) {
				WinError::winerror_print_last_error( __FUNCTION__ 
					": Error Opening Process" );
				return FALSE;
		}
	}
	if( !ReadProcessMemory( hProcess,  vpAddress, vpBuffer, ulSize,
		&stNoBytesRead ) ) {
			WinError::winerror_print_last_error( __FUNCTION__ "Read Memory Error" );
			return FALSE;
	}
	this->nProcessIdCurrent = nProcessId;
	return TRUE;
}

BOOL WindowsMemory::memory_write_to_address( int nProcessId, void * vpAddress, 
	void * vpData, unsigned long ulDataSize )
{
	if( this->nProcessIdCurrent != nProcessId || this->hWriteProcess == NULL ) {

		this->nProcessIdCurrent = nProcessId;
		if( this->hWriteProcess != NULL ) {
			CloseHandle( this->hWriteProcess );
			this->hWriteProcess = NULL;
		}

		if( ( this->hWriteProcess = OpenProcess( PROCESS_VM_OPERATION + 
			PROCESS_VM_READ+PROCESS_VM_WRITE, FALSE, (DWORD)nProcessId ) ) == 
			NULL ) {
				WinError::winerror_print_last_error( __FUNCTION__ 
					": Error Opening Process for Writing" );
				return FALSE;
		}
	}
	
	
	if( !WriteProcessMemory( this->hWriteProcess, vpAddress, vpData, ulDataSize, 
		NULL ) ) {
			WinError::winerror_print_last_error( __FUNCTION__ 
				": Error writing to process" );
			return FALSE;
	}

	return TRUE;
}


BOOL WindowsMemory::memory_map_process_memory( int nProcessId )
{
	void * lpvAddress = NULL;
	MEMORY_BASIC_INFORMATION sMemBasicInfo;
	MemoryPage * lpcMemoryPage;

	if( this->vlpMemoryPages.size() != 0 && nProcessId == 
		this->nProcessIdCurrent ) {
			return TRUE;
	}

	if( ( hProcess = OpenProcess( PROCESS_QUERY_INFORMATION + PROCESS_VM_READ, 
		FALSE, (DWORD)nProcessId ) ) == NULL ) {
			WinError::winerror_print_last_error( __FUNCTION__ 
				" Unable to OpenProcess " );
			return FALSE;
	}
	
	while( lpvAddress < lpvMaximumMemAddr ) {
		if( VirtualQueryEx( hProcess, lpvAddress, 
			&sMemBasicInfo, sizeof( MEMORY_BASIC_INFORMATION ) ) ) {
				lpvAddress = (void *)( (unsigned long)sMemBasicInfo.BaseAddress
					+ sMemBasicInfo.RegionSize );
				dprintflvl( 3, "\nAllocationBase: %08X\nAllocationProtect:"
					" %08X\nBaseAddress: %08X\nProtect: %08X\n"
					"RegionSize: %08X\nState: %08X\nType: %08X\n", 
					sMemBasicInfo.AllocationBase, 
					sMemBasicInfo.AllocationProtect, sMemBasicInfo.BaseAddress, 
					sMemBasicInfo.Protect, sMemBasicInfo.RegionSize, 
					sMemBasicInfo.State, sMemBasicInfo.Type );

				switch( sMemBasicInfo.State ) {
					case MEM_COMMIT:
						lpcMemoryPage = new ImageHeaderMemory(); //XXX new MemoryPage();
						lpcMemoryPage->set_attribute_commit();
						break;
					case MEM_FREE:
					case MEM_RESERVE:
					default:
						continue;
				}

				lpcMemoryPage->set_allocation_baseaddress( 
					sMemBasicInfo.AllocationBase );
				lpcMemoryPage->set_baseaddress( sMemBasicInfo.BaseAddress );
				lpcMemoryPage->set_page_size( sMemBasicInfo.RegionSize );
				this->windowsmemory_parse_protect( sMemBasicInfo.Protect, 
					lpcMemoryPage );

				if( sMemBasicInfo.Type & MEM_IMAGE )
					lpcMemoryPage->set_attribute_image();
				if( sMemBasicInfo.Type & MEM_MAPPED )
					lpcMemoryPage->set_attribute_mapped();
				if( sMemBasicInfo.Type & MEM_PRIVATE )
					lpcMemoryPage->set_attribute_private();
				lpcMemoryPage->set_process_id( nProcessId );
				this->vlpMemoryPages.push_back( lpcMemoryPage );
		}
		else {
			WinError::winerror_print_last_error( __FUNCTION__ );
			return FALSE;
		}
	}
	this->nProcessIdCurrent = nProcessId;
	return TRUE;	
}

void WindowsMemory::windowsmemory_parse_protect( DWORD dwProtect, 
	MemoryPage * lpcMemoryPage )
{
	if( dwProtect == PAGE_GUARD ) {
		lpcMemoryPage->set_attribute_guard();
		return;
	}
	if( dwProtect & PAGE_EXECUTE || dwProtect & PAGE_EXECUTE_READ || 
		dwProtect & PAGE_EXECUTE_WRITECOPY || 
		dwProtect & PAGE_EXECUTE_READWRITE ) {
			lpcMemoryPage->set_attribute_execute();
	}
	if( dwProtect & PAGE_EXECUTE_READ || dwProtect & PAGE_EXECUTE_READWRITE || 
		dwProtect & PAGE_READONLY || dwProtect & PAGE_READWRITE  ) {
			lpcMemoryPage->set_attribute_read();
	}
	if( dwProtect & PAGE_EXECUTE_READWRITE || 
		dwProtect & PAGE_EXECUTE_WRITECOPY || dwProtect & PAGE_READWRITE || 
		dwProtect & PAGE_WRITECOPY || dwProtect & PAGE_WRITECOMBINE ) {
			lpcMemoryPage->set_attribute_write();
	}
}

void * WindowsMemory::windowsmemory_get_remote_peb_address( void * hProcess )
{
	PROCESS_BASIC_INFORMATION sProcBasicInfo;
	unsigned long ulReturn;
	FNtQueryInformationProcess pNtQueryInformationProcess = NULL;

	if( ( pNtQueryInformationProcess = (FNtQueryInformationProcess)
		GetProcAddress( LoadLibrary("ntdll.dll"), "NtQueryInformationProcess") )
		== NULL ) {
			WinError::winerror_print_last_error( __FUNCTION__ );
			return NULL;
	}

	if( pNtQueryInformationProcess( hProcess, ProcessBasicInformation, 
		&sProcBasicInfo, sizeof(PROCESS_BASIC_INFORMATION), &ulReturn ) 
		== NULL ) {
			return sProcBasicInfo.PebBaseAddress;
	}
	else {
		return NULL;
	}
}

BOOL WindowsMemory::memory_get_proc_heaps( vector<MemoryPage*> * vHeaps,
	int nProcessId )
{
	void * vpRemotePebAddress = NULL;
	PEB sPeb = {0};
	PPVOID lplpHeaps = NULL;
	MemoryPage * cMemoryPage;
	int i;

	if( this->vlpMemoryPages.size() == 0 ) {
		this->memory_map_process_memory( nProcessId );
	}

	if( nProcessId != this->nProcessIdCurrent ) { 
		if( ( hProcess = OpenProcess( PROCESS_QUERY_INFORMATION + 
			PROCESS_VM_READ, FALSE, (DWORD)nProcessId ) ) == NULL ) {
				WinError::winerror_print_last_error( __FUNCTION__ );
				return FALSE;
		}
	}

	if( ( vpRemotePebAddress = this->windowsmemory_get_remote_peb_address( 
		hProcess ) ) == NULL ) {
			return FALSE;
	}
	
	dprintflvl( 3, "PID: %d &PEB: %08X", nProcessId, vpRemotePebAddress );

	if( this->memory_get_address_contents( nProcessId, vpRemotePebAddress, sizeof(PEB),
		&sPeb ) == FALSE ) {
			WinError::winerror_print_error( __FUNCTION__ );
			return FALSE;
	}

	
	if( ( lplpHeaps = (PPVOID)calloc( sizeof( PVOID ), 
		sPeb.NumberOfHeaps ) ) == NULL ) {
			WinError::winerror_print_error( __FUNCTION__ ": Allocation error");
			dprintflvl( 3, "Allocation error");
	}

	if( this->memory_get_address_contents( nProcessId, sPeb.ProcessHeaps, 
		sizeof( PVOID ) * sPeb.NumberOfHeaps, lplpHeaps ) == FALSE ) {
			WinError::winerror_print_last_error( __FUNCTION__ );
			return FALSE;
	}

	for( i = 0; (unsigned long)i < sPeb.NumberOfHeaps; i++ ) {
		dprintflvl( 3, "Heap at: %08X", lplpHeaps[i] );
		if( ( cMemoryPage = this->memory_find_memory_page_addr( 
			this->vlpMemoryPages, lplpHeaps[i] ) ) != NULL ) {
				cMemoryPage->set_usage_heap();
				vHeaps->push_back( cMemoryPage );
				dprintflvl( 3, "MemoryPage identified");
		}
		else {
			WinError::winerror_print_error( "Heap is not a page?" );
			dprintflvl( 3, "Cannot match heap address to page: %08X", 
				lplpHeaps[i] );
		}
	}

	this->nProcessIdCurrent = nProcessId;
	return TRUE;
}

BOOL WindowsMemory::windowsmemory_get_remote_proc_threads( 
	vector<DWORD> *vdwThreads, int nProcessId )
{
	HANDLE hSnapshot = NULL;
	THREADENTRY32 sThreadEntry = { sizeof(THREADENTRY32) };

	if( ( hSnapshot = CreateToolhelp32Snapshot( TH32CS_SNAPTHREAD, NULL ) ) 
		== INVALID_HANDLE_VALUE ) {
			WinError::winerror_print_last_error( __FUNCTION__ );
			return FALSE;
	}

	if( !Thread32First( hSnapshot, &sThreadEntry ) ) {
		WinError::winerror_print_last_error( __FUNCTION__ );
		return FALSE;
	}

	do {
		if( sThreadEntry.th32OwnerProcessID == (DWORD)nProcessId ) {
			vdwThreads->push_back( sThreadEntry.th32ThreadID );
		}
	} while( Thread32Next( hSnapshot, &sThreadEntry ) );

	return TRUE;
}

void * WindowsMemory::windowsmemory_get_remote_thread_teb( void * hThread )
{
	THREAD_BASIC_INFORMATION sThreadBasicInfo = {0};
	unsigned long ulReturn = NULL;
	FNtQueryInformationThread pNtQueryInformationThread = NULL;

	if( ( pNtQueryInformationThread = (FNtQueryInformationThread)GetProcAddress(
		LoadLibrary("ntdll.dll"), "NtQueryInformationThread" ) ) == NULL ) {
			WinError::winerror_print_last_error( __FUNCTION__ );
			return NULL;
	}

	if( pNtQueryInformationThread( hThread, ThreadBasicInformation, 
		&sThreadBasicInfo, sizeof(THREAD_BASIC_INFORMATION), &ulReturn ) 
		== NULL ) {
			return sThreadBasicInfo.TebBaseAddress;
	}
	else {
		WinError::winerror_print_last_error( __FUNCTION__ );
		return NULL;
	}
}

BOOL WindowsMemory::memory_get_proc_stacks( vector<ThreadStack*> * vStack,
	int nProcessId, int nThreadId )
{
	vector<DWORD> vThreads;
	int i;
	void * hThread;
	void * vpRemoteThreadTebAddr;
	TEB sTeb;
	MemoryPage * lpMemoryPage;
	ThreadStack * lpThreadStack;

	if( this->vlpThreadStacks.size() != 0 && this->nProcessIdCurrent == 
		nProcessId ) {
			for( i = 0; i < (int)this->vlpThreadStacks.size(); i++ ) {
				vStack->push_back( this->vlpThreadStacks[i] );
			}
			return TRUE;
	}
	if( this->windowsmemory_get_remote_proc_threads( &vThreads, nProcessId ) 
		== FALSE) {
			WinError::winerror_print_error( "Unable to get remote threads");
			return FALSE;
	}

	if( this->vlpMemoryPages.size() == 0 ) {
		if( this->memory_map_process_memory( nProcessId ) == FALSE ) {
			return FALSE;
		}
	}
	
	for( i = 0; i < (int)vThreads.size(); i++ ) {
		if( nThreadId != ALL_THREADS ) {
			if( nThreadId != vThreads[i] ) continue;
		}
		if( ( hThread = OpenThread( THREAD_QUERY_INFORMATION, FALSE, 
			vThreads[i] ) ) == NULL ) {
				WinError::winerror_print_last_error( __FUNCTION__ );
				return FALSE;
		}

		if( ( vpRemoteThreadTebAddr = this->windowsmemory_get_remote_thread_teb(
			hThread ) ) == NULL ) {
				WinError::winerror_print_error( "Unable to get Thread's TEB" );
				return FALSE;
		}

		if( this->memory_get_address_contents( nProcessId, vpRemoteThreadTebAddr, 
			sizeof(TEB), &sTeb ) == FALSE ) {
				WinError::winerror_print_error( "Error getting contents" );
				return FALSE;
		}

		if( ( lpMemoryPage = this->memory_find_memory_page_addr( vlpMemoryPages,
			sTeb.Tib.StackLimit ) ) != NULL ) {
				lpThreadStack = static_cast<ThreadStack *>(lpMemoryPage);
				lpThreadStack->set_stack_thread_id( vThreads[i] );
				this->vlpThreadStacks.push_back( lpThreadStack );
				vStack->push_back( lpThreadStack );
		}
		CloseHandle( hThread );
	}
	return TRUE;
}

BOOL WindowsMemory::memory_get_memory_page_contents( int nProcessId, 
	MemoryPage * pMemoryPage, void * vpBuffer, int nBufferSize )
{
	if( (int)pMemoryPage->get_page_size() > nBufferSize ) {
		dprintflvl( 1, "Buffer too small, stop being naughty!" );
		return FALSE;
	}

	if( this->memory_get_address_contents(nProcessId, pMemoryPage->get_baseaddress(),
		pMemoryPage->get_page_size(), vpBuffer ) == TRUE ) {
			return TRUE;
	}
	else {
		return FALSE;
	}
}

BOOL WindowsMemory::memory_get_module_headers( 
	vector<ImageHeaderMemory*> * vModuleHeaders, int nProcessId )
{
	PEB sPeb = {0};
	PEB_LDR_DATA sLoaderData = {0};
	LDR_DATA_TABLE_ENTRY sLoaderDataEntry = {0};
	PLDR_DATA_TABLE_ENTRY psLoaderDataEntryStart;
	PLDR_DATA_TABLE_ENTRY psLoaderDataEntryCurrent;
	void * vpPebAddress;
	ImageHeaderMemory * sImgHeaderMemory;
	wchar_t * lpwcImageName;
	wchar_t * lpwcImageFullName;
	MemoryPage * lpMemoryPage;
	
	if( nProcessId == NULL && this->nProcessIdCurrent != INVALID_PROCID ) {
		nProcessId = this->nProcessIdCurrent;
	}
// 	else {
// 		return FALSE;
// 	}

	if( this->vlpMemoryPages.size() == 0 ) {
		this->memory_map_process_memory( nProcessId );
	}

	if( nProcessId != this->nProcessIdCurrent ) { 
		if( ( hProcess = OpenProcess( PROCESS_QUERY_INFORMATION + 
			PROCESS_VM_READ, FALSE, (DWORD)nProcessId ) ) == NULL ) {
				WinError::winerror_print_last_error( __FUNCTION__ );
				return FALSE;
		}
		this->hProcess = hProcess;
		this->nProcessIdCurrent = nProcessId;
	}
	else {
		hProcess = this->hProcess;
	}
	
	if( ( vpPebAddress = this->windowsmemory_get_remote_peb_address( hProcess )
		) == NULL ) {
			return FALSE;
	}

	if( this->memory_get_address_contents( nProcessId, vpPebAddress,
		sizeof(PEB), &sPeb ) == FALSE ) {
			dprintflvl( 1, "Error getting PEB for PID %d", nProcessId );
			return FALSE;
	}

	if( this->memory_get_address_contents( nProcessId, sPeb.LoaderData, 
		sizeof(PEB_LDR_DATA), &sLoaderData ) == FALSE ) {
			dprintflvl( 1, "Error getting Ldr for PID %d", nProcessId );
			return FALSE;
	}

	psLoaderDataEntryStart = (PLDR_DATA_TABLE_ENTRY)
		sLoaderData.InLoadOrderModuleList.Flink;

	psLoaderDataEntryCurrent = psLoaderDataEntryStart; 
	
	do {
		if( this->memory_get_address_contents( nProcessId, 
			psLoaderDataEntryCurrent, sizeof(LDR_DATA_TABLE_ENTRY), 
			&sLoaderDataEntry ) == FALSE ) {
				dprintflvl( 1, "Error getting LoaderDataEntry" );
				return FALSE;
		}
		
		//XXX Should i?
		if( sLoaderDataEntry.DllBase == NULL ) {
			break;
		}
		//UNICODE_STRING.MaximumLength is in bytes and not wchars
		if( ( lpwcImageName = (wchar_t *)calloc( 
			sLoaderDataEntry.BaseDllName.MaximumLength, sizeof(char) ) ) 
			== NULL ) {
				WinError::winerror_print_error("Allocating Memory");
				return FALSE;
		}

		if( this->memory_get_address_contents( nProcessId, 
			sLoaderDataEntry.BaseDllName.Buffer, 
			sLoaderDataEntry.BaseDllName.Length, lpwcImageName ) == FALSE ) {
				return FALSE;
		}

		if( ( lpwcImageFullName = (wchar_t *)calloc( 
			sLoaderDataEntry.FullDllName.MaximumLength, sizeof( char ) ) ) == 
			NULL ) {
				WinError::winerror_print_error("Allocating Memory");
				return FALSE;
		}

		if( this->memory_get_address_contents( nProcessId, 
			sLoaderDataEntry.FullDllName.Buffer, 
			sLoaderDataEntry.FullDllName.Length, lpwcImageFullName ) == FALSE ) {
				return FALSE;
		}

		vector<MemoryPage*> * lpv;
		if( ( lpMemoryPage = this->memory_find_memory_page_addr( 
			this->vlpMemoryPages, sLoaderDataEntry.DllBase ) ) == NULL ) {
				WinError::winerror_print_error( 
					"Image Base not Found in Memory Map" );
				return FALSE;
		}

		sImgHeaderMemory = static_cast<ImageHeaderMemory*>( lpMemoryPage );

		sImgHeaderMemory->set_image_name( lpwcImageName );
		sImgHeaderMemory->set_image_name_ascii( 
			DataEncoder::wchar_to_ascii( lpwcImageName ) );

		sImgHeaderMemory->set_image_fullname( lpwcImageFullName );
		sImgHeaderMemory->set_image_fullname_ascii( DataEncoder::wchar_to_ascii( 
			lpwcImageFullName ) );

		sImgHeaderMemory->set_image_size( sLoaderDataEntry.SizeOfImage );
		sImgHeaderMemory->set_exe_type( EXE_PE );
		sImgHeaderMemory->set_image_section_name( "PE Header" );

		vModuleHeaders->push_back( sImgHeaderMemory );
		
		psLoaderDataEntryCurrent = (PLDR_DATA_TABLE_ENTRY)
			sLoaderDataEntry.InLoadOrderLinks.Flink;
	} while( psLoaderDataEntryCurrent != psLoaderDataEntryStart );

	return TRUE;
}

BOOL WindowsMemory::memory_is_valid_code_address( int nProcessId, 
	void * vpAddress )
{
	MemoryPage * lpsMemoryPage = NULL;

	if( this->vlpMemoryPages.size() == 0 ) {
		this->memory_map_process_memory( nProcessId );
	}

	if( ( lpsMemoryPage = this->memory_find_memory_page_addr( 
		this->vlpMemoryPages, vpAddress ) ) == NULL ) {
			dprintflvl( 3, "Unable to match address to page" );
			return FALSE;
	}

	return lpsMemoryPage->mem_execute();
}

BOOL WindowsMemory::memory_is_valid_write_address( int nProcessId, 
	void * vpAddress )
{
	MemoryPage * lpsMemoryPage = NULL;

	if( this->vlpMemoryPages.size() == 0 ) {
		this->memory_map_process_memory( nProcessId );
	}

	if( ( lpsMemoryPage = this->memory_find_memory_page_addr( 
		this->vlpMemoryPages, vpAddress ) ) == NULL ) {
			dprintflvl( 3, "Unable to match address to page" );
			return FALSE;
	}

	return lpsMemoryPage->mem_write();
}

BOOL WindowsMemory::memory_is_valid_read_address( int nProcessId, 
	void * vpAddress )
{
	MemoryPage * lpsMemoryPage = NULL;

	if( this->vlpMemoryPages.size() == 0 ) {
		this->memory_map_process_memory( nProcessId );
	}

	if( ( lpsMemoryPage = this->memory_find_memory_page_addr( 
		this->vlpMemoryPages, vpAddress ) ) == NULL ) {
			dprintflvl( 3, "Unable to match address to page" );
			return FALSE;
	}

	return lpsMemoryPage->mem_read();
}

vector<MemoryPage*> WindowsMemory::memory_get_memory_pages()
{
	return this->vlpMemoryPages;
}

BOOL WindowsMemory::memory_get_non_image_executable_sections( 
	vector<MemoryPage*> * lpvExecutableSections )
{
	int i = 0;
	MemoryPage * lpcMemoryPage;
	
	if( this->vlpMemoryPages.size() == 0 ) {
		return FALSE;
	}

	for( i = 0; i < (int)this->vlpMemoryPages.size(); i++ ) {
		lpcMemoryPage = this->vlpMemoryPages[i];
		if( lpcMemoryPage->type_image() == FALSE ) {
			if( lpcMemoryPage->mem_execute() == TRUE ) {
				lpvExecutableSections->push_back( lpcMemoryPage );
				dprintflvl( 3, "Non Image Executable Section Found at 0x%X", 
					lpcMemoryPage->get_baseaddress() );
			}
		}
	}
	
	return TRUE;
}

void * WindowsMemory::memory_get_process_id( )
{
	return (void *)this->nProcessIdCurrent;
}

void WindowsMemory::memory_set_process_id( void * vpProcessId )
{
	this->nProcessIdCurrent = (int)vpProcessId;
}

int WindowsMemory::memory_get_default_page_size()
{
	return this->nPageSize;
}

int WindowsMemory::memory_get_max_page_alloc_size()
{
	return this->nMaxAllocPageSize;
}