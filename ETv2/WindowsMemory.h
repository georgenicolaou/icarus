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
#include "IMemory.h"
#include "MemoryPage.h"
#include "ThreadStack.h"
#include "ImageHeaderMemory.h"

class WindowsMemory : public IMemory
{
public:
	WindowsMemory(void);
	~WindowsMemory(void);
	virtual BOOL memory_map_process_memory( int nProcessId );
	virtual void * get_min_allowed_memory_address( void );
	virtual void * get_max_allowed_memory_address( void );
	virtual void set_min_allowed_memory_address( void * lpvMinimumMemAddr );
	virtual void set_max_allowed_memory_address( void * lpvMaximumMemAddr );
	virtual BOOL memory_get_address_contents( int nProcessId, void * vpAddress, 
		unsigned long ulSize, void * vpBuffer );
	virtual BOOL memory_write_to_address( int nProcessId, void * vpAddress, 
		void * vpData, unsigned long ulDataSize );
	virtual BOOL memory_get_proc_heaps( vector<MemoryPage*> * vHeaps,
		int nProcessId );
	virtual BOOL memory_get_proc_stacks( vector<ThreadStack*> * vStack,
		int nProcessId, int nThreadId );
	virtual BOOL memory_get_memory_page_contents( int nProcessId, 
		MemoryPage * pMemoryPage, void * vpBuffer, int nBufferSize );
	virtual BOOL memory_get_module_headers( 
		vector<ImageHeaderMemory*> * vModuleHeaders, int nProcessId );
	virtual BOOL memory_is_valid_code_address( int nProcessId, 
		void * vpAddress );
	virtual BOOL memory_is_valid_write_address( int nProcessId, 
		void * vpAddress );
	virtual BOOL memory_is_valid_read_address( int nProcessId, 
		void * vpAddress );
	virtual vector<MemoryPage*> memory_get_memory_pages();
	virtual BOOL memory_get_non_image_executable_sections( vector<MemoryPage*> *
		lpvExecutableSections );
	virtual void * memory_get_process_id( void );
	virtual void memory_set_process_id( void * vpProcessId );
	virtual int memory_get_default_page_size();
	virtual int memory_get_max_page_alloc_size();

	void windowsmemory_parse_protect( DWORD dwProtect, 
		MemoryPage * cMemoryPage );
	void * windowsmemory_get_remote_peb_address( void * hProcess );
	BOOL windowsmemory_get_remote_proc_threads( vector<DWORD> * vdwThreads,
		int nProcessId );
	void * windowsmemory_get_remote_thread_teb( void * hThread );

private:
	void * lpvMinimumMemAddr;
	void * lpvMaximumMemAddr;
	int nPageSize;
	int nMaxAllocPageSize;
	void * hProcess;
	void * hWriteProcess;
	int nProcessIdCurrent;
	vector<MemoryPage*> vlpMemoryPages;
	vector<ThreadStack*> vlpThreadStacks;
};

