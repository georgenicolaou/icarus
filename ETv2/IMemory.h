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
#include "MemoryPage.h"
#include "ImageHeaderMemory.h"
#include "ThreadStack.h"

/*
** Argument send to memory_get_proc_stacks. If this is set then the function
** returns all stacks for all threads.
*/
#define ALL_THREADS -1

class LIBEXPORT IMemory
{
public:
	IMemory(void);
	~IMemory(void);
	static unsigned char * memory_ustrstr( unsigned char * lpszHaystack, 
		int nHaystackSize, unsigned char * lpszNiddle, int nNiddleSize );
	
	static MemoryPage * memory_find_memory_page_addr( vector<MemoryPage*>& vMemoryPages, 
		void * vpAddress );
	static ImageHeaderMemory * memory_find_memory_page_addr( vector<ImageHeaderMemory*>& vMemoryPages, 
		void * vpAddress );
	static IMemory * init_get_instance( void );

	static BOOL is_address_in_page( MemoryPage * lpcMemoryPage, 
		void * lvpAddress );

	virtual BOOL memory_map_process_memory( int nProcessId ) = NULL;
	virtual void * get_min_allowed_memory_address( void ) = NULL;
	virtual void * get_max_allowed_memory_address( void ) = NULL;
	virtual void set_min_allowed_memory_address( void * ) = NULL;
	virtual void set_max_allowed_memory_address( void * ) = NULL;
	virtual BOOL memory_get_address_contents( int nProcessId, void * vpAddress, 
		unsigned long ulSize, void * vpBuffer ) = NULL;
	virtual BOOL memory_write_to_address( int nProcessId, void * vpAddress, 
		void * vpData, unsigned long ulDataSize ) = NULL;
	virtual BOOL memory_get_memory_page_contents( int nProcessId, 
		MemoryPage * pMemoryPage, void * vpBuffer, int nBufferSize ) = NULL;
	virtual BOOL memory_get_proc_heaps( vector<MemoryPage*> * vHeaps,
		int nProcessId ) = NULL;
	virtual BOOL memory_get_proc_stacks( vector<ThreadStack*> * vStack,
		int nProcessId, int nThreadId ) = NULL;
	virtual BOOL memory_get_module_headers( 
		vector<ImageHeaderMemory * > * vModuleHeaders, int nProcessId ) = NULL;
	virtual BOOL memory_is_valid_code_address( int nProcessId, 
		void * vpAddress ) = NULL;
	virtual BOOL memory_is_valid_write_address( int nProcessId, 
		void * vpAddress ) = NULL;
	virtual BOOL memory_is_valid_read_address( int nProcessId, 
		void * vpAddress ) = NULL;
	virtual void * memory_get_process_id( ) = NULL;
	virtual void memory_set_process_id( void * vpProcessId ) = NULL;
	//Memory map must be initialized to call these functions
	virtual vector<MemoryPage*> memory_get_memory_pages() = NULL;
	virtual BOOL memory_get_non_image_executable_sections( vector<MemoryPage*> * 
		lpvExecutableSections ) = NULL;
	virtual int memory_get_default_page_size() = NULL;
	virtual int memory_get_max_page_alloc_size() = NULL;
};

