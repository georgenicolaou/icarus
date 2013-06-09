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
#include <vector>

#include "icarus_include.h"
#include "Address.h"

typedef enum enum_mem_attributes {
	MEM_NONE	= 0x00000000,
	MEM_READ	= 0x00000002,
	MEM_WRITE	= 0x00000004,
	MEM_EXECUTE = 0x00000008,
	MEM_GUARD	= 0x00000010,

	MEM_STATE_COMMIT	= 0x80000000,
	MEM_STATE_FREE		= 0x40000000,
	MEM_STATE_RESERVED	= 0x20000000,

	MEM_TYPE_IMAGE		= 0x00010000,
	MEM_TYPE_MAPPED		= 0x00020000,
	MEM_TYPE_PRIVATE	= 0x00040000
} MEM_ATTRIBUTES;

typedef enum enum_mem_usage {
	MEM_HEAP	= 0x00000001,
	MEM_STACK	= 0x00000002
} MEM_USAGE;

class LIBEXPORT MemoryPage
{
public:
	MemoryPage(void);
	~MemoryPage(void);

	void set_process_id( int nProcessId );
	void set_allocation_baseaddress( void * lpvAddress );
	void set_baseaddress( void * lpvAddress );
	void set_page_size( unsigned long ulSize );
	void set_memorypage_contents( unsigned char * lpucContents );
	int get_process_id( void );
	void * get_allocation_baseaddress( void );
	void * get_baseaddress( void );
	unsigned long get_page_size( void );
	unsigned char * get_memorypage_contents( void );

	void set_attribute_read( void );
	void set_attribute_write( void );
	void set_attribute_execute( void );
	void set_attribute_guard( void );
	void set_attribute_commit( void );
	void set_attribute_free( void );
	void set_attribute_reserved( void );
	void set_attribute_image( void );
	void set_attribute_mapped( void );
	void set_attribute_private( void );

	BOOL mem_read( void );
	BOOL mem_write( void );
	BOOL mem_execute( void );
	BOOL mem_guard( void );
	BOOL state_commit( void );
	BOOL state_free( void );
	BOOL state_reserved( void );
	BOOL type_image( void );
	BOOL type_mapped( void );
	BOOL type_private( void );

	void set_usage_heap( void );
	void set_usage_stack( void );

	BOOL usage_heap( void );
	BOOL usage_stack( void );

	unsigned char * get_memory_page_contents_buffer( void );
	BOOL allocate_buffer_for_page( void );

	vector<Address*> * get_special_addresses( );
	void add_special_address( Address * lpsAddress );
private:
	void * lpvAllocationBaseAddress; //Address requested by system/program
	void * lpvBaseAddress;
	unsigned long ulPageSize;
	MEM_ATTRIBUTES eMemoryProtections;
	MEM_USAGE eMemoryUsage;
	unsigned char * lpucMemoryPageContents;
	int nProcessId;
	vector<Address*> vpSpecialAddresses;
};

