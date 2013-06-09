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

#include "MemoryPage.h"


inline MEM_ATTRIBUTES &operator |=( MEM_ATTRIBUTES &a, const MEM_ATTRIBUTES b )
{
	return a = static_cast<MEM_ATTRIBUTES> 
		( static_cast<int>(a) | static_cast<int>(b) );
}

inline MEM_USAGE &operator |=( MEM_USAGE &a, const MEM_USAGE b )
{
	return a = static_cast<MEM_USAGE> 
		( static_cast<int>(a) | static_cast<int>(b) );
}

MemoryPage::MemoryPage(void)
{
	this->lpvAllocationBaseAddress = NULL;
	this->lpvBaseAddress = NULL;
	this->ulPageSize = 0;
	this->lpucMemoryPageContents = NULL;
	this->eMemoryProtections = MEM_NONE;
	this->eMemoryUsage = (MEM_USAGE) NULL;
}


MemoryPage::~MemoryPage(void)
{
	if( this->lpucMemoryPageContents != NULL ) 
		free( this->lpucMemoryPageContents );
}

void MemoryPage::set_process_id( int nProcessId )
{
	this->nProcessId = nProcessId;
}

void MemoryPage::set_allocation_baseaddress( void * lpvAddress )
{
	this->lpvAllocationBaseAddress = lpvAddress;
}

void MemoryPage::set_baseaddress( void * lpvAddress )
{
	this->lpvBaseAddress = lpvAddress;
}

void MemoryPage::set_page_size( unsigned long ulSize )
{
	this->ulPageSize = ulSize;
}

void MemoryPage::set_memorypage_contents( unsigned char * lpucContents )
{
	this->lpucMemoryPageContents = lpucContents;
}

int MemoryPage::get_process_id( void )
{
	return this->nProcessId;
}

void * MemoryPage::get_allocation_baseaddress( void )
{
	return this->lpvAllocationBaseAddress;
}

void * MemoryPage::get_baseaddress( void )
{
	return this->lpvBaseAddress;
}

unsigned long MemoryPage::get_page_size( void )
{
	return this->ulPageSize;
}

unsigned char * MemoryPage::get_memorypage_contents( void )
{
	return this->lpucMemoryPageContents;
}


void MemoryPage::set_attribute_read( void )
{
	this->eMemoryProtections |= MEM_READ;
}
void MemoryPage::set_attribute_write( void )
{
	this->eMemoryProtections |= MEM_WRITE;
}
void MemoryPage::set_attribute_execute( void )
{
	this->eMemoryProtections |= MEM_EXECUTE;
}

void MemoryPage::set_attribute_guard( void )
{
	this->eMemoryProtections |= MEM_GUARD;
}

void MemoryPage::set_attribute_commit( void )
{
	this->eMemoryProtections |= MEM_STATE_COMMIT;
}

void MemoryPage::set_attribute_free( void )
{
	this->eMemoryProtections |= MEM_STATE_FREE;
}

void MemoryPage::set_attribute_reserved( void )
{
	this->eMemoryProtections |= MEM_STATE_RESERVED;
}

void MemoryPage::set_attribute_image( void )
{
	this->eMemoryProtections |= MEM_TYPE_IMAGE;
}

void MemoryPage::set_attribute_mapped( void )
{
	this->eMemoryProtections |= MEM_TYPE_MAPPED;
}

void MemoryPage::set_attribute_private( void )
{
	this->eMemoryProtections |= MEM_TYPE_PRIVATE;
}



BOOL MemoryPage::mem_read( void ) {
	FlagCheck( this->eMemoryProtections, MEM_READ );
}

BOOL MemoryPage::mem_write( void ) {
	FlagCheck( this->eMemoryProtections, MEM_WRITE );
}

BOOL MemoryPage::mem_execute( void ) {
	FlagCheck( this->eMemoryProtections, MEM_EXECUTE );
}

BOOL MemoryPage::mem_guard( void ) {
	FlagCheck( this->eMemoryProtections, MEM_GUARD );
}

BOOL MemoryPage::state_commit( void ) {
	FlagCheck( this->eMemoryProtections, MEM_STATE_COMMIT );
}

BOOL MemoryPage::state_free( void ) {
	FlagCheck( this->eMemoryProtections, MEM_STATE_FREE );
}

BOOL MemoryPage::state_reserved( void ) {
	FlagCheck( this->eMemoryProtections, MEM_STATE_RESERVED );
}

BOOL MemoryPage::type_image( void ) {
	FlagCheck( this->eMemoryProtections, MEM_TYPE_IMAGE );
}

BOOL MemoryPage::type_mapped( void ) {
	FlagCheck( this->eMemoryProtections, MEM_TYPE_MAPPED );
}

BOOL MemoryPage::type_private( void ) {
	FlagCheck( this->eMemoryProtections, MEM_TYPE_PRIVATE );
}

void MemoryPage::set_usage_heap( void )
{
	this->eMemoryUsage |= MEM_HEAP;
}

void MemoryPage::set_usage_stack( void )
{
	this->eMemoryUsage |= MEM_STACK;
}

BOOL MemoryPage::usage_heap( void )
{
	FlagCheck( this->eMemoryUsage, MEM_HEAP );
}

BOOL MemoryPage::usage_stack( void )
{
	FlagCheck( this->eMemoryUsage, MEM_STACK );
}

unsigned char * MemoryPage::get_memory_page_contents_buffer( void )
{
	return this->lpucMemoryPageContents;
}

BOOL MemoryPage::allocate_buffer_for_page( void )
{
	if( this->get_page_size() == 0 ) return FALSE;

	if( ( this->lpucMemoryPageContents = (unsigned char *) calloc( 
		this->get_page_size(), sizeof(char) ) ) == NULL ) {
			return FALSE;
	}

	return TRUE;
}