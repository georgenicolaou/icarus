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

#include "InstructionFinder.h"
#include "IMemory.h"
#include "MemoryPage.h"
#include "IExeHandler.h"
#include "ImageHeaderMemory.h"
#include "Address.h"

InstructionFinder::InstructionFinder(void)
{
	this->sAddressBucket.vpBucket = NULL;
}


InstructionFinder::~InstructionFinder(void)
{
	this->clear_bucket();
}

void InstructionFinder::clear_bucket()
{
	if( this->sAddressBucket.vpBucket != NULL ) {
		MemoryAllocator::m_free_bucket( &this->sAddressBucket );
	}
}

BOOL InstructionFinder::find_instruction_in_exe( int nProcessId, 
	IProtections * lpcProtectionsFilter, HexPattern * lpcCompiledHexPattern, 
	vector<Address *> * lpvFoundAddresses )
{
	return find_instruction_in_exe( nProcessId, lpcProtectionsFilter, 
		lpcCompiledHexPattern, lpvFoundAddresses, NULL );
}

BOOL InstructionFinder::find_instruction_in_exe( int nProcessId, 
	IProtections * lpcProtectionsFilter, 
	HexPattern * lpcCompiledHexPattern,
	vector<Address *> * lpvFoundAddresses, //Optional
	ICallback * Handler ) //Optional if lpvFoundAddresses == NULL
{
	ImageHeaderMemory * lpcImageHeader = NULL;
	vector<ImageHeaderMemory*> vImageHeaders;
	IExeHandler * lpcExeHandler;
	vector<MemoryPage *> vCodeSections;
	MemoryPage * lpcSectionMemoryPage;
	int i;
	int j;
	unsigned char * lpucSectionContents = NULL;
	unsigned long ulSectionSize = 0;
	void * lvpMatchedPatternOffset;
	unsigned char * lpucSectionContentsPrevious = NULL;
	Address * lpcAddress = NULL;
	unsigned long ulOffset = NULL;
	vector<MemoryPage *> vNonModuleExeSections;
	IMemory * lpcMemory = IMemory::init_get_instance();

	if( lpvFoundAddresses == NULL ) {
		if( Handler == NULL ) {
			PrintError( __FUNCTION__ " No handler given" );
			return FALSE;
		}

	}
	int nBucketItems = 1;
	if( Handler == NULL ) {
		//Allocate 1 page for Address structures
		nBucketItems = lpcMemory->memory_get_max_page_alloc_size() / sizeof(Address);
	}

	
	MemoryAllocator::m_allocate_bucket( &this->sAddressBucket, nBucketItems, 
		sizeof(Address), FALSE );

	if( lpcMemory->memory_get_module_headers( &vImageHeaders, nProcessId ) 
		== FALSE ) {
			this->clear_bucket();
			return FALSE;
	}

	for( i = 0; i < (int)vImageHeaders.size(); i++ ) {
		if( lpcProtectionsFilter->filter_module_allowed( vImageHeaders[i] ) 
			== TRUE ) {
				lpcImageHeader = vImageHeaders[i];
				if( ( lpcExeHandler = IExeHandler::init_get_instance( 
					lpcImageHeader ) ) == NULL ) {
						PrintError( "Error initializing exe handler" );
						this->clear_bucket();
						return FALSE;
				}
				
				if( lpcExeHandler->get_code_sections( lpcMemory, 
					&vCodeSections, lpcImageHeader ) == FALSE ) {
						PrintError( "Error getting code sections" );
						this->clear_bucket();
						return FALSE;
				}

				for( j = 0; j < (int)vCodeSections.size(); j++ ) {
					lpcSectionMemoryPage = vCodeSections[j];
					if( lpcSectionMemoryPage->allocate_buffer_for_page() 
						== FALSE ) {
							PrintError( __FUNCTION__ 
								": Unfortunately we run out of memory" );
							return MORE;
					}
					if( lpcMemory->memory_get_memory_page_contents( 
						lpcSectionMemoryPage->get_process_id(), 
						lpcSectionMemoryPage, 
						lpcSectionMemoryPage->get_memory_page_contents_buffer(), 
						lpcSectionMemoryPage->get_page_size() ) == FALSE ) {
							PrintError( __FUNCTION__ 
								"Error Getting Page Contents Address: 0x%08X", 
								lpcSectionMemoryPage->get_baseaddress() );
							continue;
					}

					lpucSectionContents = 
						lpcSectionMemoryPage->get_memory_page_contents_buffer();
					ulSectionSize = lpcSectionMemoryPage->get_page_size();

					lpucSectionContentsPrevious = lpucSectionContents;
					while( ( lpucSectionContents = (unsigned char *)
						lpcCompiledHexPattern->find_next_match( 
						lpucSectionContents, ulSectionSize ) ) != NULL ) {
							ulSectionSize = ulSectionSize - 
								( lpucSectionContents - 
								lpucSectionContentsPrevious ); 
							ulOffset = lpucSectionContents - 
								lpcSectionMemoryPage->get_memory_page_contents_buffer();
							lpcAddress = 
								(Address *)MemoryAllocator::m_next_from_bucket( 
								&this->sAddressBucket );

							lpcAddress->set_address_contents_pointer(
								lpucSectionContents );
							lpcAddress->set_address( (void *)(
								(unsigned long)
								lpcSectionMemoryPage->get_baseaddress() + 
								ulOffset) );
							lpcAddress->set_address_contents_size( 
								lpcCompiledHexPattern->get_pattern_size() );
							if( Handler != NULL ) {
								Handler->fcallback( lpcAddress );
								MemoryAllocator::m_give_back_to_bucket( 
									&this->sAddressBucket, lpcAddress );
							}
							else {
								lpvFoundAddresses->push_back( lpcAddress );
							}
							
							lpucSectionContentsPrevious = 
								lpucSectionContents;
					}
				}
		}
	}
	
	//Check non module executable sections
	lpcMemory->memory_get_non_image_executable_sections( 
		&vNonModuleExeSections );

	for( i = 0; i < (int)vNonModuleExeSections.size(); i++ ) {
		lpcSectionMemoryPage = vNonModuleExeSections[i];
		lpcSectionMemoryPage->allocate_buffer_for_page();
		if( lpcMemory->memory_get_memory_page_contents( 
			lpcSectionMemoryPage->get_process_id(), lpcSectionMemoryPage, 
			lpcSectionMemoryPage->get_memory_page_contents_buffer(), 
			lpcSectionMemoryPage->get_page_size() ) == FALSE ) {
				return FALSE;
		}

		lpucSectionContents = 
			lpcSectionMemoryPage->get_memory_page_contents_buffer();
		ulSectionSize = lpcSectionMemoryPage->get_page_size();
		void * baseaddr =  lpcSectionMemoryPage->get_baseaddress();
		lpucSectionContentsPrevious = lpucSectionContents;
		while( ( lpucSectionContents = (unsigned char *) 
			lpcCompiledHexPattern->find_next_match( lpucSectionContents, 
			ulSectionSize ) ) != NULL ) {
				ulSectionSize -= ( lpucSectionContents -
					lpucSectionContentsPrevious ); 
				ulOffset = lpucSectionContents - 
					lpcSectionMemoryPage->get_memory_page_contents_buffer();
				lpcAddress = new Address();
				lpcAddress->set_address_contents_pointer( lpucSectionContents );
				lpcAddress->set_address( (void *)( (unsigned long) 
					lpcSectionMemoryPage->get_baseaddress() + ulOffset) );
				lpcAddress->set_address_contents_size( 
					lpcCompiledHexPattern->get_pattern_size() );
				
				lpvFoundAddresses->push_back( lpcAddress );
				lpucSectionContentsPrevious = lpucSectionContents;
		}
	}
	return TRUE;
}