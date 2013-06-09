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

#include "IMemory.h"
#ifdef OS_WIN_
#include "WindowsMemory.h"
#endif // _WIN_OS_
#include "IExeHandler.h"


IMemory * IMemory::init_get_instance( void )
{
	IMemory * lpcIMemory;
#ifdef OS_WIN_
	WindowsMemory * lpcWindowsMemory = new WindowsMemory();
	lpcIMemory = static_cast<IMemory *>( lpcWindowsMemory );
#endif // OS_WIN_
	return lpcIMemory;
}
IMemory::IMemory(void)
{
}


IMemory::~IMemory(void)
{
}


// IRegister * IRegister::init_get_instance( void )
// {
// 	IRegister * lpsIRegister;
// #ifdef ARCH_X86_
// 	X86Register * sX86Register = new X86Register();
// 	lpsIRegister = static_cast<IRegister *>(sX86Register);
// #endif
// 	return lpsIRegister;
// }

unsigned char * IMemory::memory_ustrstr( unsigned char * lpszHaystack, 
	int nHaystackSize, unsigned char * lpszNiddle, int nNiddleSize ) 
{
	unsigned char * s1, *s2;
	int ns1, ns2;

	if( nNiddleSize <= 0 ) return lpszHaystack;

	while(nHaystackSize) {
		s1 = lpszHaystack;
		ns1 = nHaystackSize;
		s2 = lpszNiddle;
		ns2 = nNiddleSize;

		while( ns1 && ns2 && !(*s1 - *s2) ) {
			s1++; s2++; ns1--; ns2--;
		}
		if( ns2 == 0 ) return lpszHaystack;

		lpszHaystack++;
		nHaystackSize--;
	}
	return (unsigned char *)NULL;
}

MemoryPage * IMemory::memory_find_memory_page_addr( 
	vector<MemoryPage*>& vMemoryPages, void * vpAddress )
{
	int i;
	for( i = 0; i < (int)vMemoryPages.size(); i++ ) {
		if( vMemoryPages[i]->get_baseaddress() <= vpAddress && ( 
			(unsigned long)vMemoryPages[i]->get_baseaddress() + 
			vMemoryPages[i]->get_page_size() ) > (unsigned long)vpAddress ) {
				return vMemoryPages[i];
		}
	}
	
	dprintflvl( 3, "Unable to locate MemoryPage at 0x%X", vpAddress );
	return NULL;
}

ImageHeaderMemory * IMemory::memory_find_memory_page_addr( 
	vector<ImageHeaderMemory*>& vMemoryPages, 
	void * vpAddress )
{
	int i;

	if( vMemoryPages.size() == 0 ) return NULL;

	IExeHandler * lpcExeHandler = IExeHandler::init_get_instance( 
		vMemoryPages[0] );
	
	for( i = 0; i < (int)vMemoryPages.size(); i++ ) {
		if( vMemoryPages[i]->get_baseaddress() <= vpAddress && ( 
			(unsigned long)vMemoryPages[i]->get_baseaddress() + 
			lpcExeHandler->get_virtual_sizeo_if_image( vMemoryPages[i] ) ) > 
			(unsigned long)vpAddress ) {
				return vMemoryPages[i];
		}
	}

	dprintflvl( 3, "Unable to locate MemoryPage at 0x%X", vpAddress );
	return NULL;
}

BOOL IMemory::is_address_in_page( 
	MemoryPage * lpcMemoryPage, void * lvpAddress )
{
	if( lpcMemoryPage->get_baseaddress() <= lvpAddress && 
		( (unsigned long)lpcMemoryPage->get_baseaddress() + 
		lpcMemoryPage->get_page_size() ) >= (unsigned long)lvpAddress ) {
			return TRUE;
	}
	else {
		return FALSE;
	}
}