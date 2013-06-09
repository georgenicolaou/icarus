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

#include "WindowsProtections.h"
#include "Seh.h"
#include "GSBufferSec.h"
#include "DataExecutionPrevention.h"
#include "WinASLR.h"

const char * lplpProtectionNames[] = {
	"SafeSEH OFF",
	"SEH OFF",
	"SafeSEH ON",
	"DEP",
	"ASLR|Rebased",
	"ASLR|Not Rebased",
	"GS"
};

WindowsProtections::WindowsProtections(void)
{
	this->lpszProtection0Dep = (char *)lplpProtectionNames[3];
}


WindowsProtections::~WindowsProtections(void)
{
}

BOOL WindowsProtections::apply_protection_filter( IProtections::_PROTECTION_FILTER 
	eProtectionFilter )
{
	this->eCurrentFilter = (_WINDOWS_PROTECTION_FILTER) eProtectionFilter;
	return TRUE;
}

BOOL WindowsProtections::filter_module_allowed( ImageHeaderMemory * 
	lpcHeaderMemory )
{
	BOOL bReturn = TRUE;

	this->bProtection0Dep = FALSE;
	this->bProtection1Gs = FALSE;
	this->bProtection2Seh = FALSE;
	this->bProtection3Aslr = FALSE;
	this->lpszProtection0Dep = NULL;
	this->lpszProtection1Gs = NULL;
	this->lpszProtection2Seh = NULL;
	this->lpszProtection3Aslr = NULL;

	dprintflvl( 3, "Module: %s ", lpcHeaderMemory->get_image_name_ascii() );

	if( ( this->eCurrentFilter & 
		(unsigned long)_WINDOWS_PROTECTION_FILTER::PROTECTION_SEH ) != NULL ) {
			Seh * lpcSeh = new Seh;
			SEH_TYPE eSehType = lpcSeh->seh_get_seh_type( lpcHeaderMemory );
			switch( eSehType ) {
				case SEH_ON: {
					this->lpszProtection2Seh = (char *)lplpProtectionNames[0];
					dprintflvl( 3, "[SafeSEH OFF]");
					break;
				}
				case SEH_OFF: {
					this->lpszProtection2Seh = (char *)lplpProtectionNames[1];
					this->bProtection2Seh = TRUE;
					dprintflvl( 3, "[SEH OFF]" );
					bReturn = FALSE;
					break;
				}
				case SEH_SAFESEH: {
					this->bProtection2Seh = TRUE;
					this->lpszProtection2Seh = (char *)lplpProtectionNames[2];
					dprintflvl( 3, "[SafeSEH ON]");
					bReturn = FALSE;
					break;
				}
			}
	}
	if( ( this->eCurrentFilter & 
		(unsigned long)_WINDOWS_PROTECTION_FILTER::PROTECTION_DEP ) != NULL ) {
			DataExecutionPrevention * lpcDep = new DataExecutionPrevention();
			if( lpcDep->dep_is_module_dep_enabled( lpcHeaderMemory ) == TRUE) {
				this->lpszProtection0Dep = (char *)lplpProtectionNames[3];
				dprintflvl( 3, "[DEP]" );
				bReturn = FALSE;
			} 
	}
	if( ( this->eCurrentFilter & 
		(unsigned long)_WINDOWS_PROTECTION_FILTER::PROTECTION_ASLR ) != NULL ) {
			WinASLR * lpcAslr = new WinASLR();
			if( lpcAslr->winaslr_is_module_aslr_enabled( lpcHeaderMemory ) 
				== TRUE ) {
					this->bProtection3Aslr = TRUE;
					if( lpcAslr->winaslr_is_module_rebased( lpcHeaderMemory ) 
						== TRUE ) {
							this->lpszProtection3Aslr = 
								(char *)lplpProtectionNames[4];
							dprintflvl( 3, "[ASLR|Rebased]" );
							bReturn = FALSE;
					}
					else {
						this->lpszProtection3Aslr = 
							(char *)lplpProtectionNames[5];
						dprintflvl( 3, "[ASLR|Not Rebased]" );
					}
			}
	}
	if( ( this->eCurrentFilter & 
		(unsigned long)_WINDOWS_PROTECTION_FILTER::PROTECTION_GS ) != NULL ) {
			GSBufferSec * lpcGs = new GSBufferSec();
			if( lpcGs->gsbuffersec_module_has_stack_cookie( lpcHeaderMemory ) 
				== TRUE ) {
					this->bProtection1Gs = TRUE;
					this->lpszProtection1Gs = (char *)lplpProtectionNames[6];
					dprintflvl( 3, "[GS|Cookie: 0x%X", 
						lpcGs->gsbuffersec_module_get_stack_cookie( 
						lpcHeaderMemory ) );
					bReturn = FALSE;
			}
	}

	return bReturn;
}


BOOL WindowsProtections::is_protection_0()
{
	return this->bProtection0Dep;
}

char * WindowsProtections::get_protection_0_name()
{
	if( this->bProtection0Dep == TRUE )
		return this->lpszProtection0Dep;
	else
		return NULL;
}

BOOL WindowsProtections::is_protection_1()
{
	return this->bProtection1Gs;

}

char * WindowsProtections::get_protection_1_name()
{
	if( this->bProtection1Gs == TRUE )
		return this->lpszProtection1Gs;
	else
		return NULL;
}

BOOL WindowsProtections::is_protection_2()
{
	return this->bProtection2Seh;
}

char * WindowsProtections::get_protection_2_name()
{
	return this->lpszProtection2Seh;
}

BOOL WindowsProtections::is_protection_3()
{
	return this->bProtection3Aslr;
}

char * WindowsProtections::get_protection_3_name()
{
	if( this->bProtection3Aslr == TRUE )
		return this->lpszProtection3Aslr;
	else 
		return NULL;
}

BOOL WindowsProtections::is_protection_4()
{
	return FALSE;
}

char * WindowsProtections::get_protection_4_name()
{
	return NULL;
}

BOOL WindowsProtections::is_protection_5()
{
	return FALSE;
}

char * WindowsProtections::get_protection_5_name()
{
	return NULL;
}