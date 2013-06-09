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

#include "TracedFunction.h"
#include "processor\IProcessorArchitecture.h"
#include "ImageHeaderMemory.h"

#define DEFAULT_ARG_LOOKUP 4

TracedFunction::TracedFunction(void)
{
	this->bHasSymbols = FALSE;
	this->lpobjThreadStack = NULL;
}


TracedFunction::~TracedFunction(void)
{
}

BOOL TracedFunction::setup_function( 
	ThreadStack * lpobjThreadStack, 
	vector<IRegister *> * lpvCurrentRegisters, 
	IMemory * lpobjMemory, 
	int nNumberOfArgs
)
{


	IProcessorArchitecture * lpobjArchitecture = 
		IProcessorArchitecture::init_get_instance();

	int nStackwidthBytes = lpobjArchitecture->get_stack_width() / 
		lpobjArchitecture->get_sizeof_char_bits();

	if( lpobjSPRegister->get_register_size() / 
		lpobjArchitecture->get_sizeof_char_bits() > sizeof( long ) ) {
			dprintflvl( 2, "Error architecture sizes do not match" );
			return FALSE;
	}

	unsigned char * lpucStack = NULL;
	if( ( lpucStack = lpobjThreadStack->get_memory_page_contents_buffer() ) == NULL ) {
		dprintflvl( 2, "Stack not populated or released" );
		return FALSE;
	}

	this->lpobjFPRegister = IRegister::get_register( lpvCurrentRegisters, 
		IRegister::REG_FP );
	
	this->lpucFramePtr = (unsigned char *)this->lpobjFPRegister->get_offset_from_base( 
		(unsigned long)lpobjThreadStack->get_baseaddress() );

	//Get Return addr
	this->lpvReturnAddress = lpucStack + (int)this->lpucFramePtr + 
		nStackwidthBytes;

	vector<ImageHeaderMemory *> vHeaders;
	if( lpobjMemory->memory_get_module_headers( &vHeaders, NULL ) == FALSE ) {
		dprintflvl( 2, "Error getting module headers" );
		return FALSE;
	}

	ImageHeaderMemory * lpobjImageHeader = 
		lpobjMemory->memory_find_memory_page_addr( vHeaders, this->lpvReturnAddress );

	this->lpszReturnModule = lpobjImageHeader->get_image_name_ascii();

	if( this->has_symbolic_information() ) {
		//XXX Determine number of arguments from symbol
	}
	else {
		if( nNumberOfArgs == NULL ) nNumberOfArgs = DEFAULT_ARG_LOOKUP;
		for( int i = 0; i < nNumberOfArgs; i++ ) {

		}
	}

}

ARGUMENT_TYPE TracedFunction::get_argument_n_type( int nArgumentNumber )
{
	return ARGUMENT_TYPE::VALUE;
}

void * TracedFunction::get_argument_n_value( int nArgumentNumber )
{
	return NULL;
}

void TracedFunction::set_calling_convention( CALLING_CONVENTION )
{
	
}

BOOL TracedFunction::has_symbolic_information()
{
	return FALSE;
}

char * TracedFunction::get_function_name()
{
	return NULL;
}

ARGUMENT_TYPE TracedFunction::guess_argument_type( void * lpvArgument )
{
	return VALUE;
}