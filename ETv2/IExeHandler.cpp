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

#include "IExeHandler.h"
#include "PEParser.h"

IExeHandler::IExeHandler(void)
{
}


IExeHandler::~IExeHandler(void)
{
}

static EXE_TYPE exehandler_get_exe_type( void * vpAFewBytes, 
	int nBytesBufferSize );

IExeHandler * IExeHandler::init_get_instance( 
	ImageHeaderMemory * lpcHeader)
{
	IExeHandler * lpcExeHandler = NULL;
	PEParser * lpPEParser;
	//lpsIRegister = static_cast<IRegister *>(sX86Register);
// 	switch( lpcHeader->get_exe_type() ) {
// 		case EXE_PE: {
// 			lpPEParser = new PEParser();
// 			lpcExeHandler = static_cast<IExeHandler *>( lpPEParser );
// 			break;
// 		}
// 		case EXE_ELF: {
// 			return NULL;
// 			break;
// 		}
// 	}
	lpPEParser = new PEParser();
	lpcExeHandler = static_cast<IExeHandler *>( lpPEParser );
	return lpcExeHandler;
}