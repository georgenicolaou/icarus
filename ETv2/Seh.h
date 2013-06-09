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
#include "WindowsMemory.h"
#include "icarus_include.h"
#include "windef.h"

typedef enum _SEH_TYPE {
	SEH_OFF = 1,
	SEH_ON,
	SEH_SAFESEH,
} SEH_TYPE;

class Seh
{
public:
	Seh(void);
	~Seh(void);
	BOOL seh_get_thread_seh_chain( vector<Address *> * lpvSehList, 
		int nProcessId, int nThreadId );
	SEH_TYPE seh_get_seh_type( ImageHeaderMemory * lpsImageHeader );
	BOOL seh_get_module_registered_exception_handlers( vector<Address *> lpvSeh,
		ImageHeaderMemory * lpsImageHeader );
private:

};

