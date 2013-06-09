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
#include "iDisasm\types.h"
#include "RopGadget.h"
#include "IProtections.h"
class LIBEXPORT IGadgetFinder
{
public:
	IGadgetFinder(void);
	~IGadgetFinder(void);
	static IGadgetFinder * init_get_instance();

	virtual BOOL proc_find_rop_gadgets( IProtections * lpcProtectionsFilter, 
		int nProcessId ) = NULL;
	virtual BOOL mem_find_rop_gadgets( vector<RopGadget*> * vFoundRopGadgets,
		Address * lpMemory ) = NULL;
	virtual BOOL proc_find_api_gadgets( IProtections * lpcProtectionsFilter,
		int nProcessId ) = NULL;
	virtual void set_maximum_rop_size( int nMax ) = NULL;
	virtual vector<RopGadget *> * get_found_rop_gadgets() = NULL;
	virtual vector<RopGadget *> * get_found_api_gadgets() = NULL;
};

