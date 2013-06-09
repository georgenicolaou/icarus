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
#include "../icarus_include.h"
#include "IProcessorArchitecture.h"
#include "../iDisasm/intel_defs.h"
#include "../RopGadget.h"
class IA32 : public IProcessorArchitecture
{
public:
	IA32(void);
	~IA32(void);
	virtual int get_sizeof_char_bits();
	virtual BOOL run_call_trace( IDebugger * lpobjDebugger, int nThreadId );
	virtual int get_stack_width();
	virtual void setup_disassembler( PSIDISASM lpDisasm, 
		void * lpVirtualAddress, BOOL bPopulateMnemonics );
	virtual BOOL disassemble( PSIDISASM lpDisasm );
	virtual char * get_return_to_stack_strpattern( vector<IRegister *> * );
};

