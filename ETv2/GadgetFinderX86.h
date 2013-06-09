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
#include "icarus_include.h"
#include "IGadgetFinder.h"
#include "HexPattern.h"
#include "ICallback.h"
#include "processor\IProcessorArchitecture.h"
#include "iDisasm\idisasm_include.h"
#include "processor\IRegister.h"
#include "MemoryAllocator.h"

//How many instructions in ROP Gadget
#define DEFAULT_ROPG_SIZE 5 
class GadgetFinderX86 : public IGadgetFinder, public ICallback
{
public:
	GadgetFinderX86(void);
	~GadgetFinderX86(void);
	virtual BOOL proc_find_rop_gadgets( IProtections * lpcProtectionsFilter, 
		int nProcessId );

	virtual BOOL mem_find_rop_gadgets( vector<RopGadget*> * vFoundRopGadgets,
		Address * lpMemory );

	virtual void set_maximum_rop_size( int nMax );
	virtual void fcallback( void * );
	virtual BOOL fbCallback( void * );

	virtual BOOL proc_find_api_gadgets( IProtections * lpcProtectionsFilter,
		int nProcessId );

	virtual vector<RopGadget *> * get_found_rop_gadgets();
	virtual vector<RopGadget *> * get_found_api_gadgets();

private:
	BOOL find_gadgets_at_address( vector<RopGadget *> *, Address * );
	RopGadget * get_gadget( vector<PSIDISASM> vInstructions );
	IRegister * idisasm_reg_to_ireg( OPERAND_TYPE regType, REG iDisasmReg,
		BITSIZE eSize );
	void update_gadget_registers( RopGadget * lpGadget, 
		INSTRUCTION * lpInstruction );
	BOOL reg_already_in_regs( vector<IRegister *> *, IRegister * );
	BOOL in_list( int nOpIndex, ... );
	vector<RopGadget *> vRopGadgets;
	vector<RopGadget *> vApiGadgets;
	HexPattern cExitPattern;
	HexPattern cApiCallPattern;
	int nMaxRopSize;
	IProcessorArchitecture * lpProcessor;
	//the bucket list
	s_bucket sInstructionsBucket;
	s_bucket sGadgetsBucket;
};

