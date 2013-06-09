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

#include "iDisasm\idisasm_include.h"
using namespace std;
#include <vector>
#include "processor\IRegister.h"
#include "Function.h"
typedef enum {
	GC_NONE			= 0,
	GC_MEMORY		= 0x00000001,
	GC_REGMEMORY	= 0x00000002,
	GC_ASSIGNMENT	= 0x00000004,
	GC_FUNCCALL		= 0x00000008,
	GC_SYSCALL		= 0x00000010,
	GC_MATH			= 0x00000020,
	GC_LOGICAL		= 0x00000040,
	GC_CONTROLFLOW	= 0x00000080,
	GC_SYSTEMINSTR	= 0x00000100,
	GC_SEGMENT		= 0x00000200,
	GC_UNKNOWNINSTR	= 0x00000400
} GADGET_CATEGORY;

typedef enum {
	GT_NONE = 0,
	GT_CONTROLFLOW_REG	= 0x00000001,
	GT_CONTROLFLOW_MEM	= 0x00000002,
	GT_CONTROLFLOW_REL	= 0x00000004,
	GT_ASSIGNS_ZERO		= 0x00000008,
	GT_STRING_MOVE		= 0x00000010,
	GT_STRING_CMP		= 0x00000010,
} GADGET_TYPE;
/*
typedef enum {
	//pop pop ret gadgets
	GT_POPPOPRET	= 0x00000000,
	//Gadgets POPing registers and returning
	GT_POPRET		= 0x00000001, 
	//Gadgets Modifying registers and returning
	GT_REGMODRET	= 0x00000002, 
	//Gadget that branches to an address or function
	GT_CTRANSFER	= 0x00000004, 
	//Gadget that branches to register or contents of register
	GT_CTRANSFERREG	= 0x00000008, 
	//Gadget containing any kind of instructions followed by a ret
	GT_ANYRET		= 0x00000010, 
	//Gadget involving FS
	GT_FS			= 0x00000020,
	//Gadget involving GS
	GT_GS			= 0x00000040,
	// Gadget that modifies ESP then rets
	GT_ESPRET		= 0x00000080,
	//Gadget that modifies a memory location and rets
	GT_MEMRET		= 0x00000100,

	GT_ALL			= 0xFFFFFFFF
} GADGET_TYPE;
*/
class LIBEXPORT RopGadget
{
public:
	RopGadget(void);
	~RopGadget(void);
	void add_category_flag( GADGET_CATEGORY );
	void remove_category_flag( GADGET_CATEGORY );
	GADGET_CATEGORY get_gadget_category();

	void add_type_flag( GADGET_TYPE );
	void remove_type_flag( GADGET_TYPE );
	GADGET_TYPE get_gadget_type();

	void set_instructions( vector<PSIDISASM> vInstructions );
	vector<PSIDISASM> * get_instructions();

	void set_gadget_size( int );
	int get_gadget_size();

	void add_affected_register( IRegister * );
	vector<IRegister *> * get_affected_registers();
	void add_read_register( IRegister * );
	vector<IRegister *> * get_read_registers();

	void assign_function( Function * );
	Function * get_function();

	void set_gadget_address( unsigned long );
	unsigned long get_gadget_address();
private:
	//Note that these are deleted when RopGadget is destroyed.
	vector<PSIDISASM> * vInstructions;
	vector<IRegister *> vAffectedRegisters;
	vector<IRegister *> vReadRegisters;
	GADGET_CATEGORY eGadgetCategory;
	GADGET_TYPE eGadgetType;
	int nGadgetSize;
	unsigned long ulGadgetAddress;
	//If function call gadget store function
	Function * lpFunction;
};

