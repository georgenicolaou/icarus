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

#include "IA32.h"
#include "..\IMemory.h"
#include "..\iDisasm\idisasm_include.h"


IA32::IA32(void)
{
}


IA32::~IA32(void)
{
}

int IA32::get_stack_width()
{
	return 32;
}

int IA32::get_sizeof_char_bits()
{
	return 8;
}

BOOL IA32::run_call_trace( IDebugger * lpobjDebugger, int nThreadId )
{
	vector<IRegister*> vlpRegisters;
	IMemory * lpobjMemory = IMemory::init_get_instance();

	if( lpobjDebugger->debugger_get_registers( &vlpRegisters, nThreadId ) 
		== FALSE ) {
			dprintflvl( 1, "Error getting registers for call trace");
			return FALSE;
	}

	IRegister * lpobjFPRegister = IRegister::get_register( &vlpRegisters, 
		IRegister::REG_FP );

	vector<ThreadStack *> vlpThreadStacks;
	if( lpobjMemory->memory_get_proc_stacks( &vlpThreadStacks, 
		lpobjDebugger->get_process_id(), nThreadId ) == FALSE ) {
			return FALSE;
	}

	ThreadStack * lpobjThreadStack = vlpThreadStacks[0];
	lpobjThreadStack->allocate_buffer_for_page();
	if( lpobjMemory->memory_get_memory_page_contents( 
			lpobjDebugger->get_process_id(), lpobjThreadStack, 
			lpobjThreadStack->get_memory_page_contents_buffer(), 
			lpobjThreadStack->get_page_size() ) == FALSE ) {
				return FALSE;
	}

	unsigned char * lpucStackBuffer = 
		lpobjThreadStack->get_memory_page_contents_buffer();
	unsigned long ulFPBufferPtr = 
		*((unsigned long *)lpobjFPRegister->get_register_value()) - 
		(unsigned long)lpobjThreadStack->get_baseaddress();


	//XXX switch( calling conversion )...

	unsigned long ulStackBase = (unsigned long)lpobjThreadStack->get_baseaddress();
	unsigned long ulStackTop = (unsigned long)lpobjThreadStack->get_baseaddress() + 
		lpobjThreadStack->get_page_size();

	do {
		
		//Next FP
		ulFPBufferPtr = *((unsigned long *)(lpucStackBuffer + ulFPBufferPtr)) - 
			ulStackBase;
	} while( ulFPBufferPtr > ulStackBase && ulFPBufferPtr <  ulStackTop );

}
void IA32::setup_disassembler( PSIDISASM lpDisasm, 
	void * lpVirtualAddress, BOOL bPopulateMnemonics )
{
	lpDisasm->Architecture = X86;
	lpDisasm->VirtualAddress = (uiptr)lpVirtualAddress;
	lpDisasm->InternalStuff.bPopulateMnemonics = bPopulateMnemonics;
}

BOOL IA32::disassemble( PSIDISASM lpDisasm )
{
	dprintflvl( 3, "Disassembling: %#X (VA: %#X)", lpDisasm->InstructionPointer, 
		lpDisasm->VirtualAddress );
	if( disasm( lpDisasm ) == INSTRUCTION_VALID ) {
		return TRUE;
	}
	return FALSE;
}

//XXX should generate a pattern based on controllable registers (vContainingRegs)
char * IA32::get_return_to_stack_strpattern( vector<IRegister *> * vContainingRegs )
{
	return "FF[E4D4]";
}