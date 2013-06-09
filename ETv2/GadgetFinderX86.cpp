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

#include "GadgetFinderX86.h"
#include "InstructionFinder.h"
#include "processor\IA32.h"
#include "iDisasm\intel.h"
#include "processor\X86Register.h"
#include "processor\IRegister.h"
#include "IMemory.h"
#include "IExeHandler.h"


/*
#define CREATE_REGISTER( lpsRegister, lpsRegName, lpRegValue, nRegSize ) { \
	lpsRegister = (X86Register *)MemoryAllocator::m_next_from_bucket( &this->sIRegisterBucket ); \
	lpsRegister->set_register_name((IRegister::_GENERAL_REGISTER_ENUM) lpsRegName ); \
	lpsRegister->set_register_value( lpRegValue ); \
	lpsRegister->set_register_size( (unsigned long)nRegSize ); \
}
*/

char * lpRopExits = 
	"["
	"C3" // RETN
	"C2" // RETN Iw
	"CA" // RETF Iw
	"CB" //RETF
	"]"
	/* 
	//Currently not supported by HexPattern
	"|FF1424" // CALL [ESP]
	"|FF5500" // CALL [EBP]
	"|FF2424" // JMP [ESP]
	"|FF6500" // JMP [EBP]
	// Add CALL|JMP [ECX|EAX|EBX|EDX|ESI|EDI]
	*/
	;

char * lpApiEntries = 
	"FF25"; // for now just this
	//"["
	//"E8" // CALL Jz (Jay-Z)
	//"E9" // JMP Jz
	//"]";

GadgetFinderX86::GadgetFinderX86(void)
{
	this->cExitPattern.parse_pattern( lpRopExits );
	this->cApiCallPattern.parse_pattern( lpApiEntries );
	this->lpProcessor = IProcessorArchitecture::init_get_instance();
	this->nMaxRopSize = DEFAULT_ROPG_SIZE;
	this->sInstructionsBucket.vpBucket = NULL;
	this->sGadgetsBucket.vpBucket = NULL;
}

GadgetFinderX86::~GadgetFinderX86(void)
{
	MemoryAllocator::m_free_bucket( &this->sInstructionsBucket );
	MemoryAllocator::m_free_bucket( &this->sGadgetsBucket );
}

void GadgetFinderX86::set_maximum_rop_size( int nMax )
{
	this->nMaxRopSize = nMax;
}

BOOL GadgetFinderX86::proc_find_rop_gadgets( 
	IProtections * lpcProtectionsFilter, 
	int nProcessId )
{
	vector<Address *> vFoundAddresses;
	InstructionFinder cInstrunctionFinder;
	BOOL bInstrFinderResult = FALSE;
	IMemory * lpMemory = IMemory::init_get_instance();
	/*We are expecting quite a lot of instructions 
	** Need to come up with a better way to calculate number of items
	** (possibly use the same technique as in InstructionFinder)
	*/
	MemoryAllocator::m_free_bucket( &this->sInstructionsBucket );
	MemoryAllocator::m_free_bucket( &this->sGadgetsBucket );

	MemoryAllocator::m_allocate_bucket( &this->sInstructionsBucket, 
		lpMemory->memory_get_max_page_alloc_size() / sizeof(SIDISASM), 
		sizeof(SIDISASM), FALSE );

	MemoryAllocator::m_allocate_bucket( &this->sGadgetsBucket, 
		lpMemory->memory_get_max_page_alloc_size() / sizeof(RopGadget), 
		sizeof(RopGadget), FALSE );

	delete lpMemory;

	dprintflvl( 3, "Finding all RETN instructions in Process: %d", nProcessId );

	bInstrFinderResult = cInstrunctionFinder.find_instruction_in_exe( 
		nProcessId, lpcProtectionsFilter, &this->cExitPattern, 
		NULL, this );

	if( bInstrFinderResult == FALSE ) {
		return FALSE;
	}

	return TRUE;
}

void GadgetFinderX86::fcallback( void * lpArg )
{
	this->find_gadgets_at_address( &this->vRopGadgets, (Address *)lpArg );
}

BOOL GadgetFinderX86::mem_find_rop_gadgets( 
	vector<RopGadget*> * vFoundRopGadgets,
	Address * lpobjAddress )
{
	return TRUE;
}

BOOL GadgetFinderX86::find_gadgets_at_address( 
	vector<RopGadget *> * vFoundGadgets, Address * lpObjAddress )
{
	PSIDISASM lpDisasm = (PSIDISASM)MemoryAllocator::m_next_from_bucket( 
		&this->sInstructionsBucket );
	vector<PSIDISASM> vInstructions;

	this->lpProcessor->setup_disassembler( lpDisasm, lpObjAddress->get_address(), 
		TRUE );

	lpDisasm->InstructionPointer = 
		(uiptr)lpObjAddress->get_address_contents_buffer();

	this->lpProcessor->disassemble( lpDisasm );

	BOOL bValidRop = TRUE;
	int nNumberOfInstructions = 0;
	int nBytesConsumed = 0;
	int nBytesGone = 0;
	vInstructions.push_back( lpDisasm );

	uiptr ulDeadMansPoint = lpDisasm->InstructionPointer - lpDisasm->InstructionSize;
	uiptr ulCurrentIP = ulDeadMansPoint;
	uiptr ulCurrentVA = lpDisasm->VirtualAddress; //- lpDisasm->InstructionSize;
	vector<PSIDISASM> vTmpInstructions;
	BOOL bDeadManHit = FALSE;
	while( bValidRop ) {
		nBytesConsumed++;
		while( bDeadManHit == FALSE ) {
			lpDisasm = (PSIDISASM)MemoryAllocator::m_next_from_bucket( 
				&this->sInstructionsBucket );
			this->lpProcessor->setup_disassembler( lpDisasm, 
				(void *)(ulCurrentVA - nBytesConsumed + nBytesGone), TRUE );

			lpDisasm->InstructionPointer = ulCurrentIP - nBytesConsumed + nBytesGone;
			if( this->lpProcessor->disassemble( lpDisasm ) == INSTRUCTION_INVALID ) {
				dprintflvl( 3, "%#X: Invalid Instruction", 
					lpDisasm->VirtualAddress );
				nBytesGone = 0;
				nBytesConsumed++;
				for( int i = 0; i < (int)vTmpInstructions.size(); i++ ) {
					MemoryAllocator::m_give_back_to_bucket( 
						&this->sInstructionsBucket, vInstructions[i] );
				}
				vTmpInstructions.clear();
				MemoryAllocator::m_give_back_to_bucket( 
					&this->sInstructionsBucket, lpDisasm );
				continue;
			}
			if( lpDisasm->InstructionPointer > ulDeadMansPoint ) {
				dprintflvl( 3, "%#X: %s (Instruction after dead man's point)", 
					lpDisasm->InstructionPointer, lpDisasm->Mnemonic );
				nBytesConsumed++;
				nBytesGone = 0;
				for( int i = 0; i < (int)vTmpInstructions.size(); i++ ) {
					MemoryAllocator::m_give_back_to_bucket( 
						&this->sInstructionsBucket, vTmpInstructions[i] );
				}
				vTmpInstructions.clear();
				MemoryAllocator::m_give_back_to_bucket( 
					&this->sInstructionsBucket, lpDisasm );
				continue;
			}
			vTmpInstructions.push_back( lpDisasm );
			if( lpDisasm->InstructionPointer == ulDeadMansPoint ) {
				bDeadManHit = TRUE;
			}
			else { //InstructionPointer < ulDeadMansPoint (more instructions)
				if( vTmpInstructions.size() >= this->nMaxRopSize ) {
					return FALSE;
				}
				nBytesGone += lpDisasm->InstructionSize;
			}
		}
		bDeadManHit = FALSE;
		nBytesGone = 0;
		vTmpInstructions.insert( vTmpInstructions.end(), vInstructions.begin(), 
			vInstructions.end() );

		dprintflvl( 3, "Got Valid Rop Gadget");
		for( int i = 0; i < (int)vTmpInstructions.size(); i++ ) {
			dprintflvl(3, "%#X: %s", vTmpInstructions[i]->VirtualAddress, 
				vTmpInstructions[i]->Mnemonic );
		}
		if( (int)vTmpInstructions.size() >= this->nMaxRopSize )
			bValidRop = FALSE;

		RopGadget * lpTmpGadget;
		dprintflvl( 3, "Verifying gadget")
		if( ( lpTmpGadget = this->get_gadget( vTmpInstructions ) ) != NULL ) {
			vFoundGadgets->push_back( lpTmpGadget );
		}
		else {
			dprintflvl( 3, "False alarm, bad gadget" );
			//Free all except original RET instruction (last one)
			for( int i = 0; i < (int)vTmpInstructions.size() - 1; i++ ) {
				MemoryAllocator::m_give_back_to_bucket( 
						&this->sInstructionsBucket, vTmpInstructions[i] );
			}
		}

		vTmpInstructions.clear();
	}
	return TRUE;
}
BOOL GadgetFinderX86::in_list( int nOpIndex, ... )
{
	va_list lst;
	int nOpIndexItem;
	BOOL bReturn = FALSE;
	va_start( lst, nOpIndex );

	while( ( nOpIndexItem = (int)va_arg( lst, int ) ) != -1 ) {
		if( nOpIndex == nOpIndexItem ) {
			bReturn = TRUE;
			break;
		}
	}
	va_end( lst );
	return bReturn;
}

RopGadget * GadgetFinderX86::get_gadget( vector<PSIDISASM> vInstructions )
{
	dprintflvl( 3, "Attributing gadget beginning at address %#X", 
		vInstructions[0]->VirtualAddress );

	INSTRUCTION * lpTmpInstr = &vInstructions[vInstructions.size()-1]->Instruction;
	int nOpcode = vInstructions[vInstructions.size()-1]->InternalStuff.nOpcodeIndex;

	PSIDISASM lpTmpDisasm = vInstructions[vInstructions.size()-1];
	uiptr ulDeadMansPt = lpTmpDisasm->InstructionPointer - 
		lpTmpDisasm->InstructionSize;

	uiptr ulLiveMansPt = vInstructions[0]->InstructionPointer - 
		vInstructions[0]->InstructionSize;
	
	//Verify control of gadget exit
	if( nOpcode != OP_RET && nOpcode != OP_RETF ) {
		dprintflvl( 3, "Last instruction is not return");
		//If its not a CT then what are we doing here?
		if( lpTmpInstr->Category != CONTROL_TRANSFER ) {
			dprintflvl( 3, "Bad Gadget: Exit is not CONTROL_TRANSFER");
			return NULL;
		}
		//Memory based control transfer check
		if( lpTmpInstr->Operands[0].Type & OPERAND_TYPE_TYPE_MASK != 
			OPERAND_MEMORY ) {
				dprintflvl( 3, "Bad Gadget: Exit goes to memory");
				return NULL;
		}
		//Check if memory is controllable through a register
		if( lpTmpInstr->Operands[0].RegValMem.Memory.BaseRegister == REG_NIL ) {
			dprintflvl( 3, "Bad Gadget: Exit not controlled with REG");
			return NULL;
		}
	}

	RopGadget * lpGadget = (RopGadget *)MemoryAllocator::m_next_from_bucket( 
		&this->sGadgetsBucket );

	lpGadget->set_gadget_address( (unsigned long)vInstructions[0]->VirtualAddress );
	//Verify that the rest of instr are valid and populate category and type
	for( int i = 0; i < vInstructions.size()-1; i++ ) {
		lpTmpInstr = &vInstructions[i]->Instruction;
		
		switch( lpTmpInstr->Category ) {
		case CONTROL_TRANSFER:
			//Check for inline RET instructions that might come up
			if( vInstructions[i]->InternalStuff.nOpcodeIndex == OP_RET || 
				vInstructions[i]->InternalStuff.nOpcodeIndex == OP_RETF ) {
					dprintflvl( 3, "Inline RET found, bad gadget" );
					MemoryAllocator::m_give_back_to_bucket( 
						&this->sGadgetsBucket, lpGadget );
					return NULL;
			}
			//Check if branch within gadget
			switch( lpTmpInstr->Operands[0].Type & OPERAND_TYPE_TYPE_MASK ) {
			case OPERAND_IMMIDIATE_ADDR:
				//Verify that relative address is within the gadget
				if( vInstructions[i]->InstructionPointer + 
					lpTmpInstr->Operands[0].RegValMem.Value > ulDeadMansPt || 
					vInstructions[i]->InstructionPointer + 
					lpTmpInstr->Operands[0].RegValMem.Value < ulLiveMansPt ) {
						MemoryAllocator::m_give_back_to_bucket( 
							&this->sGadgetsBucket, lpGadget );
						return NULL;
				}
				else {
					//Verify that branch doesn't intersect instruction.
					for( int j = 0; j < (int)vInstructions.size(); j++ ) {
						//Ok branch targets an instruction (the only valid exit)
						if( lpTmpInstr->Operands[0].TargetAddress == 
							vInstructions[j]->VirtualAddress )
								break;
						//If TA < VA of instr then it intersects
						if( lpTmpInstr->Operands[0].TargetAddress < 
							vInstructions[j]->VirtualAddress ) {
								MemoryAllocator::m_give_back_to_bucket( 
									&this->sGadgetsBucket, lpGadget );
								return NULL;
						}
					}
				}
				lpGadget->add_category_flag( GC_CONTROLFLOW );
				lpGadget->add_type_flag( GT_CONTROLFLOW_REL );
				break;
			case OPERAND_MEMORY:
				//Check if memory address is controllable by a register.
				if( lpTmpInstr->Operands[0].RegValMem.Memory.BaseRegister == 
					REG_NIL ) {
						/*
						If this is a call to a function then the inter-module
						call finder should catch it.
						*/
						MemoryAllocator::m_give_back_to_bucket( 
							&this->sGadgetsBucket, lpGadget );
						return NULL;
				}
				else {
					lpGadget->add_category_flag( GC_CONTROLFLOW );
					lpGadget->add_type_flag( GT_CONTROLFLOW_MEM );
				}
				
				break;
			case OPERAND_REGISTER:
				lpGadget->add_category_flag( GC_CONTROLFLOW );
				lpGadget->add_type_flag( GT_CONTROLFLOW_REG );
				break;
			default:
				MemoryAllocator::m_give_back_to_bucket( 
					&this->sGadgetsBucket, lpGadget );
				return NULL;
			}
			break;
		case BIT_BYTE:
		case LOGICAL_ARITHMETIC:
		case SHIFT_ROTATE:
			lpGadget->add_category_flag( GC_LOGICAL );
			//Case when XOR REGX, REGX assigns zero to REGX
			if( vInstructions[i]->InternalStuff.nOpcodeIndex == OP_XOR && 
				lpTmpInstr->Operands[0].Type == lpTmpInstr->Operands[1].Type && 
				lpTmpInstr->Operands[0].Type & OPERAND_REGISTER &&
				lpTmpInstr->Operands[0].RegValMem.Register == 
				lpTmpInstr->Operands[1].RegValMem.Register ) {
					lpGadget->add_type_flag( GT_ASSIGNS_ZERO );
			}
			//Case when AND X,0 assignes zero to X
			else if( vInstructions[i]->InternalStuff.nOpcodeIndex == OP_AND && 
				( lpTmpInstr->Operands[1].Type & OPERAND_IMMIDIATE ) && 
				lpTmpInstr->Operands[1].RegValMem.Value == 0 ) {
					lpGadget->add_type_flag( GT_ASSIGNS_ZERO );
			}
			break;
		case BINARY_ARITHMETIC:
			//CMP instruction is arithmetic
			lpGadget->add_category_flag( GC_MATH );
			//Case when MOV X,0 assigns zero to X
			if( vInstructions[i]->InternalStuff.nOpcodeIndex == OP_MOV && 
				lpTmpInstr->Operands[1].Type & OPERAND_IMMIDIATE && 
				lpTmpInstr->Operands[1].RegValMem.Value == 0 ) {
					lpGadget->add_type_flag( GT_ASSIGNS_ZERO );
			}
			//Case when SUB REGX,REGX assigns zero to REGX
			else if( vInstructions[i]->InternalStuff.nOpcodeIndex == OP_SUB && 
				lpTmpInstr->Operands[0].Type == lpTmpInstr->Operands[1].Type &&
				lpTmpInstr->Operands[0].Type & OPERAND_REGISTER &&
				lpTmpInstr->Operands[0].RegValMem.Register == 
				lpTmpInstr->Operands[1].RegValMem.Register ) {
					lpGadget->add_type_flag( GT_ASSIGNS_ZERO );
			}
			break;
		case CONTROL_FLAG:
		case DATA_TRANSFER:
			//Check if either operand is memory and the other is register
			if( ( ( lpTmpInstr->Operands[0].Type & OPERAND_REGISTER ) && 
					( lpTmpInstr->Operands[1].Type & OPERAND_MEMORY ) ) || 
				( ( lpTmpInstr->Operands[1].Type & OPERAND_REGISTER ) && 
					( lpTmpInstr->Operands[0].Type & OPERAND_MEMORY ) ) ) {
						lpGadget->add_category_flag( GC_MEMORY );
			}
			else {
				lpGadget->add_category_flag( GC_ASSIGNMENT );
				if( ( lpTmpInstr->Operands[1].Type & OPERAND_IMMIDIATE ) && 
					lpTmpInstr->Operands[1].RegValMem.Value == 0 ) {
						lpGadget->add_type_flag( GT_ASSIGNS_ZERO );
				}
			}
			break;
		case STRING_INSTRUCTIONS:
			if( this->in_list( vInstructions[i]->InternalStuff.nOpcodeIndex, 
				OP_REP, OP_REPE, OP_REPNE, OP_REPNZ, OP_REPZ, OP_STOS, OP_STOSB, 
				OP_STOSD, OP_STOSQ, OP_STOSW, OP_LODS, OP_LODSB, OP_LODSD, 
				OP_LODSQ, OP_LODSW, OP_MOVS, OP_MOVSB, OP_MOVSD, OP_MOVSW, -1 ) ) {
					lpGadget->add_category_flag( GC_ASSIGNMENT );
					lpGadget->add_type_flag( GT_STRING_MOVE );
			}
			if( this->in_list( vInstructions[i]->InternalStuff.nOpcodeIndex, 
				OP_CMPS, OP_CMPSB, OP_CMPSD, OP_CMPSQ, OP_CMPSW, OP_SCAS, 
				OP_SCASB, OP_SCASD, OP_SCASW, -1 ) ) {
					lpGadget->add_category_flag( GC_MATH );
					lpGadget->add_type_flag( GT_STRING_CMP );
			}
			break;
		case MISC_INSTRUCTION:
			if( vInstructions[i]->InternalStuff.nOpcodeIndex == OP_LEA ) {
				lpGadget->add_category_flag( GC_MEMORY );
			}
			break;
		case SYSTEM_INSTRUCTION:
			lpGadget->add_category_flag( GC_SYSTEMINSTR );
			break;
		case SEGMENT_REGISTER: //XXX should probably have something for this
			lpGadget->add_category_flag( GC_SEGMENT );
			break;
		default:
			lpGadget->add_category_flag( GC_UNKNOWNINSTR );
		}
		//Setup read/write registers
		this->update_gadget_registers( lpGadget, lpTmpInstr );
	}
	lpGadget->set_instructions( vInstructions );
	return lpGadget;
}

//XXX should prob move this to X86Register class
IRegister * GadgetFinderX86::idisasm_reg_to_ireg( 
	OPERAND_TYPE regType, 
	REG iDisasmReg,
	BITSIZE eSize )
{
	IRegister * lpRegister;
	switch( regType ) {
	case INTEL_TYPE_REG_GENERAL:
		switch( iDisasmReg ) {
		case REG_ECX: 
			CREATE_REGISTER( lpRegister, X86Register::ECX, NULL, eSize );
			return lpRegister;
		case REG_EAX: 
			CREATE_REGISTER( lpRegister, X86Register::EAX, NULL, eSize ); 
			return lpRegister;
		case REG_EDX: 
			CREATE_REGISTER( lpRegister, X86Register::EDX, NULL, eSize ); 
			return lpRegister;
		case REG_EBX:
			CREATE_REGISTER( lpRegister, X86Register::EBX, NULL, eSize ); 
			return lpRegister;
		case REG_ESP:
			CREATE_REGISTER( lpRegister, X86Register::ESP, NULL, eSize ); 
			return lpRegister;
		case REG_EBP:
			CREATE_REGISTER( lpRegister, X86Register::EBP, NULL, eSize ); 
			return lpRegister;
		case REG_ESI: 
			CREATE_REGISTER( lpRegister, X86Register::ESI, NULL, eSize );
			return lpRegister;
		case REG_EDI:
			CREATE_REGISTER( lpRegister, X86Register::EDI, NULL, eSize );
			return lpRegister;
		case REG_EIP:
			CREATE_REGISTER( lpRegister, X86Register::EIP, NULL, eSize ); 
			return lpRegister;
		case REG_AH: 
			CREATE_REGISTER( lpRegister, X86Register::AH, NULL, eSize ); 
			return lpRegister;
		case REG_CH: 
			CREATE_REGISTER( lpRegister, X86Register::CH, NULL, eSize ); 
			return lpRegister;
		case REG_DH: 
			CREATE_REGISTER( lpRegister, X86Register::DH, NULL, eSize ); 
			return lpRegister;
		case REG_BH: 
			CREATE_REGISTER( lpRegister, X86Register::BH, NULL, eSize ); 
			return lpRegister;
		case REG_SPH: 
			CREATE_REGISTER( lpRegister, X86Register::SPH, NULL, eSize ); 
			return lpRegister;
		//XXX need to handle PUSHAD/POPAD that affects/reads from all GPR
		}
	case INTEL_TYPE_REG_DR:
		switch( iDisasmReg ) {
		case REG_DR_0:
			CREATE_REGISTER( lpRegister, X86Register::IREG_DR0, NULL, eSize );
			return lpRegister;
		case REG_DR_1:
			CREATE_REGISTER( lpRegister, X86Register::IREG_DR1, NULL, eSize );
			return lpRegister;
		case REG_DR_2:
			CREATE_REGISTER( lpRegister, X86Register::IREG_DR2, NULL, eSize );
			return lpRegister;
		case REG_DR_3:
			CREATE_REGISTER( lpRegister, X86Register::IREG_DR3, NULL, eSize );
			return lpRegister;
		case REG_DR_4:
			CREATE_REGISTER( lpRegister, X86Register::IREG_DR4, NULL, eSize );
			return lpRegister;
		case REG_DR_5:
			CREATE_REGISTER( lpRegister, X86Register::IREG_DR5, NULL, eSize );
			return lpRegister;
		case REG_DR_6:
			CREATE_REGISTER( lpRegister, X86Register::IREG_DR6, NULL, eSize );
			return lpRegister;
		case REG_DR_7:
			CREATE_REGISTER( lpRegister, X86Register::IREG_DR7, NULL, eSize );
			return lpRegister;
		}
	case INTEL_TYPE_REG_CR:
		switch( iDisasmReg ) {
		case REG_CR_0:
			CREATE_REGISTER( lpRegister, X86Register::IREG_CR0, NULL, eSize );
			return lpRegister;
		case REG_CR_1:
			CREATE_REGISTER( lpRegister, X86Register::IREG_CR1, NULL, eSize );
			return lpRegister;
		case REG_CR_2:
			CREATE_REGISTER( lpRegister, X86Register::IREG_CR2, NULL, eSize );
			return lpRegister;
		case REG_CR_3:
			CREATE_REGISTER( lpRegister, X86Register::IREG_CR3, NULL, eSize );
			return lpRegister;
		case REG_CR_4:
			CREATE_REGISTER( lpRegister, X86Register::IREG_CR4, NULL, eSize );
			return lpRegister;
		case REG_CR_5:
			CREATE_REGISTER( lpRegister, X86Register::IREG_CR5, NULL, eSize );
			return lpRegister;
		case REG_CR_6:
			CREATE_REGISTER( lpRegister, X86Register::IREG_CR6, NULL, eSize );
			return lpRegister;
		case REG_CR_7:
			CREATE_REGISTER( lpRegister, X86Register::IREG_CR7, NULL, eSize );
			return lpRegister;
		}
	case INTEL_TYPE_REG_SEGMENT:
		switch( iDisasmReg ) {
		case REG_ES:
			CREATE_REGISTER( lpRegister, X86Register::IREG_ES, NULL, eSize );
			return lpRegister;
		case REG_CS:
			CREATE_REGISTER( lpRegister, X86Register::IREG_CS, NULL, eSize );
			return lpRegister;
		case REG_SS:
			CREATE_REGISTER( lpRegister, X86Register::IREG_SS, NULL, eSize );
			return lpRegister;
		case REG_DS:
			CREATE_REGISTER( lpRegister, X86Register::IREG_DS, NULL, eSize );
			return lpRegister;
		case REG_FS:
			CREATE_REGISTER( lpRegister, X86Register::IREG_FS, NULL, eSize );
			return lpRegister;
		case REG_GS:
			CREATE_REGISTER( lpRegister, X86Register::IREG_GS, NULL, eSize );
			return lpRegister;
		}
	}
	//XXX should add support for XMM, ST MMX etc...
	return NULL;
}

BOOL GadgetFinderX86::reg_already_in_regs( vector<IRegister *> * lpvRegs, 
	IRegister * lpRegister )
{
	for( int i = 0; i < (int)lpvRegs->size(); i++ ) {
		if( lpvRegs->at(i)->get_register_type() == 
			lpRegister->get_register_type() ) {
				return TRUE;
		}
	}
	return FALSE;
}

void GadgetFinderX86::update_gadget_registers( RopGadget * lpGadget, 
	INSTRUCTION * lpInstruction )
{
	IRegister * lpRegister;
	for( int i = 0; i < INTEL_MAX_NUMBER_OF_OPERANDS; i++ ) {
		if( lpInstruction->Operands[i].Type != OPERAND_NONE ) {
			if( lpInstruction->Operands[i].Type & OPERAND_REGISTER ) {
				lpRegister = this->idisasm_reg_to_ireg( 
					(OPERAND_TYPE)(lpInstruction->Operands[i].Type & 
					OPERAND_TYPE_REGISTER_MASK), 
					lpInstruction->Operands[i].RegValMem.Register, 
					lpInstruction->Operands[i].BitSize );
				if( lpRegister == NULL ) continue;
				switch( lpInstruction->Operands[i].Access & 
					OPERAND_ACCESS_TYPE ) {
				case READ: 
					if( this->reg_already_in_regs( lpGadget->get_read_registers(), 
						lpRegister ) == FALSE ) {
							lpGadget->add_read_register( lpRegister );
					}
					else {
						delete lpRegister;
					}
					break;
				case WRITE:
					if( this->reg_already_in_regs( lpGadget->get_read_registers(), 
						lpRegister ) == FALSE ) {
							lpGadget->add_affected_register( lpRegister );
					}
					else {
						delete lpRegister;
					}
					break;
				case READWRITE:
					BOOL bAdded = FALSE;
					if( this->reg_already_in_regs( lpGadget->get_read_registers(), 
						lpRegister ) == FALSE ) {
							lpGadget->add_read_register( lpRegister );
							bAdded = TRUE;
					}
					if( this->reg_already_in_regs( lpGadget->get_affected_registers(), 
						lpRegister ) == FALSE ) {
							lpGadget->add_affected_register( lpRegister );
							bAdded = TRUE;
					}

					if( bAdded == FALSE ) {
						delete lpRegister;
					}
					break;
				}
			}
			else if( lpInstruction->Operands[i].Type & OPERAND_MEMORY ) {
				if( lpInstruction->Operands[i].RegValMem.Memory.BaseRegister != 
					REG_NIL ) {
						lpRegister = this->idisasm_reg_to_ireg( 
							(OPERAND_TYPE)INTEL_TYPE_REG_GENERAL, 
							lpInstruction->Operands[i].RegValMem.Memory.BaseRegister,
							lpInstruction->Operands[i].AddressingSize );
						if( lpRegister != NULL ) {
							lpGadget->add_read_register( lpRegister );
						}
				}
				if( lpInstruction->Operands[i].RegValMem.Memory.IndexRegister != 
					REG_NIL ) {
						lpRegister = this->idisasm_reg_to_ireg( 
							(OPERAND_TYPE)INTEL_TYPE_REG_GENERAL, 
							lpInstruction->Operands[i].RegValMem.Memory.IndexRegister,
							lpInstruction->Operands[i].AddressingSize );
						if( lpRegister != NULL ) {
							lpGadget->add_read_register( lpRegister );
						}
				}
			}
		}
			
	}
	
}

BOOL GadgetFinderX86::proc_find_api_gadgets(
	IProtections * lpcProtectionsFilter,
	int nProcessId
	)
{
	vector<PSIDISASM> vInstructions; //temp holder for instructions
	//Get all headers and store exported functions (some duplication doesnt hurt)
	IMemory * lpcMemory = IMemory::init_get_instance();
	vector<ImageHeaderMemory *> vHeaders;
	lpcMemory->memory_get_module_headers( &vHeaders, nProcessId );
	IExeHandler * lpcExeHandler = IExeHandler::init_get_instance( vHeaders[0] );
	vector<Function *> vExports;

	for( int i = 0; i < (int)vHeaders.size(); i++ ) {
		dprintflvl( 3, "Getting exports of %s", 
			vHeaders[i]->get_image_name_ascii() );
		if( lpcExeHandler->get_image_exported_functions( lpcMemory, &vExports, 
			vHeaders[i] ) == FALSE ) {
				continue;
		}
	}

	//Scan memory based on filter for API calls
	InstructionFinder cInstructionFinder;
	vector<Address *> vAddresses;

	if( cInstructionFinder.find_instruction_in_exe( nProcessId, 
		lpcProtectionsFilter, &this->cApiCallPattern, &vAddresses ) == FALSE ) {
			return FALSE;
	}

	//Check API calls with exported functions
	SIDISASM sDisasm;
	RopGadget * lpGadget;
	if( this->sGadgetsBucket.vpBucket == NULL ) {
		MemoryAllocator::m_allocate_bucket( &this->sGadgetsBucket, 
			lpcMemory->memory_get_max_page_alloc_size() / sizeof(RopGadget), 
			sizeof(RopGadget), FALSE );
	}

	this->lpProcessor->setup_disassembler( &sDisasm, NULL, TRUE );

	for( int i = 0; i < (int)vAddresses.size(); i++ ) {
		sDisasm.VirtualAddress = (uiptr)vAddresses[i]->get_address();
		sDisasm.InstructionPointer = 
			(uiptr)vAddresses[i]->get_address_contents_buffer();

		this->lpProcessor->disassemble( &sDisasm );
		if( sDisasm.Instruction.Category != CONTROL_TRANSFER ) {
			dprintflvl( 3, "Not CONTROL_TRANSFER" );
			continue;
		}
		uiptr lpTargetAddress;
		if( sDisasm.Instruction.Operands[0].Type & OPERAND_MEMORY ) {
			// JMP [X] where X contains virtual address of API function
			lpcMemory->memory_get_address_contents( nProcessId, 
				(void *)sDisasm.Instruction.Operands[0].RegValMem.Memory.Displacement, 
				this->lpProcessor->get_stack_width() / 
				this->lpProcessor->get_sizeof_char_bits(), &lpTargetAddress );
		}
		//Too expensive to compute, consider first finding the page then match
		for( int j = 0; j < (int)vExports.size(); j++ ) {
			if( lpTargetAddress == 
				(uiptr)vExports[j]->get_function_virtual_address() ) {
					dprintflvl( 3, "Found matching ROP address calling %#X:%s",
						vExports[j]->get_function_virtual_address(), 
						vExports[j]->get_function_name() );
					lpGadget = (RopGadget *)MemoryAllocator::m_next_from_bucket( 
						&this->sGadgetsBucket );
					SIDISASM * lpsTmpDisasm = new SIDISASM();
					memcpy( lpsTmpDisasm, &sDisasm, sizeof( SIDISASM ) );
					vInstructions.push_back( lpsTmpDisasm );
					lpGadget->set_instructions( vInstructions );
					vInstructions.clear();
					lpGadget->add_category_flag( GC_FUNCCALL );
					lpGadget->assign_function( vExports[j] );
					this->vApiGadgets.push_back( lpGadget );
					break;
			}
		}
	}
	return TRUE;
}

vector<RopGadget *> * GadgetFinderX86::get_found_rop_gadgets()
{
	return &this->vRopGadgets;
}

vector<RopGadget *> * GadgetFinderX86::get_found_api_gadgets()
{
	return &this->vApiGadgets;
}

//Just implementing this, but we dont need it
BOOL GadgetFinderX86::fbCallback( void * lpArg )
{
	return FALSE;
}