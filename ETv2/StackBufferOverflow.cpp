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

#include "StackBufferOverflow.h"
#include "Pattern.h"
#include "DataEncoder.h"
#include "IMemory.h"
#include "processor\IProcessorArchitecture.h"
#include "InstructionFinder.h"
#include "IProtections.h"


StackBufferOverflow::StackBufferOverflow(void)
{
	this->nVulnerabilityScore = 0;
	this->bControlAnalysisFinished = FALSE;
	this->dScore = 0.0;
	this->lpobjPayload = NULL;
	this->lpobjInstructionFinder = NULL;
}


StackBufferOverflow::~StackBufferOverflow(void)
{
	if( this->lpobjInstructionFinder != NULL ) {
		delete this->lpobjInstructionFinder;
	}
}

double StackBufferOverflow::get_vulnerability_score()
{
	return this->nVulnerabilityScore;
}

char * StackBufferOverflow::get_vulnerability_name()
{
	return "Stack Buffer Overflow";
}

/*
Calculate and find out whether one or more registers are controlled by using
the standard pattern matching methodologies.
*/
BOOL StackBufferOverflow::check_for_vulnerability( IDebugger * lpDebugger )
{

	if( this->bClassificationFinished == TRUE ) {
		return this->bIsVulnerable;
	}

	Pattern * lpobjPattern = new Pattern();
	IProcessorArchitecture * lpobjProcessorArchitecture = 
		IProcessorArchitecture::init_get_instance();
	lpobjPattern->pattern_set_default_sets();
	this->bClassificationFinished = TRUE;

	this->nVulnerabilityScore = 0;
	IRegister * lpobjRegister = IRegister::init_get_instance();

	//Generate a pattern with all possible values that a register can get
	char * lpszMaxPattern = lpobjPattern->pattern_create( MAX_WRAP_SIZE + 
		lpobjRegister->get_register_size() / 
		lpobjProcessorArchitecture->get_sizeof_char_bits() );

	if( this->run_register_control_analysis( lpDebugger, 
		lpobjPattern ) == FALSE ) {
			dprintflvl( 2, "Error running register control analysis" );
			return FALSE;
	}

	//Lets run a typical overflow analysis with most commonly used buffers
	if( this->vControllableRegisters.size() == 0 ) {	
		lpobjPattern->pattern_release_pattern();
		lpobjPattern->pattern_set_characters_set( 1, "A" );
		//Generate pattern "A" * sizeof( register )
		lpobjPattern->pattern_create( lpobjRegister->get_register_size() / 
			lpobjProcessorArchitecture->get_sizeof_char_bits() );
		if( this->run_register_control_analysis( lpDebugger, lpobjPattern ) 
			== FALSE ) {
				dprintflvl( 2, "Error running register control analysis" );
				return FALSE;
		}
	}

	if( this->vControllableRegisters.size() == 0 ) {
		lpobjPattern->pattern_release_pattern();
		lpobjPattern->pattern_set_characters_set( 1, "B" );
		//Generate pattern "A" * sizeof( register )
		lpobjPattern->pattern_create( lpobjRegister->get_register_size() / 
			lpobjProcessorArchitecture->get_sizeof_char_bits() );
		if( this->run_register_control_analysis( lpDebugger, lpobjPattern ) 
			== FALSE ) {
				dprintflvl( 2, "Error running register control analysis" );
				return FALSE;
		}
	}

	if( this->vControllableRegisters.size() == 0 ) {
		dprintflvl( 3, "Not a stack buffer overflow..." );
		return FALSE;
	}
	this->lpobjVerifiedPattern = lpobjPattern;
	this->bIsVulnerable = TRUE;
	this->nVulnerabilityScore = 50;
	this->dScore = 50; //50% for controlling a register
	return TRUE;
}

/*
Using the register control match pattern found in the check_for_vulnerability
step, calculate the exact location where PC is controlled.
*/
BOOL StackBufferOverflow::run_vulnerability_analysis( IDebugger * lpobjDebugger)
{
		IMemory * lpcMemory = IMemory::init_get_instance();
	vector<ThreadStack *> vStacks;

	//Get stack of last excepting thread
	if( lpcMemory->memory_get_proc_stacks( &vStacks, 
		lpobjDebugger->get_process_id(), 
		(int)lpobjDebugger->debugger_get_last_exception_thread() ) == FALSE ) {
			return FALSE;
	}

	//Get the actual contents of the stack
	ThreadStack * lpcThreadStack = vStacks[0];
	this->lpobjExceptingStack = lpcThreadStack;

	lpcThreadStack->allocate_buffer_for_page();
	if( lpcMemory->memory_get_memory_page_contents( 
		lpobjDebugger->get_process_id(), 
		lpcThreadStack, 
		lpcThreadStack->get_memory_page_contents_buffer(), 
		lpcThreadStack->get_page_size() ) == FALSE ) {
			return FALSE;
	}


	dprintflvl( 4, "Scanning Injected payload from Overflown EIP" );

	//Get registers of last excepting thread
	lpobjDebugger->debugger_get_registers( &this->vThreadRegisters, 
		(int)lpobjDebugger->debugger_get_last_exception_thread() );

	//Get the stack pointer register
	IRegister * lpStackPointer = 
		IRegister::get_register( &this->vThreadRegisters, IRegister::REG_SP );

	if( lpStackPointer == NULL ) {
		dprintflvl( 2, "Unknown Error, unable to get the stack pointer" );
		return FALSE;
	}

	//Get the index of PC
	int nPCRegisterIndex = IRegister::get_register_index( 
		&this->vControllableRegisters, IRegister::REG_PC );

	if( nPCRegisterIndex == -1 ) {
		dprintflvl( 2, "PC not controlled, why did you even call this function?");
		return FALSE;
	}

	//Get PC Register and controllable PC offsets
	vector<int> vControllablePCOffsets = 
		this->vvControllableRegisterOffsets[nPCRegisterIndex];
	IRegister * lpcPCRegister = this->vControllableRegisters[nPCRegisterIndex];

	/*
	** XXX this code assumes that reg value fits into an unsigned long...
	** Calculate the actual stack offset of the stack pointer from the beginning
	** of the stack buffer
	*/
	unsigned long ulRealStackOffset = 
		*((unsigned long *)lpStackPointer->get_register_value()) - 
		(unsigned long)lpcThreadStack->get_baseaddress();

	//Get the actual stack buffer
	unsigned char * lpucStackBuffer = 
		lpcThreadStack->get_memory_page_contents_buffer() + ulRealStackOffset;
	
	this->nPCOverflowOffset = -1;

	int nMaxWrapSize = MAX_WRAP_SIZE;

	IProcessorArchitecture * lpobjArchitecture = 
		IProcessorArchitecture::init_get_instance();

	//If verified control pattern == register size (eg AAAA set wrap size to 4 )
	if( this->lpobjVerifiedPattern->get_pattern_size() == 
		lpcPCRegister->get_register_size() / 
		lpobjArchitecture->get_sizeof_char_bits() ) {
			nMaxWrapSize = lpobjVerifiedPattern->get_pattern_size();
	}
	//Only the first pattern match is needed to calculate offset
	this->nPCOverflowOffset = this->get_correct_pc_overflown_index( 
		ulRealStackOffset, lpcThreadStack->get_memory_page_contents_buffer(), 
		lpcPCRegister, vControllablePCOffsets[0], this->lpobjVerifiedPattern, 
		nMaxWrapSize  );

	if( this->nPCOverflowOffset == -1 ) {
		dprintflvl( 2, "No controllable offset found for IP");
		return FALSE;
	}

	//Setting up the payload

	this->lpobjPayload = new Payload();
	this->lpobjPayload->append_payload( PAYLOAD_RANDOM, 
		this->nPCOverflowOffset - 1, NULL, NULL );

	
	this->lpobjPayload->append_payload( PAYLOAD_ADDRESS,
		lpcPCRegister->get_register_size() / 
		lpobjArchitecture->get_sizeof_char_bits(), NULL, NULL );

	this->dScore += 50; //50% for controlling PC = 100% eventually.
	return TRUE;
}

IProtections::PROTECTION_FILTER eStackBufferOverflowProtFilter = 
	IProtections::PROTECTION_ASLR;

BOOL StackBufferOverflow::run_skeleton_implementation( IDebugger * lpDebugger )
{
	if( this->lpobjPayload == NULL ) return NULL;
	HexPattern objHexPattern;
	this->lpobjInstructionFinder = new InstructionFinder();
	IProcessorArchitecture * lpArchitecture = 
		IProcessorArchitecture::init_get_instance();
	IProtections * lpobjProtections = IProtections::init_get_instance();

	lpobjProtections->apply_protection_filter( eStackBufferOverflowProtFilter );
	
	//Get pattern from architecture and parse it.
	objHexPattern.parse_pattern( 
		lpArchitecture->get_return_to_stack_strpattern( 
		&this->vControllableRegisters ) );

	vector<Address *> * lpvAddresses = new vector<Address *>;
	if( this->lpobjInstructionFinder->find_instruction_in_exe( 
		lpDebugger->get_process_id(), lpobjProtections, &objHexPattern, 
		lpvAddresses ) == FALSE ) {
			PrintError( "Error getting instructions" );
			return FALSE;
	}

	if( lpvAddresses->size() == 0 ) {
		return FALSE;
	}

	/*
	Resulting structure should be [RANDOM/CODE][ADDR/ADDR_MULT][CODE].
	So we modify the original payload from exploitability analysis into a fully
	working buffer (since we should have everything we need at this point).
	*/
	Payload * lpPayload = new Payload();

	IRegister * lpStackPointer = IRegister::get_register( 
		&this->vThreadRegisters, IRegister::REG_SP );

	if( lpStackPointer == NULL ) {
		PrintError( "Unable to retrieve stack pointer" );
		return FALSE;
	}

	int nRegisterSize = lpStackPointer->get_register_size() / 
		lpArchitecture->get_sizeof_char_bits();

	//Payload starts at LocalStackBuffer + SP - LocalStackBufferBase - PC Offset
	unsigned char * lpPayloadStartPtr = (unsigned char *)
		(lpobjExceptingStack->get_memory_page_contents_buffer() +
		*((unsigned long *)lpStackPointer->get_register_value()) - 
		(unsigned long)this->lpobjExceptingStack->get_baseaddress() - 
		this->nPCOverflowOffset );

	unsigned char * lpStackBottom = 
		(unsigned char *)lpobjExceptingStack->get_memory_page_contents_buffer() + 
		lpobjExceptingStack->get_page_size();

	//Run stack corruption check for pre-PC buffer here
	char * lpPattern = this->lpobjVerifiedPattern->pattern_get_pattern();
	int nPatternSize = this->lpobjVerifiedPattern->get_pattern_size();
	int nIndex = 0;
	int nStartIndex = 0;
	int nCorrputionStartPtr = 0;
	int nPatternIndex = 0;
	int nValidCharsSoFar = 0;
	BOOL bInCorruptedSpace = FALSE;
	BOOL bContinue = TRUE;
	//XXX Should probably move this in Pattern.get_next_corrputed or somthn
	while( bContinue ) {
		if( nIndex == this->nPCOverflowOffset ) {
			//Push available PC addresses
			lpPayload->append_addresses_payload( nRegisterSize, lpvAddresses );
			nIndex += nRegisterSize;
			nPatternIndex += nRegisterSize;
			if( nPatternIndex >= nPatternSize ) {
				nPatternIndex = nPatternIndex % nPatternSize;
				//nPatternSize = nIndex - nPatternSize;
			}
			nValidCharsSoFar = 0;
			continue;
		}
		if(nIndex % nPatternSize == 0 ) {
			nPatternIndex = 0;
		}
		if( bInCorruptedSpace == FALSE ) {
			nValidCharsSoFar++;
		}
		if( bInCorruptedSpace == FALSE && *(lpPayloadStartPtr+nIndex) != 
			*(lpPattern+nPatternIndex) && nValidCharsSoFar > 5 ) {
				//Found corruption, pushing last and entering corruption space
				nCorrputionStartPtr = nIndex;
				if( nIndex != 0 ) {
					lpPayload->append_payload( PAYLOAD_CODE, 
						nIndex - 1 - nStartIndex, NULL, NULL );
				}
				bInCorruptedSpace = TRUE;
				nValidCharsSoFar = 0;
				//nStartIndex = nIndex;
		}
		else if( bInCorruptedSpace == TRUE && *(lpPayloadStartPtr+nIndex) == 
			*(lpPattern+nPatternIndex) && nValidCharsSoFar > 5 ) {
				//Exited corruption space
				lpPayload->append_payload( PAYLOAD_BAD, 
					nIndex - 1 - nCorrputionStartPtr, NULL, NULL );
				bInCorruptedSpace = FALSE;
				nStartIndex = nIndex;
		}
		else if( nIndex + 1 == this->nPCOverflowOffset ) {
			//Since the next loop would take us to PC overwrite offset
			//no need for nIndex - 1 here
			lpPayload->append_payload( PAYLOAD_CODE, nIndex - nStartIndex, 
				NULL, NULL );
		}
		
		if( lpPayloadStartPtr+nIndex >= lpStackBottom ) {
			if( bInCorruptedSpace ) {
				lpPayload->append_payload( PAYLOAD_BAD, 
					nIndex - 1 - nCorrputionStartPtr, NULL, NULL );
			}
			bContinue = FALSE;
		}
		nIndex++;
		nPatternIndex++;
	}

	delete this->lpobjPayload;
	this->lpobjPayload = lpPayload;
	return TRUE;
}

VULNERABILITY_TYPE StackBufferOverflow::get_vulnerability_type()
{
	return VULNERABILITY_SBOF;
}

BOOL StackBufferOverflow::run_register_control_analysis( IDebugger * lpDebugger,
	Pattern * lpcPattern )
{
	vector<IRegister *> vRegisters;
	IProcessorArchitecture * lpobjArchitecutre = 
		IProcessorArchitecture::init_get_instance();

	this->nPatternSize = lpcPattern->get_pattern_size();
	lpDebugger->debugger_get_registers( &vRegisters, 
		(int)lpDebugger->debugger_get_last_exception_thread() );

	dprintflvl( 4, "Enumerating Registers" );
	for( int i = 0; i < (int)vRegisters.size(); i++ ) {
		int nRegisterSizeInChars = vRegisters[i]->get_register_size() / 
			lpobjArchitecutre->get_sizeof_char_bits();
		//void * lpvRegisterValue = vRegisters[i]->get_register_value();
		void * lpvRegValue = ( !vRegisters[i]->is_little_endian() ) ? 
			DataEncoder::swap_endianess( vRegisters[i]->get_register_value(), 
			vRegisters[i]->get_register_size() ) :
		vRegisters[i]->get_register_value();

		char * lpszRegisterValue = DataEncoder::htoa( lpvRegValue, 
			nRegisterSizeInChars );

		dprintflvl( 4, "Register: %s Value: 0x%s", 
			vRegisters[i]->get_register_name(), lpszRegisterValue );

		/*
		//Allocate space for pattern, if 32bit processor then 4 chars + 1 null
		char * lpszNiddle = (char *)malloc( nRegisterSizeInChars + 1 );

		*(lpszNiddle + nRegisterSizeInChars) = '\0';

		*((unsigned long *)lpszNiddle) = *lpvRegValue;
		*/
		dprintflvl( 4, "Initiating Pattern Search for register" );
		vector<int> vMatchedPatterns = lpcPattern->pattern_search( 
			this->nPatternSize, (char *)lpvRegValue, nRegisterSizeInChars );

		if( vMatchedPatterns.size() == 0 ) {
			dprintflvl( 4, "No Patterns found, skipping to next register" );
			continue;
		}

		dprintflvl( 4, "Found Matched patterns at offsets:" );
		for( int j = 0; j < (int)vMatchedPatterns.size(); j++ ) {
			dprintflvl( 4, "\tOffset: 0x%08X (%d)", vMatchedPatterns[j], 
				vMatchedPatterns[j] );
		}

		this->vControllableRegisters.push_back( vRegisters[i] );
		this->vvControllableRegisterOffsets.push_back( vMatchedPatterns );
	}
	this->bControlAnalysisFinished = TRUE;
	return TRUE;
}

//XXX [FIXED] This algorithm does not work if the vulnerable function is responsible
//for cleaning up the stack (fastcall/stdcall/etc) and the number of fixed
//arguments exceeds 5070~ (or ( MAX_WRAP_SIZE + register size ) / 4 )...d'oh
int StackBufferOverflow::get_correct_pc_overflown_index( 
	unsigned long ulSPRealOffset, 
	unsigned char * lpucStackBufferBase,
	IRegister * lpobjPCRegister,
	int nMatchedPatternOffset, 
	Pattern * lpobjPattern,
	int nPatternWrapLocation
)
{
	IProcessorArchitecture * lpobjArchitecture = 
		IProcessorArchitecture::init_get_instance();
	
	int nRegisterSizeInChars = lpobjPCRegister->get_register_size() / 
		lpobjArchitecture->get_sizeof_char_bits();

	/*
	** SP - 0x04 (for pop) - RL(PC) - Matched Offset = beginning of pattern
	** RL(PC) stands for the relative offset of PC from SP. If last instruction
	** was RETN then that is sizeof(PC). If last instruction was RETN N then that
	** is sizeof(PC) + N
	*/
	unsigned long ulPCOverwriteOffset = ulSPRealOffset - nRegisterSizeInChars;
	unsigned char * lpvRegisterValue = (unsigned char *)lpobjPCRegister->get_register_value();
	unsigned char * ulStackLookupOffset = lpucStackBufferBase + ulPCOverwriteOffset;

	int nLookbackOffset = 0;
	BOOL bMatched = FALSE;

	while( !bMatched ) {
		if( nLookbackOffset >= ( MAX_WRAP_SIZE + nRegisterSizeInChars ) / 4 ) {
			dprintflvl( 4, "Reached the maximum lookup length");
			return -1;
		}
		if( ( ulPCOverwriteOffset - nLookbackOffset ) <= 0 ) {
			dprintflvl( 4, "Reached top of the stack" );
			return -1;
		}
		bMatched = TRUE;
		for( int i = 0; i < nRegisterSizeInChars; i++ ) {
			if( *(lpvRegisterValue+i) != *(ulStackLookupOffset - nLookbackOffset + i) ) {
				bMatched = FALSE;
				break;
			}
		}

		if( bMatched == FALSE ) {
			nLookbackOffset += nRegisterSizeInChars;
			//ulPCOverwriteOffset -= nLookbackOffset;
		}
	}
	ulPCOverwriteOffset -= nLookbackOffset;

	char * lpszPattern = lpobjPattern->pattern_get_pattern();
	char * lpszLastPatternChars = NULL;

	//Get the last sizeof( unsigned long ) characters inside the pattern.
	if( lpobjPattern->get_pattern_size() == sizeof( unsigned long ) ) {
		lpszLastPatternChars = lpszPattern;
	}
	else {
		lpszLastPatternChars = lpszPattern + lpobjPattern->get_pattern_size() - 
			sizeof( unsigned long );
	}
	
	int nMatchedOffset = -1;
	unsigned long * lpulStackLocation = NULL;
	do {
		lpulStackLocation = (unsigned long *)( lpucStackBufferBase + 
			( ulPCOverwriteOffset - nMatchedPatternOffset ) );

		if( lpulStackLocation < (unsigned long *)lpucStackBufferBase && 
			lpulStackLocation-1 < (unsigned long *)lpucStackBufferBase ) {
				dprintflvl( 4, "We reached the top of the stack");
				break;
		}
		if( *lpulStackLocation == *((unsigned long *)lpszPattern) ) {
			if( *(lpulStackLocation-1) != *((unsigned long *)lpszLastPatternChars ) ) {
				dprintflvl( 4, "Found possible matched offset at 0x%X", 
					nMatchedPatternOffset );
				nMatchedOffset = nMatchedPatternOffset;
			}
		}
		nMatchedPatternOffset += nPatternWrapLocation;
	} while( (unsigned long)lpulStackLocation > (unsigned long)lpucStackBufferBase );
	return nMatchedOffset;
}

Payload * StackBufferOverflow::get_payload()
{
	return this->lpobjPayload;
}
/*
BOOL StackBufferOverflow::run_stack_analysis( IDebugger * lpDebugger )
{
	IMemory * lpcMemory = IMemory::init_get_instance();
	vector<ThreadStack *> vStacks;

	//Get stack of last excepting thread
	if( lpcMemory->memory_get_proc_stacks( &vStacks, 
		lpDebugger->get_process_id(), 
		(int)lpDebugger->debugger_get_last_exception_thread() ) == FALSE ) {
			return FALSE;
	}

	//Get the actual contents of the stack
	ThreadStack * lpcThreadStack = vStacks[0];
	lpcThreadStack->allocate_buffer_for_page();
	if( lpcMemory->memory_get_memory_page_contents( 
		lpDebugger->get_process_id(), 
		lpcThreadStack, 
		lpcThreadStack->get_memory_page_contents_buffer(), 
		lpcThreadStack->get_page_size() ) == FALSE ) {
			return FALSE;
	}

	dprintflvl( 4, "Scanning Injected payload from Overflown EIP" );

	//XXX this code assumes that reg value fits into an unsigned long...
	//unsigned long dwSPOffset = NULL;

	//Get registers of last excepting thread
	vector<IRegister *> vRegisters;
	lpDebugger->debugger_get_registers( &vRegisters, 
		(int)lpDebugger->debugger_get_last_exception_thread() );

	//Get the stack pointer register
	IRegister * lpStackPointer = 
		IRegister::get_register( &vRegisters, IRegister::REG_SP );

	if( lpStackPointer == NULL ) {
		dprintflvl( 2, "Unknown Error, unable to get the stack pointer" );
		return FALSE;
	}

	//Get the index of PC
	int nPCRegisterIndex = IRegister::get_register_index( 
		&this->vControllableRegisters, IRegister::REG_PC );

	if( nPCRegisterIndex == -1 ) {
		dprintflvl( 2, "PC not controlled, why did you even call this function?");
		return FALSE;
	}

	//Get PC Register and controllable PC offsets
	vector<int> vControllablePCOffsets = 
		this->vvControllableRegisterOffsets[nPCRegisterIndex];
	IRegister * lpcPCRegister = this->vControllableRegisters[nPCRegisterIndex];

	//Calculate the actual stack offset of the stack pointer from the beginning of the stack buffer
	unsigned long ulRealStackOffset = 
		*((unsigned long *)lpStackPointer->get_register_value()) - 
		(unsigned long)lpcThreadStack->get_baseaddress();

	//Get the actual stack buffer
	unsigned char * lpucStackBuffer = 
		lpcThreadStack->get_memory_page_contents_buffer() + ulRealStackOffset;
	
	int nCorrectPCOffsetIndex = 0;

	//Only the first pattern match is needed to calculate offset
	nCorrectPCOffsetIndex = this->get_correct_pc_overflown_index( 
		ulRealStackOffset, lpcThreadStack->get_memory_page_contents_buffer(), 
		lpcPCRegister, vControllablePCOffsets[0], this->lpobjVerifiedPattern, 
		MAX_WRAP_SIZE  );
	
	/*
	if( vControllablePCOffsets.size() > 1 ) {
		dprintflvl( 4, "More than one possible pattern matches for PC" );
		
		nCorrectPCOffsetIndex = this->get_correct_pc_overflown_index( 
			ulRealStackOffset, lpucStackBuffer, lpcPCRegister, 
			&vControllablePCOffsets, lpcPattern );
		if( nCorrectPCOffsetIndex == -1 ) {
			dprintflvl( 2, "Error identifying PC overwrite offset" );
			return FALSE;
		}
	}
	

	return FALSE;

	/*




	int nSPRegisterIndex = IRegister::get_register_index( 
		&this->vControllableRegisters, IRegister::REG_SP );
	if( nSPRegisterIndex != -1 ) {
		dprintflvl( 4, "Stack pointer corrupted?" );
		//Need to handle this...
		return FALSE;
	}


	//Calculate the actual offset that PC is overflown (assumes that SP is not corrupted)

	//dwRealStackOffset - 4 // SP - 4 should point at value that overflown PC

	char * lpszPattern = lpcPattern->pattern_get_pattern();
	char * lpszOffsettedPattern = NULL;
	unsigned char * lpucStackBufferTmp = NULL;
	int nOffsettedPatternLength = 0;
	BOOL bNonJmpFlag;
	for( int i = 0; i < (int)vControllablePCOffsets.size(); i++ ) {
		dprintflvl( 4, "Testing %d pattern match", i );
		bNonJmpFlag = TRUE;
		lpucStackBufferTmp = lpucStackBuffer;
		lpszOffsettedPattern = lpszPattern + vControllablePCOffsets[i] + 
			lpcPCRegister->get_register_size() / sizeof( char ); //XXX ProcessorArchitecture this
		StackAnalysis * lpcStackAnalysis = new StackAnalysis();

		do {
			if( *lpucStackBufferTmp != *lpszOffsettedPattern ) {
				lpcStackAnalysis->nJunkBytes++;
				bNonJmpFlag = FALSE;
			}
			else {
				lpcStackAnalysis->nValuableSize++;
				if( bNonJmpFlag ) {
					lpcStackAnalysis->nNonJmpSize++;
				}
			}
		} while( ++lpszOffsettedPattern, ++lpucStackBufferTmp );

		dprintflvl( 4, "Analysis Complete:");
		dprintflvl( 4, 
			"\tTotal Number of Junk Bytes: %d\n"
			"\tTotal Number of Non Jmp Bytes: %d\n"
			"\tTotal Number of good bytes: %d", 
			lpcStackAnalysis->nJunkBytes,
			lpcStackAnalysis->nNonJmpSize,
			lpcStackAnalysis->nValuableSize );

		this->vStackAnalysis.push_back( lpcStackAnalysis );
	}
	return TRUE;
	
}
*/
// 
// unsigned long StackBufferOverflow::get_pattern_starting_address( 
// 	Pattern * lpobjPattern, 
// 	IRegister * lpobjStackPointer, 
// 	ThreadStack * lpobjThreadStack 
// )
// {
// 	char * lpszPattern = lpobjPattern->pattern_get_pattern();
// 	unsigned long ulBufferSP = (unsigned long)lpobjStackPointer->get_register_value() - 
// 		(unsigned long)lpobjThreadStack->get_baseaddress();
// 
// 	
// }