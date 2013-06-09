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
#include "IVulnerability.h"
#include "IDebugger.h"
using namespace std;
#include <vector>
#define VULNERABILITY_SBOF VULNERABILITY_0
#include "StackAnalysis.h"
#include "FuzzingPayload.h"
#include "ThreadStack.h"
#include "processor\IRegister.h"
#include "Pattern.h"
#include "Payload.h"
#include "InstructionFinder.h"

class LIBEXPORT StackBufferOverflow : public IVulnerability
{
public:
	StackBufferOverflow(void);
	~StackBufferOverflow(void);
	virtual char * get_vulnerability_name();
	virtual BOOL check_for_vulnerability( IDebugger * );
	virtual BOOL run_vulnerability_analysis( IDebugger * );
	virtual VULNERABILITY_TYPE get_vulnerability_type();
	virtual double get_vulnerability_score();
	virtual BOOL run_skeleton_implementation( IDebugger * );
	virtual Payload * get_payload();
	BOOL run_register_control_analysis( IDebugger *, Pattern * );
	BOOL run_skeleton_analysis( IDebugger * );
	/*
	** Runs a stack analysis of the last excepting thread
	** Arguments:
	**	IDebugger * lpDebugger - Pointer to the debugger hanlding the exception
	**	Pattern * lpcPattern - Pointer to the payload pattern that crashed the
	**	program.
	** Returns:
	**	TRUE - If the analysis was successful.
	**	FALSE - If the analysis was unsuccessful.
	*/
	BOOL run_stack_analysis( IDebugger * lpDebugger );
	int StackBufferOverflow::get_correct_pc_overflown_index( 
		unsigned long ulSPRealOffset, 
		unsigned char * lpucStackBufferBase,
		IRegister * lpobjPCRegister,
		int nMatchedPatternOffset, 
		Pattern * lpobjPattern,
		int nPatternWrapLocation );
private:
	double dScore;
	Payload * lpobjPayload;
	BOOL bClassificationFinished;
	BOOL bIsVulnerable;
	int nPatternSize;
	Pattern * lpobjVerifiedPattern;
	vector<IRegister *> vThreadRegisters;
	vector<IRegister *> vControllableRegisters;
	vector<vector<int>> vvControllableRegisterOffsets;
	ThreadStack * lpobjExceptingStack;
	unsigned long ulBufferStackPointer;
	BOOL bControlAnalysisFinished;
	vector<StackAnalysis *> vStackAnalysis;
	int nVulnerabilityScore;
	int nPCOverflowOffset;
	InstructionFinder * lpobjInstructionFinder;
	//vector<Address *> vReturnAddresses;
	
};

