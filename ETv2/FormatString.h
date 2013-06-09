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
#include "StackAnalysis.h"
#define VULNERABILITY_FORMATSTRING VULNERABILITY_2
class LIBEXPORT FormatString : public IVulnerability
{
public:
	FormatString(void);
	~FormatString(void);
	virtual char * get_vulnerability_name();
	virtual BOOL check_for_vulnerability( IDebugger * );
	virtual BOOL run_vulnerability_analysis( IDebugger * );
	virtual VULNERABILITY_TYPE get_vulnerability_type();
	virtual BOOL run_skeleton_implementation( IDebugger * );
	virtual double get_vulnerability_score();
	Payload * get_payload();
};

