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

#include "SehBufferOverflow.h"


SehBufferOverflow::SehBufferOverflow(void)
{
}


SehBufferOverflow::~SehBufferOverflow(void)
{
}

char * SehBufferOverflow::get_vulnerability_name()
{
	return "SEH Buffer Overflow";
}

BOOL SehBufferOverflow::check_for_vulnerability( IDebugger * )
{
	return FALSE;
}

BOOL SehBufferOverflow::run_vulnerability_analysis( IDebugger * )
{
	return FALSE;
}

VULNERABILITY_TYPE SehBufferOverflow::get_vulnerability_type()
{
	return VULNERABILITY_SEH;
}

double SehBufferOverflow::get_vulnerability_score()
{
	return 0;
}

BOOL SehBufferOverflow::run_skeleton_implementation( IDebugger * )
{
	return FALSE;
}

Payload * SehBufferOverflow::get_payload()
{
	return NULL;
}