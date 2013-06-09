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
class LIBEXPORT Address
{
public:
	Address(void);
	~Address(void);

	void * get_address( void );
	void * get_address_contents_buffer( void );
	unsigned long get_address_contents_size( void );

	void set_address( void * vpAddress );
	void set_address_contents_pointer( void * vpContentsAddress );
	void set_address_contents_size( unsigned long ulContentsSize );
private:
	void * vpAddress;
	void * vpContents;
	unsigned long ulContentsSize;

};
