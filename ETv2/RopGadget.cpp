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

#include "RopGadget.h"


RopGadget::RopGadget(void)
{
	this->eGadgetCategory = GC_NONE;
	this->eGadgetType = GT_NONE;
	this->vInstructions = NULL;
}


RopGadget::~RopGadget(void)
{
	if( this->vInstructions != NULL ) {
		for( int i = 0; i < this->vInstructions->size(); i++ ) {
			delete vInstructions->at(i);
		}
	}
}

void RopGadget::add_category_flag( GADGET_CATEGORY eCategoryFlag )
{
	this->eGadgetCategory = 
		(GADGET_CATEGORY)(this->eGadgetCategory | eCategoryFlag);
}

void RopGadget::remove_category_flag( GADGET_CATEGORY eCategoryFlag )
{
	this->eGadgetCategory =
		(GADGET_CATEGORY)(this->eGadgetCategory ^ eCategoryFlag );
}

void RopGadget::add_type_flag( GADGET_TYPE eTypeFlag )
{
	this->eGadgetType = (GADGET_TYPE)(this->eGadgetType | eTypeFlag );
}

void RopGadget::remove_type_flag( GADGET_TYPE eTypeFlag )
{
	this->eGadgetType = (GADGET_TYPE)(this->eGadgetType ^ eTypeFlag );
}

void RopGadget::set_instructions( vector<PSIDISASM> vInstructions )
{
	this->vInstructions = new vector<PSIDISASM>( vInstructions );
	this->nGadgetSize = vInstructions.size();
}

vector<PSIDISASM> * RopGadget::get_instructions()
{
	return this->vInstructions;
}

void RopGadget::set_gadget_size( int nSize )
{
	this->nGadgetSize = nSize;
}

int RopGadget::get_gadget_size()
{
	return this->nGadgetSize;
}

void RopGadget::add_affected_register( IRegister * lpRegister )
{
	this->vAffectedRegisters.push_back( lpRegister );
}

void RopGadget::add_read_register( IRegister * lpRegister )
{
	this->vReadRegisters.push_back( lpRegister );
}

vector<IRegister *> * RopGadget::get_affected_registers()
{
	return &this->vAffectedRegisters;
}

vector<IRegister *> * RopGadget::get_read_registers()
{
	return &this->vReadRegisters;
}

void RopGadget::assign_function( Function * lpFunction )
{
	this->lpFunction = lpFunction;
}

Function * RopGadget::get_function()
{
	return this->lpFunction;
}

void RopGadget::set_gadget_address( unsigned long ulAddr )
{
	this->ulGadgetAddress = ulAddr;
}

unsigned long RopGadget::get_gadget_address()
{
	return this->ulGadgetAddress;
}

GADGET_CATEGORY RopGadget::get_gadget_category()
{
	return this->eGadgetCategory;
}

GADGET_TYPE RopGadget::get_gadget_type()
{
	return this->eGadgetType;
}