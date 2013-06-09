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

typedef struct _s_realloc_bucket {
	struct _s_realloc_bucket * next;
	void * vpMemory;
} s_realloc_bucket, * ps_realloc_bucket;

typedef struct _s_retained_item {
	struct _s_retained_item * next;
	void * vpMemory;
} s_retained_item, * ps_retained_item;


typedef struct {
	void * vpBucket;
	void * vpCurrent;
	int nCount;
	int nOrigCount;
	int nItemSize;
	BOOL bAbuseMemory;
	ps_realloc_bucket psReallocBuckets;
	ps_retained_item psRetainedItems;
} s_bucket, * ps_bucket;

class MemoryAllocator
{
public:
	MemoryAllocator(void);
	~MemoryAllocator(void);
	static void * m_allocate_bucket( ps_bucket psBucket, int nCount, 
		int nItemSize, BOOL bRetItem );

	static void * m_next_from_bucket( ps_bucket psBucket );
	static void m_free_bucket( ps_bucket psBucket );
	static BOOL m_give_back_to_bucket( ps_bucket psBucket, void * vpItem );
};

