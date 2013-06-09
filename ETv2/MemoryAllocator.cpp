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

#include "MemoryAllocator.h"
#include <stdlib.h>
#include <string.h>

#define mallocate( obj, objsize, objcast, erret ) \
	if( ( obj = (objcast)malloc( objsize )) == NULL ) { \
	PrintError("Memory Allocation Error\n"); \
	return erret; \
	}

#define  callocate( obj, ncount, nsize, objcast, erret ) \
	if( ( obj = (objcast)calloc( ncount, nsize )) == NULL ) { \
	PrintError("Memory Allocation Error\n"); \
	return erret; \
	}

#define callocate_object( obj, objtype, objcast, erret ) \
	if( ( obj = (objcast)calloc(1, sizeof(objtype))) == NULL ) { \
	PrintError("Memory Allocation Error\n"); \
	return erret; \
	}

MemoryAllocator::MemoryAllocator(void)
{
}


MemoryAllocator::~MemoryAllocator(void)
{
}

void * MemoryAllocator::m_allocate_bucket( 
	ps_bucket psBucket, 
	int nCount, 
	int nItemSize, 
	BOOL bRetItem 
) {
	void * vpTmp;
	if( nCount != 0 || nItemSize != 0 ) {
		callocate( vpTmp, nCount, nItemSize, void *, NULL );
		if( bRetItem == TRUE )
			psBucket->nCount = nCount - 1;
		else
			psBucket->nCount = nCount;
		if( nItemSize >= sizeof( s_retained_item ) ) {
			psBucket->bAbuseMemory = TRUE;
		}
		psBucket->nOrigCount = nCount;
		psBucket->vpBucket = vpTmp;
		psBucket->vpCurrent = vpTmp;
		psBucket->nItemSize = nItemSize;
		psBucket->psReallocBuckets = NULL;
		psBucket->psRetainedItems = NULL;
		return vpTmp;
	}
	return NULL;
}

void * MemoryAllocator::m_next_from_bucket( ps_bucket psBucket )
{
	void * vpReloc;
	void * vpTmpRet;
	int nNewSize;
	ps_realloc_bucket psRealloc;
	ps_realloc_bucket psReallocTmp;
	ps_retained_item psRetainedItem;

	if( psBucket->nCount == psBucket->nOrigCount ) {
		psBucket->nCount--;
		return psBucket->vpCurrent;
	}
	if( psBucket->nCount == 0 ) {
		if( psBucket->psRetainedItems != NULL ) {
			psRetainedItem = psBucket->psRetainedItems;
			vpTmpRet = psRetainedItem->vpMemory;
			psBucket->psRetainedItems = psRetainedItem->next;
			if( !psBucket->bAbuseMemory ) {
				free( psRetainedItem );
			}
			else {
				memset( vpTmpRet, 0, psBucket->nItemSize );
			}
			return vpTmpRet;
		}
		vpReloc = psBucket->vpBucket;
		nNewSize = psBucket->nItemSize * psBucket->nOrigCount * 2;
		mallocate( psRealloc, sizeof(s_realloc_bucket), ps_realloc_bucket, NULL);
		psRealloc->vpMemory = psBucket->vpBucket;
		psRealloc->next = NULL;

		if( psBucket->psReallocBuckets == NULL ) {
			psBucket->psReallocBuckets = psRealloc;
		}
		else {
			psRealloc->next = psBucket->psReallocBuckets;
			psBucket->psReallocBuckets = psRealloc;
		}

		callocate( psBucket->vpBucket, psBucket->nOrigCount * 2, 
			psBucket->nItemSize, void *, NULL );
		psBucket->vpCurrent = (void *) ( ((int)psBucket->vpBucket) - 
			((int)vpReloc) + ((int)psBucket->vpCurrent) );
		psBucket->nCount = psBucket->nOrigCount;
		psBucket->nOrigCount *= 2;
	}
	psBucket->vpCurrent = ((char *)psBucket->vpCurrent) + psBucket->nItemSize;
	psBucket->nCount--;
	return psBucket->vpCurrent;
}

void MemoryAllocator::m_free_bucket( ps_bucket psBucket )
{
	if( psBucket->vpBucket != NULL ) {
		free(psBucket->vpBucket);
	}
	psBucket->nCount = 0;
	psBucket->nItemSize = 0;
	psBucket->nOrigCount = 0;
	psBucket->vpCurrent = NULL;
}

BOOL MemoryAllocator::m_give_back_to_bucket( ps_bucket psBucket, void * vpItem )
{
	ps_retained_item psRetainedItem = NULL;
	ps_retained_item psRetainedItemNext = NULL;
	memset( vpItem, 0, psBucket->nItemSize );
	if( psBucket->bAbuseMemory ) {
		psRetainedItem = (ps_retained_item)vpItem;
		memset( ((unsigned char *)vpItem) + sizeof(s_retained_item), 0xcc, 
			psBucket->nItemSize - sizeof(s_retained_item) );
	}
	else {
		//We are not abusing here... we are doing something else...
		callocate_object( psRetainedItem, s_retained_item, ps_retained_item, 
			FALSE );
	}
	psRetainedItem->vpMemory = vpItem;
	if( psBucket->psRetainedItems == NULL ) {
		psBucket->psRetainedItems = psRetainedItem;
	}
	else {
		psRetainedItem->next = psBucket->psRetainedItems;
		psBucket->psRetainedItems = psRetainedItem;
	}
	return TRUE;
}