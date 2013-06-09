#ifndef __IDISASM_INTERNAL_H
#define __IDISASM_INTERNAL_H

#define IDISASM_VERSION "0.1.0"
#define _DLLRLS

#include <stdio.h>
#include "idisasm_include.h"
#include "types.h"



#define CONSUME_BYTES( lpDisasm, n ) \
	lpDisasm->InstructionSize += n; \
	lpDisasm->InstructionPointer += n;

typedef int ENUM_OPCODE_PTR_T;
typedef	int ENUM_OPCODE_CATEGORY_T;
typedef int ENUM_OPERAND_ADDRESSING_T;
typedef int ENUM_OPERAND_SIZE_T;

typedef enum _HINT_T {
	MAP_INVALID = 0, //Invalid, produce error
	MAP_OPCODE, //If opcode then get the values and populate INSTRUCTION
	MAP_PREFIX, //Prefix must pass INSTRUCTION through function
	MAP_ESCAPE, //Escape forwards to another map
	MAP_GROUP,
	MAP_SPECIAL
} HINT_T;


typedef struct {
	union {
		int eOpcodePtr; //ENUM_OPCODE_PTR
		uiptr * lpGroupMap;
	} uOpcodeMap;
	struct {
		ENUM_OPERAND_ADDRESSING_T eAddressing;
		union {
			ENUM_OPERAND_SIZE_T eSize;
			uiptr Immidiate;
		};
		OPERAND_ACCESS eReadWrite;
	} Parameters[3];
} INSTRUCTIONINTERNAL;

typedef struct _GROUP_MAP;

typedef struct _PLUGIN_MAP {
	HINT_T hint_t;
	union UITEM {
		INSTRUCTIONINTERNAL sInstruction;
		struct _PLUGIN_MAP * lpForwarderMap;
		struct _GROUP_MAP * lpGroupMap;
		int ( * prefix_handler )( PSIDISASM, uchar );
		//struct _dummy { struct _PLUGIN_MAP * lpForwarderMap; };
	} uItem;
} PLUGIN_MAP, * PPLUGIN_MAP;

typedef struct _GROUP_MAP {
	uint8 uMask;
	int nRightShift;
	PLUGIN_MAP sPluginMap[];
} GROUP_MAP;

typedef struct _INSTRUCTION_INFO {
	char * lpszName;
	ENUM_OPCODE_CATEGORY_T eCategory;
	char * lpszDescription;
} INSTRUCTION_INFO;

#define ADDRESSING_GIVEN 0
#define ADDRESSING_INVALID -1

//Each architecture should define its own indexing map (eg: INTEL_INDEXING_MAP)
typedef void * INDEXING_MAP;

typedef struct {
	union {
		int eHint;
		INDEXING_MAP * lpIndexMap;
	};
	OPERAND_TYPE eType;
	ENUM_OPERAND_ADDRESSING_T eAddressing;
} ADDRESSING_TOKEN;

typedef struct {
	uint8 Mask;
	uint8 RightShift;
	ADDRESSING_TOKEN eAddressing[];
} ADDRESSING_MAP;

//Wrapper for 2 addressing maps in one (eg: SIB base + SIB scaled index)
typedef struct {
	ADDRESSING_MAP * lpAddrMap1;
	ADDRESSING_MAP * lpAddrMap2;
} ADDRESSING_MAPS;

//Error/log functions
#define IDISASMDEBUG_LEVEL 0

#define LVL0 0
#define LVL1 1

#define dprintf( lvl, fmt, ... ) \
{ \
	if( lvl <= IDISASMDEBUG_LEVEL ) { \
		printf( "%s:%u: " fmt "\n", __FUNCTION__, __LINE__, ##__VA_ARGS__ ); \
	}\
}

#define eprintf( fmt, ... ) \
{ \
	printf( "[ERROR]:%s:%u: " fmt "\n", __FUNCTION__, __LINE__, ##__VA_ARGS__ ); \
}
#endif	//__IDISASM_INTERNAL_H