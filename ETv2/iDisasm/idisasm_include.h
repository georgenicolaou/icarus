/*
Copyright (C) 2013 George Nicolaou <george[at]preaver.[dot]com>

This file is part of Icarus Disassembly Engine (iDisasm).

Icarus Disassembly Engine (iDisasm) is free software: you can redistribute it
and/or modify it under the terms of the GNU Lesser General Public License as
published by the Free Software Foundation, either version 3 of the License,
or (at your option) any later version.

Icarus Disassembly Engine (iDisasm) is distributed in the hope that it will be
useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General
Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with Icarus Disassembly Engine (iDisasm). If not, see
<http://www.gnu.org/licenses/>.
*/

#ifndef _IDISASM_INCLUDE_H
#define _IDISASM_INCLUDE_H

#include "types.h"
#ifndef IDISASM_API
#define IDISASM_API
#endif

#define MAX_INSTRUCTION_MNEMONIC_SIZE 45

typedef enum {
	X86 = 0,
	X86_64,
	ARM,
} ARCHITECTURE;

#define INSTRUCTION_INVALID -1
#define INSTRUCTION_VALID 1
#define ENGINE_ERROR 2

typedef enum {
	NONE =	0,
	READ,
	WRITE,
	READWRITE,
	REFERENCE = 0x80000000
} OPERAND_ACCESS;

#define OPERAND_ACCESS_TYPE 0x00FFFFFF

typedef enum {
	BIT_INVALID = -1,
	BIT_NONE = 0,
	BIT8 = 8,
	BIT16 = 16,
	BIT32 = 32,
	BIT48 = 48,
	BIT64 = 64,
	BIT128 = 128,
	BIT256 = 256
} BITSIZE;


/*
0xffff0000 for operand type (register/memory/immidiate)
0x0000ffff for register type
*/
typedef enum {
	OPERAND_NONE			= 0x00000000,
	OPERAND_REGISTER		= 0x01000000,
	OPERAND_MEMORY			= 0x02000000,
	OPERAND_IMMIDIATE		= 0x04000000,
	OPERAND_IMMIDIATE_ADDR	= 0x08000000,
	OPERAND_ALL				= 0x0F000000, //REG+MEM+IMM+IMMADDR
	//OPERAND_DISPLACEMENT = 0x10000000,

	TYPE_REG_GENERAL	= 0x00000001,
	TYPE_REG_SPECIAL_0, //MMX
	TYPE_REG_SPECIAL_1, //FPU
	TYPE_REG_SPECIAL_2, //SSE
	TYPE_REG_SPECIAL_3, //CR
	TYPE_REG_SPECIAL_4, //etc...
	TYPE_REG_SPECIAL_5,
	TYPE_REG_SPECIAL_6,
	TYPE_REG_SPECIAL_7,
	TYPE_REG_SPECIAL_8,
	TYPE_REG_SPECIAL_9,
} OPERAND_TYPE;

#define OPERAND_TYPE_TYPE_MASK 0xFF000000
#define OPERAND_TYPE_REGISTER_MASK 0x00FFFFFF

typedef enum {
	REG_NIL	= 0,
	REG_0	= 0x00000001, //RAX/EAX/AX/AL
	REG_1	= 0x00000002, //RCX/ECX/CX/CL
	REG_2	= 0x00000004, //RDX/EDX/DX/DL
	REG_3	= 0x00000008, //RBX/EBX/BX/BL
	REG_4	= 0x00000010, //RSP/ESP/SP/SPL
	REG_5	= 0x00000020, //RBP/EBP/BP/BP
	REG_6	= 0x00000040, //RSI/ESI/SI/SPL
	REG_7	= 0x00000080, //RDI/EDI/DI
	REG_8	= 0x00000100, //AH
	REG_9	= 0x00000200, //CH
	REG_10	= 0x00000400, //DH
	REG_11	= 0x00000800, //BH
	REG_12	= 0x00001000,// SPH
	REG_13	= 0x00002000,
	REG_14	= 0x00004000,
	REG_15	= 0x00008000,
	//...
	
	REG_SPECIAL_0	= 0x00010000, //ES
	REG_SPECIAL_1	= 0x00020000, //CS
	REG_SPECIAL_2	= 0x00040000, //SS
	REG_SPECIAL_3	= 0x00080000, //DS
	REG_SPECIAL_4	= 0x00100000, //FS
	REG_SPECIAL_5	= 0x00200000, //GS
} REG;

typedef enum {
	AR_INVALID = 0,
	AR_0, //ES
	AR_1, //CS
	AR_2, //
	AR_3,
	AR_4,
	AR_5,
	AR_6,
	AR_REGISTER = 0x10000000,
	AR_ADDRESS	= 0x20000000
} ADDRESSING_REGISTER;

#define AR_TYPE 0xFF000000
#define AR_REGVAL 0x00FFFFFF

typedef enum {
	PREFIX_NONE = 0,
	PREFIX_0	= 0x00000001,
	PREFIX_1	= 0x00000002,
	PREFIX_2	= 0x00000004,
	PREFIX_3	= 0x00000008,
	PREFIX_4	= 0x00000010,
	PREFIX_5	= 0x00000020,
	PREFIX_6	= 0x00000040,
	PREFIX_7	= 0x00000080,
	PREFIX_8	= 0x00000100,
	PREFIX_9	= 0x00000200,
	PREFIX_10	= 0x00000400,
	PREFIX_11	= 0x00000800,
	PREFIX_12	= 0x00001000,
	PREFIX_13	= 0x00002000,
} PREFIXES;

typedef int ENUM_OPCODE_PTR_T;
typedef	int ENUM_OPCODE_CATEGORY_T;
typedef int ENUM_OPERAND_ADDRESSING_T;
typedef int ENUM_OPERAND_SIZE_T;

typedef struct {
	REG BaseRegister;
	REG IndexRegister;
	int8 Scale;
	int32 Displacement;
} MEMORYOPERAND;

typedef struct {
	OPERAND_TYPE Type;
	OPERAND_ACCESS Access;
	BITSIZE BitSize;
	BITSIZE AddressingSize;
	ADDRESSING_REGISTER AddrRegister; //Segment on Intel
	union {
		REG Register;
		uiptr Value;
		int32 RelAddress;
		struct {
			REG BaseRegister;
			REG IndexRegister;
			int8 Scale;
			int32 Displacement;		
		} Memory;
	} RegValMem;
	uiptr TargetAddress;
} OPERAND;

typedef struct {
	ENUM_OPCODE_CATEGORY_T Category;
	OPERAND Operands[3];
	int32 Opcode;
	REG ModifiedRegisters;
	BOOL bIsValid;
	char InstructionMnemonicName[26];
} INSTRUCTION;

typedef struct {
	ARCHITECTURE Architecture;
	uiptr InstructionPointer;
	uiptr VirtualAddress;
	INSTRUCTION Instruction;
	int32 InstructionSize;
	PREFIXES Prefixes;
	char Mnemonic[MAX_INSTRUCTION_MNEMONIC_SIZE];
	struct {
		int nOpcodeIndex;
		int nVADelta;
		uiptr OldVirtualAddress;
		BOOL bPopulateMnemonics;
	} InternalStuff;
} SIDISASM, * PSIDISASM;

#ifdef __cplusplus
extern "C"
#endif

IDISASM_API int disasm( PSIDISASM lpsDisasm );
IDISASM_API char * disasm_version(void);

#endif
