/*
Copyright (C) 2013  George Nicolaou <george[at]preaver.[dot]com>

This file is part of Icarus Disassembly Engine (iDisasm).

Icarus Disassembly Engine (iDisasm) is free software: you can redistribute it 
and/or modify it under the terms of the GNU Lesser General Public License as 
published by the Free Software Foundation, either version 3 of the License, 
or (at your option) any later version.

Icarus Disassembly Engine (iDisasm) is distributed in the hope that it will be 
useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General 
Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with Icarus Disassembly Engine (iDisasm).  If not, see 
<http://www.gnu.org/licenses/>.
*/

#ifndef _INTEL_H
#define _INTEL_H

#include "idisasm_internal.h"

#define MODRM_MODBITS_MASK 0xC0
#define MODRM_MODBITS_SHIFT 6

#define MODRM_REGBITS_MASK 0x38
#define MODRM_REGBITS_SHIFT 3

#define MODRM_RMBITS_MASK 0x07
#define MODRM_RMBITS_SHIFT 0

#define SIB_SCALEBITS_MASK 0xC0
#define SIB_INDEXBITS_MASK 0x38
#define SIB_BASEBITS_MASK 0x07

typedef enum { 
	OP_AAA, OP_AAD, OP_AAM, OP_AAS, OP_ADC, OP_ADD, OP_ADDPD, OP_ADDPS, OP_ADDSD, 
	OP_ADDSS, OP_ADDSUBPD, OP_ADDSUBPS, OP_AESDEC, OP_AESDECLAST, OP_AESENC, 
	OP_AESENCLAST, OP_AESIMC, OP_AESKEYGENASSIST, OP_AND, OP_ANDNPD, OP_ANDNPS, 
	OP_ANDPD, OP_ANDPS, OP_ARPL, OP_BLENDPD, OP_BLENDPS, OP_BLENDVPD, 
	OP_BLENDVPS, OP_BOUND, OP_BSF, OP_BSR, OP_BSWAP, OP_BT, OP_BTC, OP_BTR, 
	OP_BTS, OP_CALL, OP_CBW, OP_CDQ, OP_CDQE, OP_CLC, OP_CLD, OP_CLFLUSH,
	OP_CLI, OP_CLTS, OP_CMC, OP_CMOVAE, OP_CMOVBE, OP_CMOVA, OP_CMOVC, OP_CMOVE, OP_CMOVGE,
	OP_CMOVLE, OP_CMOVNLE, OP_CMOVNA, OP_CMOVNB, OP_CMOVNC, OP_CMOVNE, OP_CMOVNG, OP_CMOVL, OP_CMOVNL,
	OP_CMOVNO, OP_CMOVNP, OP_CMOVNS, OP_CMOVNZ, OP_CMOVO, OP_CMOVP, OP_CMOVPE,
	OP_CMOVPO, OP_CMOVS, OP_CMOVZ, OP_CMP, OP_CMPPD, OP_CMPPS, OP_CMPS,
	OP_CMPSB, OP_CMPSD, OP_CMPSQ, OP_CMPSS, OP_CMPSW, OP_CMPXCHG, OP_CMPXCHG16B,
	OP_CMPXCHG8B, OP_COMISD, OP_COMISS, OP_CPUID, OP_CRC32, OP_CVTDQ2PD,
	OP_CVTDQ2PS, OP_CVTPD2DQ, OP_CVTPD2PI, OP_CVTPD2PS, OP_CVTPI2PD, OP_CVTPI2PS,
	OP_CVTPS2DQ, OP_CVTPS2PD, OP_CVTPS2PI, OP_CVTSD2SI, OP_CVTSD2SS, OP_CVTSI2SD,
	OP_CVTSI2SS, OP_CVTSS2SD, OP_CVTSS2SI, OP_CVTTPD2DQ, OP_CVTTPD2PI,
	OP_CVTTPS2DQ, OP_CVTTPS2PI, OP_CVTTSD2SI, OP_CVTTSS2SI, OP_CWD, OP_CWDE, 
	OP_DAA, OP_DAS, OP_DEC, OP_DIV, OP_DIVPD, OP_DIVPS, OP_DIVSD, OP_DIVSS,
	OP_DPPD, OP_DPPS, OP_EMMS, OP_ENTER, OP_EXTRACTPS, OP_F2XM1, OP_FABS, 
	OP_FADD, OP_FADDP, OP_FBLD, OP_FBSTP, OP_FCHS, OP_FCLEX, OP_FCMOVB, 
	OP_FCMOVBE, OP_FCMOVE, OP_FCMOVNB, OP_FCMOVNBE, OP_FCMOVNE, OP_FCMOVNU,
	OP_FCMOVU, OP_FCOM, OP_FCOMI, OP_FCOMIP, OP_FCOMP, OP_FCOMPP, OP_FCOS, 
	OP_FDECSTP, OP_FDIV, OP_FDIVP, OP_FDIVR, OP_FDIVRP, OP_FFREE, OP_FIADD, 
	OP_FICOM, OP_FICOMP, OP_FIDIV, OP_FIDIVR, OP_FILD, OP_FIMUL, OP_FINCSTP,
	OP_FINIT, OP_FIST, OP_FISTP, OP_FISTTP, OP_FISUB, OP_FISUBR, OP_FLD, OP_FLD1,
	OP_FLDCW, OP_FLDENV, OP_FLDL2E, OP_FLDL2T, OP_FLDLG2, OP_FLDLN2, OP_FLDPI,
	OP_FLDZ, OP_FMUL, OP_FMULP, OP_FNCLEX, OP_FNINIT, OP_FNOP, OP_FNSAVE, 
	OP_FNSTCW, OP_FNSTENV, OP_FNSTSW, OP_FPATAN, OP_FPREM, OP_FPREM1, OP_FPTAN,
	OP_FRNDINT, OP_FRSTOR, OP_FSAVE, OP_FSCALE, OP_FSIN, OP_FSINCOS, OP_FSQRT, 
	OP_FST, OP_FSTCW, OP_FSTENV, OP_FSTP, OP_FSTSW, OP_FSUB, OP_FSUBP, OP_FSUBR,
	OP_FSUBRP, OP_FTST, OP_FUCOM, OP_FUCOMI, OP_FUCOMIP, OP_FUCOMP, OP_FUCOMPP,
	OP_FWAIT, OP_FXAM, OP_FXCH, OP_FXRSTOR, OP_FXSAVE, OP_FXTRACT, OP_FYL2X,
	OP_FYL2XP1, OP_GETSEC, OP_GETSEC_CAPABILITIES, OP_GETSEC_ENTERACCS, OP_GETSEC_EXITAC, 
	OP_GETSEC_PARAMETERS, OP_GETSEC_SENTER, OP_GETSEC_SEXIT, OP_GETSEC_SMCTRL, 
	OP_GETSEC_WAKEUP, OP_HADDPD, OP_HADDPS, OP_HLT, OP_HSUBPD, OP_HSUBPS, 
	OP_IDIV, OP_IMUL, OP_IN, OP_INC, OP_INS, OP_INSB, OP_INSD, OP_INSERTPS,
	OP_INSW, OP_INT1, OP_INT3, OP_INT, OP_INTO, OP_INVD, OP_INVEPT, OP_INVLPG, OP_INVPCID, 
	OP_INVVPID, OP_IRET, OP_JA, OP_JAE, OP_JB, OP_JBE, OP_JC, OP_JCXZ, OP_JE, 
	OP_JECXZ, OP_JG, OP_JGE, OP_JL, OP_JLE, OP_JMP, OP_JNA, OP_JNAE, OP_JNB,
	OP_JNBE, OP_JNC, OP_JNE, OP_JNG, OP_JNGE, OP_JNL, OP_JNLE, OP_JNO, OP_JNP,
	OP_JNS, OP_JNZ, OP_JO, OP_JP, OP_JPE, OP_JPO, OP_JS, OP_JZ, OP_LAHF, OP_LAR,
	OP_LDMXCSR, OP_LDS, OP_LEA, OP_LEAVE, OP_LES, OP_LFENCE, OP_LFS, OP_LGDT, 
	OP_LGS, OP_LIDT, OP_LLDT, OP_LMSW, OP_LOADALL, OP_LOCK, OP_LODS, OP_LODSB, OP_LODSD,
	OP_LODSQ, OP_LODSW, OP_LOOP, OP_LOOPE, OP_LOOPNE, OP_LOOPNZ, OP_LOOPZ, 
	OP_LSL, OP_LSS, OP_LTR, OP_MASKMOVDQU, OP_MASKMOVQ, OP_MAXPD, OP_MAXPS, 
	OP_MAXSD, OP_MAXSS, OP_MFENCE, OP_MINPD, OP_MINPS, OP_MINSD, OP_MINSS,
	OP_MONITOR, OP_MOV, OP_MOVAPD, OP_MOVAPS, OP_MOVBE, OP_MOVD, OP_MOVDDUP,
	OP_MOVDQ2Q, OP_MOVDQA, OP_MOVDQU, OP_MOVHLPS, OP_MOVHPD, OP_MOVHPS,
	OP_MOVLHPS, OP_MOVLPD, OP_MOVLPS, OP_MOVMSKPD, OP_MOVMSKPS, OP_MOVNTDQ, 
	OP_MOVNTDQA, OP_MOVNTI, OP_MOVNTPD, OP_MOVNTPS, OP_MOVNTQ, OP_MOVQ,
	OP_MOVQ2DQ, OP_MOVS, OP_MOVSB, OP_MOVSD, OP_MOVSHDUP, OP_MOVSLDUP, OP_MOVSQ, 
	OP_MOVSS, OP_MOVSW, OP_MOVSX, OP_MOVUPD, OP_MOVUPS, OP_MOVZX, OP_MPSADBW, 
	OP_MUL, OP_MULPD, OP_MULPS, OP_MULSD, OP_MULSS, OP_MWAIT, OP_NEG, OP_NOP, 
	OP_NOT, OP_OR, OP_ORPD, OP_ORPS, OP_OUT, OP_OUTS, OP_OUTSB, OP_OUTSD, 
	OP_OUTSW, OP_PABSB, OP_PABSD, OP_PABSW, OP_PACKSSDW, OP_PACKSSWB, 
	OP_PACKUSDW, OP_PACKUSWB, OP_PADDB, OP_PADDD, OP_PADDQ, OP_PADDSB,
	OP_PADDSW, OP_PADDUSB, OP_PADDUSW, OP_PADDW, OP_PALIGNR, OP_PAND, OP_PANDN,
	OP_PAUSE, OP_PAVGB, OP_PAVGW, OP_PBLENDVB, OP_PBLENDW, OP_PCLMULQDQ,
	OP_PCMPEQB, OP_PCMPEQD, OP_PCMPEQQ, OP_PCMPEQW, OP_PCMPESTRI, OP_PCMPESTRM, 
	OP_PCMPGTB, OP_PCMPGTD, OP_PCMPGTQ, OP_PCMPGTW, OP_PCMPISTRI, OP_PCMPISTRM,
	OP_PEXTRB, OP_PEXTRD, OP_PEXTRQ, OP_PEXTRW, OP_PHADDD, OP_PHADDSW, OP_PHADDW,
	OP_PHMINPOSUW, OP_PHSUBD, OP_PHSUBSW, OP_PHSUBW, OP_PINSRB, OP_PINSRD,
	OP_PINSRQ, OP_PINSRW, OP_PMADDUBSW, OP_PMADDWD, OP_PMAXSB, OP_PMAXSD,
	OP_PMAXSW, OP_PMAXUB, OP_PMAXUD, OP_PMAXUW, OP_PMINSB, OP_PMINSD, OP_PMINSW,
	OP_PMINUB, OP_PMINUD, OP_PMINUW, OP_PMOVMSKB, OP_PMOVSXBD, OP_PMOVSXBQ, 
	OP_PMOVSXBW, OP_PMOVSXDQ, OP_PMOVSXWD, OP_PMOVSXWQ, OP_PMOVZXBD, OP_PMOVZXBQ,
	OP_PMOVZXBW, OP_PMOVZXDQ, OP_PMOVZXWD, OP_PMOVZXWQ, OP_PMULDQ, OP_PMULHRSW, 
	OP_PMULHUW, OP_PMULHW, OP_PMULLD, OP_PMULLW, OP_PMULUDQ, OP_POP, OP_POPA,
	OP_POPAD, OP_POPCNT, OP_POPF, OP_POPFD, OP_POR, OP_PREFETCH0, OP_PREFETCH1, OP_PREFETCH2, OP_PREFETCHNTA, OP_PSADBW, 
	OP_PSHUFB, OP_PSHUFD, OP_PSHUFHW, OP_PSHUFLW, OP_PSHUFW, OP_PSIGNB, OP_PSLLD,
	OP_PSLLDQ, OP_PSLLQ, OP_PSLLW, OP_PSRAD, OP_PSRAW, OP_PSRLD, OP_PSRLDQ,
	OP_PSRLQ, OP_PSRLW, OP_PSUBB, OP_PSUBD, OP_PSUBQ, OP_PSUBSB, OP_PSUBSW, 
	OP_PSUBUSB, OP_PSUBUSW, OP_PSUBW, OP_PTEST, OP_PUNPCKHBW, OP_PUNPCKHDQ, 
	OP_PUNPCKHQDQ, OP_PUNPCKHWD, OP_PUNPCKLBW, OP_PUNPCKLDQ, OP_PUNPCKLQDQ, 
	OP_PUNPCKLWD, OP_PUSH, OP_PUSHA, OP_PUSHAD, OP_PUSHF, OP_PUSHFD, OP_PXOR, 
	OP_RCL, OP_RCPPS, OP_RCPSS, OP_RCR, OP_RDFSBASE, OP_RDGSBASE, OP_RDMSR, 
	OP_RDPMC, OP_RDRAND, OP_RDTSC, OP_RDTSCP, OP_REP, OP_REPE, OP_REPNE,
	OP_REPNZ, OP_REPZ, OP_RET, OP_RETF, OP_ROL, OP_ROR, OP_ROUNDPD, OP_ROUNDPS, 
	OP_ROUNDSD, OP_ROUNDSS, OP_RSM, OP_RSQRTPS, OP_RSQRTSS, OP_SAHF, OP_SAL, OP_SALC,
	OP_SAR, OP_SBB, OP_SCAS, OP_SCASB, OP_SCASD, OP_SCASW, OP_SETA, OP_SETAE,
	OP_SETB, OP_SETBE, OP_SETC, OP_SETE, OP_SETG, OP_SETGE, OP_SETL, OP_SETLE,
	OP_SETNA, OP_SETNAE, OP_SETNB, OP_SETNBE, OP_SETNC, OP_SETNE, OP_SETNG, 
	OP_SETNGE, OP_SETNL, OP_SETNLE, OP_SETNO, OP_SETNP, OP_SETNS, OP_SETNZ, 
	OP_SETO, OP_SETP, OP_SETPE, OP_SETPO, OP_SETS, OP_SETZ, OP_SFENCE, OP_SGDT,
	OP_SHL, OP_SHLD, OP_SHR, OP_SHRD, OP_SHUFPD, OP_SHUFPS, OP_SIDT, OP_SLDT,
	OP_SMSW, OP_SQRTPD, OP_SQRTPS, OP_SQRTSD, OP_SQRTSS, OP_STC, OP_STD, OP_STI,
	OP_STMXCSR, OP_STOS, OP_STOSB, OP_STOSD, OP_STOSQ, OP_STOSW, OP_STR, OP_SUB,
	OP_SUBPD, OP_SUBPS, OP_SUBSD, OP_SUBSS, OP_SWAPGS, OP_SYSCALL, OP_SYSENTER,
	OP_SYSEXIT, OP_SYSRET, OP_TEST, OP_UCOMISD, OP_UCOMISS, OP_UD2, OP_UNPCKHPD,
	OP_UNPCKHPS, OP_UNPCKLPD, OP_UNPCKLPS, OP_VCVTPH2PS, OP_VCVTPS2PH, OP_VERR,
	OP_VERW, OP_VMCALL, OP_VMCLEAR, OP_VMFUNC, OP_VMLAUNCH, OP_VMPTRLD, 
	OP_VMPTRST, OP_VMREAD, OP_VMRESUME, OP_VMWRITE, OP_VMXOFF, OP_VMXON, OP_WAIT, 
	OP_WBINVD, OP_WRFSBASE, OP_WRGSBASE, OP_WRMSR, OP_XADD, OP_XCHG, OP_XGETBV,
	OP_XLAT, OP_XLATB, OP_XOR, OP_XORPD, OP_XORPS, OP_XRSTOR, OP_XSAVE, 
	OP_XSAVEOPT, OP_XSETBV,
	//AMD Specific
	OP_FMMS,
	//XXX Need to implement
	OP_CLAC, OP_STAC, OP_XEND, OP_XTEST
} ENUM_OPCODE_PTR;



#define INTEL_MAX_NUMBER_OF_OPERANDS 3
#define INTEL_SEGMENT_SIZE_BITS BIT16
#define INTEL_DEFAULT_SIZE BIT32
extern INSTRUCTION_INFO sinstruction_info[];

/*
a - Two one-word operands in memory or two double-word operands in memory, depending on operand-size *
	attribute (used only by the BOUND instruction).
b - Byte, regardless of operand-size attribute. *
c - Byte or word, depending on operand-size attribute. *
d - Doubleword, regardless of operand-size attribute. *
dq - Double-quadword, regardless of operand-size attribute. *
p - 32-bit, 48-bit, or 80-bit pointer, depending on operand-size attribute. *
pd - 128-bit or 256-bit packed double-precision floating-point data. *
pi - Quadword MMX technology register (for example: mm0). *
ps - 128-bit or 256-bit packed single-precision floating-point data.
q - Quadword, regardless of operand-size attribute. *
qq - Quad-Quadword (256-bits), regardless of operand-size attribute.*
s - 6-byte or 10-byte pseudo-descriptor.
sd - Scalar element of a 128-bit double-precision floating data. *
ss - Scalar element of a 128-bit single-precision floating data. *
si - Doubleword integer register (for example: eax). *
v - Word, doubleword or quadword (in 64-bit mode), depending on operand-size attribute. *
w - Word, regardless of operand-size attribute.*
x - dq or qq based on the operand-size attribute. *
y - Doubleword or quadword (in 64-bit mode), depending on operand-size attribute. *
z - Word for 16-bit operand-size or doubleword for 32 or 64-bit operand-size. (depends on default operand size or overwritten size) *
*/
typedef enum {
	TYPE_INVALID = 0,
	TYPE_DEFAULT,
	TYPE_GIVEN,
	TYPE_a,
	TYPE_b,
	TYPE_c,
	TYPE_d,
	TYPE_dq,
	TYPE_p,
	TYPE_pd,
	TYPE_pi,
	TYPE_ps,
	TYPE_q,
	TYPE_qq,
	TYPE_s,
	TYPE_sd,
	TYPE_ss,
	TYPE_si,
	TYPE_v,
	TYPE_w,
	TYPE_x,
	TYPE_y,
	TYPE_z
} ENUM_INTEL_OPERAND_TYPE;

typedef enum {
	SCALE_INVALID = -1,
	SCALE_NONE = 1,
	SCALE_2 = 2,
	SCALE_4 = 4,
	SCALE_8 = 8
} SCALES;

/*
A - Direct address: the instruction has no ModR/M byte; the address of the operand is encoded in the instruction.
	No base register, index register, or scaling factor can be applied (for example, far JMP (EA)).
B - The VEX.vvvv field of the VEX prefix selects a general purpose register.
C - The reg field of the ModR/M byte selects a control register (for example, MOV (0F20, 0F22)).
D - The reg field of the ModR/M byte selects a debug register (for example, MOV (0F21,0F23)).
E - A ModR/M byte follows the opcode and specifies the operand. The operand is either a general-purpose
	register or a memory address. If it is a memory address, the address is computed from a segment register
	and any of the following values: a base register, an index register, a scaling factor, a displacement.
F - EFLAGS/RFLAGS Register.
G - The reg field of the ModR/M byte selects a general register (for example, AX (000)).
H - The VEX.vvvv field of the VEX prefix selects a 128-bit XMM register or a 256-bit YMM register, determined
	by operand type. For legacy SSE encodings this operand does not exist, changing the instruction to
	destructive form.
I - Immediate data: the operand value is encoded in subsequent bytes of the instruction.
J - The instruction contains a relative offset to be added to the instruction pointer register (for example, JMP
	(0E9), LOOP).
L - The upper 4 bits of the 8-bit immediate selects a 128-bit XMM register or a 256-bit YMM register, determined
	by operand type. (the MSB is ignored in 32-bit mode)
	M The ModR/M byte may refer only to memory (for example, BOUND, LES, LDS, LSS, LFS, LGS,
	CMPXCHG8B).
N - The R/M field of the ModR/M byte selects a packed-quadword, MMX technology register.
O - The instruction has no ModR/M byte. The offset of the operand is coded as a word or double word
	(depending on address size attribute) in the instruction. No base register, index register, or scaling factor
	can be applied (for example, MOV (A0–A3)).
P - The reg field of the ModR/M byte selects a packed quadword MMX technology register.
Q - A ModR/M byte follows the opcode and specifies the operand. The operand is either an MMX technology
	register or a memory address. If it is a memory address, the address is computed from a segment register
	and any of the following values: a base register, an index register, a scaling factor, and a displacement.
R - The R/M field of the ModR/M byte may refer
S - The reg field of the ModR/M byte selects a segment register (for example, MOV (8C,8E)).
U - The R/M field of the ModR/M byte selects a 128-bit XMM register or a 256-bit YMM register, determined by
	operand type.
V - The reg field of the ModR/M byte selects a 128-bit XMM register or a 256-bit YMM register, determined by
	operand type.
W - A ModR/M byte follows the opcode and specifies the operand. The operand is either a 128-bit XMM register,
	a 256-bit YMM register (determined by operand type), or a memory address. If it is a memory address, the
	address is computed from a segment register and any of the following values: a base register, an index
	register, a scaling factor, and a displacement.
X - Memory addressed by the DS:rSI register pair (for example, MOVS, CMPS, OUTS, or LODS).
Y - Memory addressed by the ES:rDI register pair (for example, MOVS, CMPS, INS, STOS, or SCAS).
*/
typedef enum {
	ADDR_A, //Direct address *
	ADDR_B, // VEX.vvvv GPR field
	ADDR_C, // reg selects CR *
	ADDR_D, // reg selects DR *
	ADDR_E, // modR/M reg
	ADDR_F, // FLAGS register
	ADDR_G, // reg selects GPR *
	ADDR_H, // VEX.vvvv selects XMM or YMM register
	ADDR_I, // Immediate data *
	ADDR_J, // Relative offset *
	ADDR_L, // Immidiate with upper 4 bits selecting XMM or YMM register
	ADDR_M, // ModR/M only memory
	ADDR_MR, //ModR/M only Memory or GPO Register
	ADDR_N, // R/M selects packed quadward MMX
	ADDR_O, // No ModR/M operand in instruction *
	ADDR_P, // reg selects MMX reg
	ADDR_Q, // ModR/M selects MMX
	ADDR_R, // R/M refers only to GPO *
	ADDR_S, // reg selects Sreg
	ADDR_U, // R/M selects XMM or YMM reg
	ADDR_V, // reg selects XMM or YMM
	ADDR_W, // ModR/M selects XMM or YMM or memory
	ADDR_X, // Memory addressed by DS:rSI
	ADDR_Y, // Memory addressed by ES:rDI
} ENUM_INTEL_INTERNAL_ADDRESSING;
ENUM_OPCODE_CATEGORY_T intel_get_opcode_category( ENUM_OPCODE_PTR );
extern const PLUGIN_MAP one_byte_opcode_map[];
int intel_addressing_handler( PSIDISASM, INSTRUCTIONINTERNAL * );
int intel_group_handler( PSIDISASM lpDisasm, GROUP_MAP * lpGroupMap );
#endif //_INTEL_H