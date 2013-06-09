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

#ifndef __TYPES_H_
#define __TYPES_H_

#include <stdint.h>
#include <assert.h>


#define NULL 0
#define FALSE 0
#define TRUE 1
#ifndef BOOL
typedef int BOOL;
#endif

#ifndef uchar
typedef unsigned char uchar;
#endif


#define ARRAY_FILL0(val)
#define ARRAY_FILL1(val) val,
#define ARRAY_FILL2(val) ARRAY_FILL1(val) ARRAY_FILL1(val)
#define ARRAY_FILL3(val) ARRAY_FILL2(val) ARRAY_FILL1(val)
#define ARRAY_FILL4(val) ARRAY_FILL3(val) ARRAY_FILL1(val)
#define ARRAY_FILL5(val) ARRAY_FILL4(val) ARRAY_FILL1(val)
#define ARRAY_FILL6(val) ARRAY_FILL5(val) ARRAY_FILL1(val)
#define ARRAY_FILL7(val) ARRAY_FILL6(val) ARRAY_FILL1(val)
#define ARRAY_FILL8(val) ARRAY_FILL7(val) ARRAY_FILL1(val)
#define ARRAY_FILL9(val) ARRAY_FILL8(val) ARRAY_FILL1(val)

#define ARRAY_FILL00(val)
#define ARRAY_FILL10(val) ARRAY_FILL9(val)  ARRAY_FILL1(val)
#define ARRAY_FILL20(val) ARRAY_FILL10(val) ARRAY_FILL10(val)
#define ARRAY_FILL30(val) ARRAY_FILL20(val) ARRAY_FILL10(val)
#define ARRAY_FILL40(val) ARRAY_FILL30(val) ARRAY_FILL10(val)
#define ARRAY_FILL50(val) ARRAY_FILL40(val) ARRAY_FILL10(val)
#define ARRAY_FILL60(val) ARRAY_FILL50(val) ARRAY_FILL10(val)
#define ARRAY_FILL70(val) ARRAY_FILL60(val) ARRAY_FILL10(val)
#define ARRAY_FILL80(val) ARRAY_FILL70(val) ARRAY_FILL10(val)
#define ARRAY_FILL90(val) ARRAY_FILL80(val) ARRAY_FILL10(val)

#define ARRAY_FILL000(val)
#define ARRAY_FILL100(val) ARRAY_FILL90(val)  ARRAY_FILL10(val)
#define ARRAY_FILL200(val) ARRAY_FILL100(val) ARRAY_FILL100(val)
#define ARRAY_FILL300(val) ARRAY_FILL200(val) ARRAY_FILL100(val)
#define ARRAY_FILL400(val) ARRAY_FILL300(val) ARRAY_FILL100(val)
#define ARRAY_FILL500(val) ARRAY_FILL400(val) ARRAY_FILL100(val)
#define ARRAY_FILL600(val) ARRAY_FILL500(val) ARRAY_FILL100(val)
#define ARRAY_FILL700(val) ARRAY_FILL600(val) ARRAY_FILL100(val)
#define ARRAY_FILL800(val) ARRAY_FILL700(val) ARRAY_FILL100(val)
#define ARRAY_FILL900(val) ARRAY_FILL800(val) ARRAY_FILL100(val)

#define ARRAY_FILL(x100,x10,x1,val) \
	ARRAY_FILL##x100##00(val) \
	ARRAY_FILL##x10##0(val) \
	ARRAY_FILL##x10(val)

#if defined(_MSC_VER)
	typedef signed char			int8;
	typedef unsigned char		uint8;
	typedef signed short		int16;
	typedef unsigned short		uint16;
	typedef signed int			int32;
	typedef unsigned int		uint32;
	typedef int64_t				int64;
	typedef uint64_t			uint64;
	#if defined(_WIN64)
		typedef int64_t			iptr;
		typedef uint64_t		uiptr;
	#else
		typedef signed long		iptr;
		typedef unsigned long	uiptr;
	#endif
#elif defined(__GNUC__)
	typedef signed char			int8;
	typedef unsigned char		uint8;
	typedef signed short		int16;
	typedef unsigned short		uint16;
	typedef signed int			int32;
	typedef unsigned int		uint32;
	typedef int64_t				int64;
	typedef uint64_t			uint64;
	#if defined(__LP64__)  || defined(_LP64)
		typedef int64_t		iptr;
		typedef uint64_t	uiptr;
	#else
		typedef signed long		iptr;
		typedef unsigned long	uiptr;
	#endif
#endif

#if defined _WIN32 || defined __CYGWIN__
#define IDISASM_EXPORT __declspec(dllexport)
#define IDISASM_IMPORT __declspec(dllimport)
#define IDISASM_LOCAL
#elif __GNUC__ >= 4
#define IDISASM_LOCAL __attribute__ ((visibility ("hidden")))
#define IDISASM_EXPORT __attribute__ ((visibility ("default")))
#define IDISASM_IMPORT __attribute__ ((visibility ("default")))
#else
#define IDISASM_EXPORT
#define IDISASM_IMPORT
#define IDISASM_LOCAL
#endif

#ifdef _DLLRLS
#define IDISASM_API IDISASM_EXPORT
#else
#define IDISASM_API IDISASM_IMPORT
#endif //_DLL

#endif //__TYPES_H_