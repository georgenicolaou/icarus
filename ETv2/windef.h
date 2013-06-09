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


#include <Windows.h>
#include <winnt.h>
#include <ntsecapi.h>

typedef LPVOID *PPVOID;
typedef LONG KPRIORITY;

typedef struct _CLIENT_ID{
	DWORD					ClientID0;
	DWORD					ClientID1; // thread id
} CLIENT_ID, *PCLIENT_ID;

typedef struct _LDR_MODULE {
	LIST_ENTRY				InLoadOrderModuleList;
	LIST_ENTRY				InMemoryOrderModuleList;
	LIST_ENTRY				InInitializationOrderModuleList;
	PVOID					BaseAddress;
	PVOID					EntryPoint;
	ULONG					SizeOfImage;
	UNICODE_STRING			FullDllName;
	UNICODE_STRING			BaseDllName;
	ULONG					Flags;
	SHORT					LoadCount;
	SHORT					TlsIndex;
	LIST_ENTRY				HashTableEntry;
	ULONG					TimeDateStamp;
} LDR_MODULE, *PLDR_MODULE;

typedef struct _PEB_LDR_DATA {
	ULONG					Length;
	BOOL					Initialized;
	PVOID					SsHandle;
	LIST_ENTRY				InLoadOrderModuleList;
	LIST_ENTRY				InMemoryOrderModuleList;
	LIST_ENTRY				InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _RTL_DRIVE_LETTER_CURDIR {
	USHORT					Flags;
	USHORT					Length;
	ULONG					TimeStamp;
	UNICODE_STRING			DosPath;
} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
	ULONG					MaximumLength;
	ULONG					Length;
	ULONG					Flags;
	ULONG					DebugFlags;
	PVOID					ConsoleHandle;
	ULONG					ConsoleFlags;
	HANDLE					StdInputHandle;
	HANDLE					StdOutputHandle;
	HANDLE					StdErrorHandle;
	UNICODE_STRING			CurrentDirectoryPath;
	HANDLE					CurrentDirectoryHandle;
	UNICODE_STRING			DllPath;
	UNICODE_STRING			ImagePathName;
	UNICODE_STRING			CommandLine;
	PVOID					Environment;
	ULONG					StartingPositionLeft;
	ULONG					StartingPositionTop;
	ULONG					Width;
	ULONG					Height;
	ULONG					CharWidth;
	ULONG					CharHeight;
	ULONG					ConsoleTextAttributes;
	ULONG					WindowFlags;
	ULONG					ShowWindowFlags;
	UNICODE_STRING			WindowTitle;
	UNICODE_STRING			DesktopName;
	UNICODE_STRING			ShellInfo;
	UNICODE_STRING			RuntimeData;
	RTL_DRIVE_LETTER_CURDIR DLCurrentDirectory[0x20];
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef struct _SECTION_IMAGE_INFORMATION {
	PVOID					EntryPoint;
	ULONG					StackZeroBits;
	ULONG					StackReserved;
	ULONG					StackCommit;
	ULONG					ImageSubsystem;
	WORD					SubsystemVersionLow;
	WORD					SubsystemVersionHigh;
	ULONG					Unknown1;
	ULONG					ImageCharacteristics;
	ULONG					ImageMachineType;
	ULONG					Unknown2[3];
} SECTION_IMAGE_INFORMATION, *PSECTION_IMAGE_INFORMATION;

typedef struct _RTL_USER_PROCESS_INFORMATION {
	ULONG					Size;
	HANDLE					ProcessHandle;
	HANDLE					ThreadHandle;
	CLIENT_ID				ClientId;
	SECTION_IMAGE_INFORMATION ImageInformation;
} RTL_USER_PROCESS_INFORMATION, *PRTL_USER_PROCESS_INFORMATION;

typedef void (*PPEBLOCKROUTINE)( PVOID PebLock ); 

typedef struct _PEB_FREE_BLOCK {
	struct _PEB_FREE_BLOCK	*Next;
	ULONG					Size;
} PEB_FREE_BLOCK, *PPEB_FREE_BLOCK;

typedef struct _PEB {
	BOOLEAN                 InheritedAddressSpace;
	BOOLEAN                 ReadImageFileExecOptions;
	BOOLEAN                 BeingDebugged;
	BOOLEAN                 Spare;
	HANDLE                  Mutant;
	PVOID                   ImageBaseAddress;
	PPEB_LDR_DATA           LoaderData;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	PVOID                   SubSystemData;
	PVOID                   ProcessHeap;
	PVOID                   FastPebLock;
	PPEBLOCKROUTINE         FastPebLockRoutine;
	PPEBLOCKROUTINE         FastPebUnlockRoutine;
	ULONG                   EnvironmentUpdateCount;
	PPVOID                  KernelCallbackTable;
	PVOID                   EventLogSection;
	PVOID                   EventLog;
	PPEB_FREE_BLOCK         FreeList;
	ULONG                   TlsExpansionCounter;
	PVOID                   TlsBitmap;
	ULONG                   TlsBitmapBits[0x2];
	PVOID                   ReadOnlySharedMemoryBase;
	PVOID                   ReadOnlySharedMemoryHeap;
	PPVOID                  ReadOnlyStaticServerData;
	PVOID                   AnsiCodePageData;
	PVOID                   OemCodePageData;
	PVOID                   UnicodeCaseTableData;
	ULONG                   NumberOfProcessors;
	ULONG                   NtGlobalFlag;
	BYTE                    Spare2[0x4];
	LARGE_INTEGER           CriticalSectionTimeout;
	ULONG                   HeapSegmentReserve;
	ULONG                   HeapSegmentCommit;
	ULONG                   HeapDeCommitTotalFreeThreshold;
	ULONG                   HeapDeCommitFreeBlockThreshold;
	ULONG                   NumberOfHeaps;
	ULONG                   MaximumNumberOfHeaps;
	PPVOID                  *ProcessHeaps;
	PVOID                   GdiSharedHandleTable;
	PVOID                   ProcessStarterHelper;
	PVOID                   GdiDCAttributeList;
	PVOID                   LoaderLock;
	ULONG                   OSMajorVersion;
	ULONG                   OSMinorVersion;
	ULONG                   OSBuildNumber;
	ULONG                   OSPlatformId;
	ULONG                   ImageSubSystem;
	ULONG                   ImageSubSystemMajorVersion;
	ULONG                   ImageSubSystemMinorVersion;
	ULONG                   GdiHandleBuffer[0x22];
	ULONG                   PostProcessInitRoutine;
	ULONG                   TlsExpansionBitmap;
	BYTE                    TlsExpansionBitmapBits[0x80];
	ULONG                   SessionId;
} PEB, *PPEB;

typedef struct _INITIAL_TEB {
	PVOID					StackBase;
	PVOID					StackLimit;
	PVOID					StackCommit;
	PVOID					StackCommitMax;
	PVOID					StackReserved;
} INITIAL_TEB, *PINITIAL_TEB;

typedef struct _THREAD_BASIC_INFORMATION {
	NTSTATUS				ExitStatus;
	PVOID					TebBaseAddress;
	CLIENT_ID				ClientId;
	ULONG_PTR				AffinityMask;
	KPRIORITY				Priority;
	KPRIORITY				BasePriority;
} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;

typedef struct _THREAD_TIMES_INFORMATION {
	LARGE_INTEGER			CreationTime;
	LARGE_INTEGER			ExitTime;
	LARGE_INTEGER			KernelTime;
	LARGE_INTEGER			UserTime;
} THREAD_TIMES_INFORMATION, *PTHREAD_TIMES_INFORMATION;

typedef struct _TEB {
	NT_TIB					Tib;
	PVOID					EnvironmentPointer;
	CLIENT_ID				Cid;
	PVOID					ActiveRpcInfo;
	PVOID					ThreadLocalStoragePointer;
	PPEB					Peb;
	ULONG					LastErrorValue;
	ULONG					CountOfOwnedCriticalSections;
	PVOID					CsrClientThread;
	PVOID					Win32ThreadInfo;
	ULONG					Win32ClientInfo[0x1F];
	PVOID					WOW32Reserved;
	ULONG					CurrentLocale;
	ULONG					FpSoftwareStatusRegister;
	PVOID					SystemReserved1[0x36];
	PVOID					Spare1;
	ULONG					ExceptionCode;
	ULONG					SpareBytes1[0x28];
	PVOID					SystemReserved2[0xA];
	ULONG					GdiRgn;
	ULONG					GdiPen;
	ULONG					GdiBrush;
	CLIENT_ID				RealClientId;
	PVOID					GdiCachedProcessHandle;
	ULONG					GdiClientPID;
	ULONG					GdiClientTID;
	PVOID					GdiThreadLocaleInfo;
	PVOID					UserReserved[5];
	PVOID					GlDispatchTable[0x118];
	ULONG					GlReserved1[0x1A];
	PVOID					GlReserved2;
	PVOID					GlSectionInfo;
	PVOID					GlSection;
	PVOID					GlTable;
	PVOID					GlCurrentRC;
	PVOID					GlContext;
	NTSTATUS				LastStatusValue;
	UNICODE_STRING			StaticUnicodeString;
	WCHAR					StaticUnicodeBuffer[0x105];
	PVOID					DeallocationStack;
	PVOID					TlsSlots[0x40];
	LIST_ENTRY				TlsLinks;
	PVOID					Vdm;
	PVOID					ReservedForNtRpc;
	PVOID					DbgSsReserved[0x2];
	ULONG					HardErrorDisabled;
	PVOID					Instrumentation[0x10];
	PVOID					WinSockData;
	ULONG					GdiBatchCount;
	ULONG					Spare2;
	ULONG					Spare3;
	ULONG					Spare4;
	PVOID					ReservedForOle;
	ULONG					WaitingOnLoaderLock;
	PVOID					StackCommit;
	PVOID					StackCommitMax;
	PVOID					StackReserved;
} TEB, *PTEB;

//Source: http://www.pinvoke.net/default.aspx/ntdll/PROCESSINFOCLASS.html
typedef enum PROCESSINFOCLASS
{
	ProcessBasicInformation = 0,
	ProcessQuotaLimits,
	ProcessIoCounters,
	ProcessVmCounters,
	ProcessTimes,
	ProcessBasePriority,
	ProcessRaisePriority,
	ProcessDebugPort,
	ProcessExceptionPort,
	ProcessAccessToken,
	ProcessLdtInformation,
	ProcessLdtSize,
	ProcessDefaultHardErrorMode,
	ProcessIoPortHandlers, // Note: this is kernel mode only
	ProcessPooledUsageAndLimits,
	ProcessWorkingSetWatch,
	ProcessUserModeIOPL,
	ProcessEnableAlignmentFaultFixup,
	ProcessPriorityClass,
	ProcessWx86Information,
	ProcessHandleCount,
	ProcessAffinityMask,
	ProcessPriorityBoost,
	MaxProcessInfoClass,
	ProcessWow64Information = 26,
	ProcessImageFileName = 27
} PROCESSINFOCLASS;

typedef enum _THREAD_INFORMATION_CLASS {

	ThreadBasicInformation,
	ThreadTimes, 
	ThreadPriority, 
	ThreadBasePriority, 
	ThreadAffinityMask, 
	ThreadImpersonationToken, 
	ThreadDescriptorTableEntry, 
	ThreadEnableAlignmentFaultFixup, 
	ThreadEventPair, 
	ThreadQuerySetWin32StartAddress, 
	ThreadZeroTlsCell, 
	ThreadPerformanceCount, 
	ThreadAmILastThread, 
	ThreadIdealProcessor, 
	ThreadPriorityBoost, 
	ThreadSetTlsArrayAddress, 
	ThreadIsIoPending, 
	ThreadHideFromDebugger

} THREAD_INFORMATION_CLASS, *PTHREAD_INFORMATION_CLASS;

typedef struct _PROCESS_BASIC_INFORMATION {
	PVOID Reserved1;
	PPEB PebBaseAddress;
	PVOID Reserved2[2];
	ULONG_PTR UniqueProcessId;
	PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;
typedef PROCESS_BASIC_INFORMATION *PPROCESS_BASIC_INFORMATION;


typedef NTSTATUS (WINAPI* FNtQueryInformationProcess)(
	HANDLE ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID ProcessInformation,
	ULONG ProcessInformationLength,
	PULONG ReturnLength
	);

typedef NTSTATUS (WINAPI* FNtQueryInformationThread) (
	HANDLE ThreadHandle,
	THREAD_INFORMATION_CLASS ThreadInformationClass,
	PVOID ThreadInformation,
	ULONG ThreadInformationLength,
	PULONG ReturnLength
	);


#define CONTAINING_RECORD(address, type, field) ((type *)( \
	(PCHAR)(address) - \
	(ULONG_PTR)(&((type *)0)->field)))

typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	WORD LoadCount;
	WORD TlsIndex;
	union
	{
		LIST_ENTRY HashLinks;
		struct
		{
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};
	union
	{
		ULONG TimeDateStamp;
		PVOID LoadedImports;
	};
	_ACTIVATION_CONTEXT * EntryPointActivationContext;
	PVOID PatchInformation;
	LIST_ENTRY ForwarderLinks;
	LIST_ENTRY ServiceTagLinks;
	LIST_ENTRY StaticLinks;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _EXCEPTION_REGISTRATION_RECORD {
	struct _EXCEPTION_REGISTRATION_RECORD *Next;
	PEXCEPTION_ROUTINE Handler;
} EXCEPTION_REGISTRATION_RECORD;

// Directory Entries

#define IMAGE_DIRECTORY_ENTRY_EXPORT          0   // Export Directory
#define IMAGE_DIRECTORY_ENTRY_IMPORT          1   // Import Directory
#define IMAGE_DIRECTORY_ENTRY_RESOURCE        2   // Resource Directory
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION       3   // Exception Directory
#define IMAGE_DIRECTORY_ENTRY_SECURITY        4   // Security Directory
#define IMAGE_DIRECTORY_ENTRY_BASERELOC       5   // Base Relocation Table
#define IMAGE_DIRECTORY_ENTRY_DEBUG           6   // Debug Directory
//      IMAGE_DIRECTORY_ENTRY_COPYRIGHT       7   // (X86 usage)
#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE    7   // Architecture Specific Data
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR       8   // RVA of GP
#define IMAGE_DIRECTORY_ENTRY_TLS             9   // TLS Directory
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    10   // Load Configuration Directory
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   11   // Bound Import Directory in headers
#define IMAGE_DIRECTORY_ENTRY_IAT            12   // Import Address Table
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   13   // Delay Load Import Descriptors
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14   // COM Runtime descriptor

//
// Directory format.
//
#ifdef _IMAGE_DATA_DIRECTORY
typedef struct _IMAGE_DATA_DIRECTORY {
	DWORD   VirtualAddress;
	DWORD   Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;
#endif //_IMAGE_DATA_DIRECTORY
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES    16
