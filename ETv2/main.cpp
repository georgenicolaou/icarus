

#include "windef.h"
#include "WindowsMemory.h"
#include "MemoryPage.h"
#pragma warning( push, 0 )
#include <vector>
#pragma warning( pop )
#include "icarus_include.h"
#include "HexPattern.h"
#include "Pattern.h"
#include "IProtections.h"
#include "InstructionFinder.h"
#include "IMemory.h"
#include "IDebugger.h"
#include "DataEncoder.h"
#include "IExeHandler.h"
#include "Function.h"
#include "Fuzzer.h"
#include "ProcessExecutor.h"
#include "FuzzerGenerator.h"
#include "FuzzerGeneratorExternal.h"
#include "StackBufferOverflow.h"
#include "IGadgetFinder.h"
#include "WindowsProtections.h"
#include "ExecutionMonitor.h"
#include "WindowsDebugger.h"

//using namespace std;
//#include "icarus_include.h"
//#include "string.h"
/*
#include <Windows.h>
BOOL WINAPI DllMain( HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved )
{
	return TRUE;
}
*/
#ifdef _PROCTEST

int main()
{
	FuzzerGeneratorExternal sFuzzer;
	sFuzzer.setup_generator( "E:\\testproject\\dts\\Debug\\dts.exe", 2, "arg1", "arg2" );
	
}
#endif
//#include <WinNT.h>
//#define _TEST
#ifdef _TEST

int main( int argc, char * argv[] )
{
	WindowsMemory wm;
	WindowsMemory * wmp = new WindowsMemory();

	
	//vector<ImageHeaderMemory*> vMemory;
	//vector<DWORD> threads;
	//wm.memory_map_process_memory( 5992 );
	//wm.memory_get_proc_heaps( &vMemory, 5992 );
	//wm.windowsmemory_get_remote_proc_threads( threads, 4640 );
	//wm.memory_get_proc_stacks( &vMemory, 3316 );
	//wm.memory_get_module_headers( &vMemory, 3316 );
	Pattern p;

// 	p.pattern_create( 1000 );
// 	IDebugger dbg;
// 	dbg.debugger_attach( 100 );
// 	while ( dbg.debugger_wait_for_exception() ) {

//	}
	HexPattern hp;
	unsigned char shaystack[] = "\xaa\xee\xff\x00\xff\xbb\xaa\xbb\xcc\xdd\xaa\x00\xff\x00\xaa\xff\xbb\xaa\xbb\xcc\xdd\xee\xff\x33\xee\xfa\x33\xff\xcc\xff\xcc";
	unsigned char * haystack = shaystack;
	unsigned char * haytmp = NULL;
	int nsize = sizeof(shaystack);
	haytmp = haystack;
	int offset;
	hp.parse_pattern( "aa[eebb00]");
	while( ( haytmp = (unsigned char *)hp.find_next_match( haytmp, nsize ) ) != NULL ) {
		nsize = nsize - ( haytmp - haystack );
		printf( "Pat found at offset: %d [", haytmp - haystack );
		offset = haytmp - shaystack;
		for( int i = 0; i < hp.get_pattern_size(); i++ ) {
			printf( "%02X", shaystack[offset+i] );
		}
		printf( "]\n");
		haystack = haytmp;
	}
	
#ifdef _PATTERN

#endif
	return 1;
}
#endif // _TEST

//#define _PATTERN
#ifdef _PATTERN

void usage( char * lpszExeName )
{
	printf("Usage:\n\t%s <size> - Generate pattern of size <size>", lpszExeName );
	printf("\n\t%s <size> <pattern> - Search for offset in pattern", lpszExeName );
	printf(". Note that the pattern type depends on how many letters u type.");
}
int main( int argc, char * argv[] )
{
	Pattern p;
	char * lpszPattern;
	vector<int> vint;
	int i;
	char sSearchString[5];

	p.pattern_set_default_sets();

	if( argc == 2 ) {
		lpszPattern = p.pattern_create( atoi( argv[1] ) );
		printf( "%s", lpszPattern );
	}
	else if( argc == 3) {
		char * lpszActualSearchStr = argv[2];
		if( strlen( argv[2] ) > 4 ) {
			unsigned long ulHex = strtol( argv[2], NULL, 16);
			DataEncoder::ltostr( DataEncoder::swap_endianess( ulHex ), 
				(char *)&sSearchString );
			lpszActualSearchStr = (char*) &sSearchString;
		}
		vint = p.pattern_search( atoi( argv[1] ), lpszActualSearchStr, strlen( 
			lpszActualSearchStr ) );
		printf( "Offset:\n");
		for( i = 0; i < (int)vint.size(); i++ ) {
			printf( "0x%08X ( %d )", vint[i], vint[i] ); 
		}
	}
	else {
		usage( argv[0] );
	}
	return 1;
}
#endif // _PATTERN

//#define _FINDEXPORTS
#ifdef _FINDEXPORTS
int main( int argc, char * argv[] )
{
	vector<ImageHeaderMemory *> vHeaders;
	IMemory * wm = IMemory::init_get_instance();
	wm->memory_get_module_headers( &vHeaders, atoi( argv[1] ) );
	IExeHandler * lpcExeHandler = IExeHandler::init_get_instance( vHeaders[0] );
	vector<Function*> vExportedFunctions;
	for( int i = 0; i < (int)vHeaders.size(); i++ ) {
		if( lpcExeHandler->get_image_exported_functions( wm, &vExportedFunctions, 
			vHeaders[i] ) == TRUE ) {
// 				printf("------ %s : %08X -----\n", 
// 					vHeaders[i]->get_image_name_ascii(), 
// 					vHeaders[i]->get_baseaddress() );
				for( int j = 0; j < (int)vExportedFunctions.size(); j++ ) {
					unsigned char * lpucFunc = 
						vExportedFunctions[j]->get_function_contents( wm, 6 );
					if( *lpucFunc == (unsigned char)'\xE9' ) {
						unsigned long ulRelativeLocation = 
							*((unsigned long *)(lpucFunc+1));
						unsigned long * lpulAddress = (unsigned long *)( 
							(long)vExportedFunctions[j]->get_function_virtual_address() + 
							(long)ulRelativeLocation + 5 ); // -5 Bytes because of sizeof( CALL <RELATIVE> )
						ImageHeaderMemory * lpcImageHeader = 
							wm->memory_find_memory_page_addr( vHeaders, 
							lpulAddress );
						if( argc == 3 ) {
							if( strcmp( argv[2], lpcImageHeader->get_image_name_ascii() ) == 0) {
								printf("Hook Detected:\n\tFunction: %08X %s!%s\n\tHook Redirects to: %s : %08X\n", 
									vExportedFunctions[j]->get_function_virtual_address(),
									vHeaders[i]->get_image_name_ascii(),
									vExportedFunctions[j]->get_function_name(), 
									lpcImageHeader->get_image_name_ascii(), lpulAddress );
							}
						}
						else {
							printf("Hook Detected:\n\tFunction: %08X %s!%s\n\tHook Redirects to: %s : %08X\n", 
								vExportedFunctions[j]->get_function_virtual_address(),
								vHeaders[i]->get_image_name_ascii(),
								vExportedFunctions[j]->get_function_name(), 
								lpcImageHeader->get_image_name_ascii(), lpulAddress );
						}
						
					}
// 					printf( "%08X ( Real: %08X ) : %s\n", 
// 						vExportedFunctions[j]->get_function_virtual_address(),
// 						vExportedFunctions[j]->get_function_address(), 
// 						vExportedFunctions[j]->get_function_name() );
				}
		}
		vExportedFunctions.clear();
	}
}
#endif

//#define _INSTRFIND
#ifdef _INSTRFIND
void usage( char * lpszExeName )
{
	printf("Usage:\n\t%s <procid> - Map process memory", lpszExeName );
	printf("\n\t%s <procid> <instruction_bytestring> - Search for instruction in executable space", lpszExeName );
	printf("\n\t%s <procid> <instruction_bytestring> [seh/gs/aslr/dep] - Search for instruction in executable space and filter out modules with specified protections");
}
int main( int argc, char * argv[] )
{
	WindowsMemory wm;
	vector<MemoryPage*> lpvmemory;
	vector<MemoryPage*> lpvmemoryHeaps;
	vector<ImageHeaderMemory*> vHeaders;
	vector<ThreadStack*> vStack;
	IProtections * cProtections = IProtections::init_get_instance();
	MemoryPage * lpMemoryPage;
	IExeHandler * cExeHandler;
	ImageHeaderMemory * lpSection;
	char * lpszSectionName = NULL;

	int i = 0;
	int j = 0;
	if( argc == 2 ) {
		printf( "Memory Pages:" );
		if( wm.memory_map_process_memory( atoi( argv[1] ) ) == FALSE )
			return 0;
		//lpvmemory = wm.memory_get_memory_pages();
		wm.memory_get_proc_heaps( &lpvmemoryHeaps, atoi( argv[1] ) );
		wm.memory_get_module_headers( &vHeaders, atoi( argv[1] ) );
		wm.memory_get_proc_stacks( &vStack, atoi( argv[1] ) );
		lpvmemory = wm.memory_get_memory_pages();
		printf( "\nBaseAddr |   Size   | ACC | Image Owner\n" );
		printf( "---------+----------+-----+--------------\n");
		for( i = 0; i < lpvmemory.size(); i++ ) {
			printf( "%08X | %08X | ", lpvmemory[i]->get_baseaddress(), 
				lpvmemory[i]->get_page_size() );
			( lpvmemory[i]->mem_read() == TRUE ) ? printf("R") : printf( " " );
			( lpvmemory[i]->mem_write() == TRUE )? printf("W") : printf( " " );
			( lpvmemory[i]->mem_execute() == TRUE )? printf("E") : printf( " " );
			printf( " |");
			
			if( lpvmemory[i]->type_image() == TRUE ) {
				for( j = 0; j < vHeaders.size(); j++ ) {
					if( lpvmemory[i]->get_allocation_baseaddress() == 
						vHeaders[j]->get_baseaddress() ) {
							cProtections->apply_protection_filter( 
								IProtections::PROTECTION_ALL );
							cProtections->filter_module_allowed( vHeaders[j] );
							if( cProtections->is_protection_0() ) {
								printf( "[%s]", 
									cProtections->get_protection_0_name() );
							}
							if( cProtections->is_protection_1() ) {
								printf( "[%s]", 
									cProtections->get_protection_1_name() );
							}
							if( cProtections->is_protection_2() ) {
								printf( "[%s]", 
									cProtections->get_protection_2_name() );
							}
							if( cProtections->is_protection_3() ) {
								printf( "[%s]", 
									cProtections->get_protection_3_name() );
							}
// 							cExeHandler = IExeHandler::init_get_instance( 
// 								vHeaders[j] );
//  							cExeHandler->get_sections( &wm, vHeaders[j] );
// 							lpSection = cExeHandler->get_section_of_address( 
// 								vHeaders[j]->get_baseaddress() );
// 							
// 							if( lpSection->get_image_section_name() == NULL ) {
// 								lpszSectionName = "NULL";
// 							}
							printf( " | %s ", 
								vHeaders[j]->get_image_name_ascii() );
					}
				}
			}
			for( j = 0; j < lpvmemoryHeaps.size(); j++ ) {
				if( lpvmemory[i]->get_baseaddress() == 
					lpvmemoryHeaps[j]->get_baseaddress() ) {
						printf( " HEAP ");
				}
			}
			for( j = 0; j < vStack.size(); j++ ) {
				if( lpvmemory[i]->get_baseaddress() == 
					vStack[j]->get_baseaddress() ) {
						printf( " Stack of Thread: 0x%X", 
							vStack[j]->get_stack_thread_id() );
				}
			}
			printf( "\n" );
		}
	}
	else if( argc >= 3 ) {
		InstructionFinder cInstructionFinder;
		IProtections * lpcProtections = IProtections::init_get_instance();
		HexPattern cHexPattern;
		vector<Address *> vAddresses;
		IProtections::_PROTECTION_FILTER pf = IProtections::PROTECTION_ALL;
		cHexPattern.parse_pattern( argv[2] );
		if( argc >= 4 ) {
			pf = (IProtections::_PROTECTION_FILTER) NULL;
			for( int i = 3; i < argc; i++ ) {
				if( *argv[i] == *"seh" ) pf = (IProtections::_PROTECTION_FILTER)
					( pf + IProtections::PROTECTION_2 );
				if( *argv[i] == *"gs" ) pf = (IProtections::_PROTECTION_FILTER)
					( pf + IProtections::PROTECTION_1 );
				if( *argv[i] == *"aslr" ) pf = (IProtections::_PROTECTION_FILTER)
					( pf + IProtections::PROTECTION_ASLR );
				if( *argv[i] == *"dep" ) pf = (IProtections::_PROTECTION_FILTER)
					( pf + IProtections::PROTECTION_0 );
			}
		}
		lpcProtections->apply_protection_filter( pf );
		//BOOL find_instruction_in_exe( int nProcessId, IProtections * lpcProtectionsFilter, HexPattern * lpcCompiledHexPattern, vector<Address *> * lpvFoundAddresses )
		if( cInstructionFinder.find_instruction_in_exe( atoi( argv[1] ), 
			lpcProtections, &cHexPattern, &vAddresses ) == FALSE ) {
				printf( "Error finding instruction");
				return 0;
		}
		else {
			ImageHeaderMemory * lpImageHeader;
			wm.memory_map_process_memory( atoi( argv[1] ) );
			lpvmemory = wm.memory_get_memory_pages();
			wm.memory_get_module_headers( &vHeaders, atoi( argv[1] ) );
			if( vAddresses.size() == 0 ) {
				printf( "Not found!" );
			}
			for( i = 0; i < vAddresses.size(); i++ ) {
				WindowsMemory wm;
				if( ( lpMemoryPage = IMemory::memory_find_memory_page_addr( 
					lpvmemory, vAddresses[i]->get_address() ) ) != NULL ) {
						if(  ( lpImageHeader = IMemory::memory_find_memory_page_addr( 
							vHeaders, lpMemoryPage->get_allocation_baseaddress() ) ) != NULL ) {
							printf( "%08X | %s | Contents: [", vAddresses[i]->get_address(), 
								lpImageHeader->get_image_name_ascii() );
							int j;
							Address * lpAddress = vAddresses[i];
							unsigned char * lpucContents = (unsigned char *) lpAddress->get_address_contents_buffer();
							for( j = 0; j < lpAddress->get_address_contents_size(); j++ ) {
								printf( "%02X", *lpucContents++ );
							}
							printf( "]\n" );
						}
						else {
							printf( "%08X | %s", vAddresses[i]->get_address(), 
								"No Image association Executable Page [" );
							int j;
							Address * lpAddress = vAddresses[i];
							unsigned char * lpucContents = (unsigned char *) lpAddress->get_address_contents_buffer();
							for( j = 0; j < lpAddress->get_address_contents_size(); j++ ) {
								printf( "%02X", *lpucContents++ );
							}
							printf( "]\n" );
						}
				}
				else {
					printf( "%08X | %s\n", vAddresses[i]->get_address(), 
						"No association" );
				}
			}
		}
	}
	else {
		usage( argv[0] );
	}
}
#endif // _INSTRFIND

//#define _EXPLOIT_ANALYSIS
#ifdef _EXPLOIT_ANALYSIS
void usage( char * lpszExeName )

{
	printf("Usage:\n\t%s <pid> <pattern size> - Attach and do exploitability analysis", lpszExeName );
}

int main( int argc, char * argv[] )
{
	
	IDebugger * lpDebugger = IDebugger::init_get_instance();
	char cContinue;
	char szAnswer[10];
	vector<IRegister*> vRegisters;
	char lpszAscii[5];
	Pattern * lpobjPattern = new Pattern();
	lpobjPattern->pattern_set_default_sets();
	//lpobjPattern->pattern_create( 301887 );
	//DataEncoder::ltostr( 0x41424344, (char *)&lpszAscii );
	/*
	if( argc != 3 ) {
		usage( argv[0] );
		return 1;
	}
	*/
	//argv[1] = "4204";
	lpDebugger->debugger_attach( atoi( argv[1] ) );
	PEXCEPTION_RECORD lpException;
	while( ( lpException = (PEXCEPTION_RECORD) 
		lpDebugger->debugger_wait_for_exception() ) != NULL ) {
			printf( "Exception at 0x%08X [%08X] Get Additional Info? [Y/N]: ", 
				lpException->ExceptionAddress, lpException->ExceptionCode );

			scanf( "%5s", &szAnswer );
			if( *szAnswer == 'Y' || *szAnswer == 'y' ) {
				StackBufferOverflow so;
				so.check_for_vulnerability( lpDebugger );
				so.run_vulnerability_analysis( lpDebugger );
				return 1;
				/*
				cContinue = 0;
				lpDebugger->debugger_get_registers( &vRegisters, 
					(int)lpDebugger->debugger_get_last_exception_thread() );
				for( int i = 0; i < vRegisters.size(); i++ ) {
					void * lpszRegisterValue = vRegisters[i]->get_register_value();
					printf( "%s = 0x%08X\n", vRegisters[i]->get_register_name(), 
						*((DWORD *)lpszRegisterValue) );
				}
				printf( "Test for register control? [Y/N]: " );
				scanf( "%5s", &szAnswer );
				Pattern cPattern;
				cPattern.pattern_set_default_sets();
				unsigned char * lucMainPattern = ( unsigned char *)
					cPattern.pattern_create( atoi( argv[2] ) );
				int nFoundFlag = 0;
				int nEIPIndex = 0;
				int nESPIndex = 0;
				unsigned long ulOffsetInPattern = NULL;
				if( *szAnswer == 'Y' || *szAnswer == 'y' ) {
					for(int i = 0; i < vRegisters.size(); i++ ) {

						if( vRegisters[i]->get_register_type() 
							== IRegister::REG_PC ) {
								nEIPIndex = i;
						}
						else if( vRegisters[i]->get_register_type() 
							== IRegister::REG_SP ) {
								nESPIndex = i;
						}

						void * lpszRegisterValue = vRegisters[i]->get_register_value();
						DataEncoder::ltostr( DataEncoder::swap_endianess( 
							*( (unsigned long*)lpszRegisterValue ) ), 
							(char *)&lpszAscii );
						vector<int> vPatterns = cPattern.pattern_search( 
							atoi( argv[2] ), lpszAscii, 
							vRegisters[i]->get_register_size() / 8 );
						if( vPatterns.size() == 0 ) continue;
						nFoundFlag = 1;
						
						printf( "Controlled Register: %s at offset(s): ", 
							vRegisters[i]->get_register_name() );
						
						for( int j = 0; j < vPatterns.size(); j++ ) {
							ulOffsetInPattern = vPatterns[j];
							printf( "0x%08X (%d) ", ulOffsetInPattern, ulOffsetInPattern );
						}
						printf( "\n" );

						
					}
					if( nFoundFlag != 0 ) {
						IMemory * lpcMemory = IMemory::init_get_instance();
						vector<ThreadStack*> vStacks;
						lpcMemory->memory_get_proc_stacks( &vStacks, 
							atoi( argv[1] ) );

						ThreadStack * lpcOverflownStack = NULL;
						for( int k = 0; k < vStacks.size(); k++ ) {
							if( (int)lpDebugger->debugger_get_last_exception_thread() 
								== vStacks[k]->get_stack_thread_id() ) {
									lpcOverflownStack = vStacks[k];
									break;
							}
						}
					
						lpcOverflownStack->allocate_buffer_for_page();
						if( lpcMemory->memory_get_memory_page_contents( 
							atoi( argv[1] ), lpcOverflownStack, 
							lpcOverflownStack->get_memory_page_contents_buffer(), 
							lpcOverflownStack->get_page_size() ) == FALSE ) {
							 dprintf( "Error pulling thread stack" );
							 return 1;
						}
						dprintf( "Scanning injected payload from EIP until the end of pattern for corruptions" );
						unsigned long ulESPOffset = NULL;
						DWORD regValue = *(DWORD *) 
							vRegisters[nESPIndex]->get_register_value();
						ulESPOffset = regValue - 
							(DWORD)lpcOverflownStack->get_baseaddress();
						int nPatternSize = atoi( argv[2] ) - ulOffsetInPattern;
						unsigned char * lpucPattern = lucMainPattern 
							+ ulOffsetInPattern + 4;

						unsigned char * lpucBuffer =
							lpcOverflownStack->get_memory_page_contents_buffer()
							+ ulESPOffset;
						int ii = 0;
						int nNumberOfJunk = 0;
						int nLastoffset = ulOffsetInPattern;
						int nNumberofJMPRequired = 0;
						int nAvailableSpace = nPatternSize;
						while( nPatternSize-- ) {
							ii++;
							if( *lpucPattern++ != *lpucBuffer++ ) {
								if( nLastoffset + 1 != ulOffsetInPattern + ii && nLastoffset != 0 ) {
									nNumberofJMPRequired++;
								}
								nLastoffset = ulOffsetInPattern + ii;
								nNumberOfJunk++;
								printf( "Junk byte identified at offset 0x%X ( %d )\n", 
									ulOffsetInPattern + ii, ulOffsetInPattern + ii );
							}
						}
						printf( "Total Number of Junk bytes: %d\n", 
							nNumberOfJunk );
						printf( "Total Number of JMP SHORT instructions "
							"required to skip junk: %d\n", 
							nNumberofJMPRequired );
						printf( "Total Number of wasted bytes: %d\n", 
							nNumberofJMPRequired * 2 + nNumberOfJunk );
						printf( "Total Available Space in current "
							"overflown stack location: %d\n", 
							nAvailableSpace - ( nNumberofJMPRequired * 2 + 
							nNumberOfJunk ) );

						/*
						if( lpcMemory->memory_get_memory_page_contents( 
						lpcSectionMemoryPage->get_process_id(), 
						lpcSectionMemoryPage, 
						lpcSectionMemoryPage->get_memory_page_contents_buffer(), 
						lpcSectionMemoryPage->get_page_size() ) == FALSE ) {
						


// 						if( vRegisters[i].get_register_type() == REG_PC ) {
// 							printf("Identified Controllable %s\n Scanning Stack", 
// 								vRegisters[i].get_register_name() );
// 							WindowsMemory wm;
// 							wm.memory_map_process_memory();
// 
// 						}

					}
					else
						printf( "No controlled registers found\n");
					
				}

				vRegisters.clear();
				*/
			}
		
	}
}
#endif // _EXPLOIT_ANALYSIS

//#define _ROP_FINDER

#ifdef _ROP_FINDER

int main( int argc, char * argv[] ) 
{
	IGadgetFinder * gf = IGadgetFinder::init_get_instance();
	vector<RopGadget *> rops;
	IProtections * lpProts = IProtections::init_get_instance();
	IProtections::_PROTECTION_FILTER eProtectionFilter = 
		(IProtections::_PROTECTION_FILTER)WindowsProtections::PROTECTION_ASLR;
	lpProts->apply_protection_filter( eProtectionFilter );
	gf->proc_find_api_gadgets( lpProts, 5692 );
	
	dprintflvl( 3, "Finished");
	gf->proc_find_rop_gadgets( lpProts, 5692 );

	delete gf;
}

#endif // _ROP_FINDER

#define _HOOKER
#ifdef _HOOKER


BOOL moncallback( ExecutionMonitor::MONITOR_EVENT_INFO * info )
{
	if( info->uType.lpFunction != NULL ) {
		printf( "%X:%s\n", info->ulEventAddress, 
			info->uType.lpFunction->get_function_name() );
	}
	return EVENT_HANDLE;
}

int main( int argc, char * argv[] )
{


	ExecutionMonitor em;
	em.set_monitor_callback( &moncallback );
	int nPID;
	HWND hWindow = FindWindow( NULL, "getWAN" );
	GetWindowThreadProcessId( hWindow, (LPDWORD)&nPID );
	WindowsDebugger * lpDbg = new WindowsDebugger();
	//IDebugger * lpDbg = IDebugger::init_get_instance();

	lpDbg->debugger_attach( nPID, FALSE );
	lpDbg->debugger_enter_loop();
//	lpDbg->debugger_enable_branch_logging();
	/*
	em.attach_and_monitor( nPID, 
	 (ExecutionMonitor::MONITOR_OPTIONS)
	 (ExecutionMonitor::MONITOR_DANGEROUS_FUNCTIONS | 
	 ExecutionMonitor::MONITOR_LIBRARY_INTERACTIONS) );
	 */
	system( "PAUSE" );
	//em.begin_monitoring();
}


#endif