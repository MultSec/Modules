#include <windows.h>
#include <stdio.h>
#include "structs.h"

#define FLG_HEAP_ENABLE_TAIL_CHECK   0x10
#define FLG_HEAP_ENABLE_FREE_CHECK   0x20
#define FLG_HEAP_VALIDATE_PARAMETERS 0x40

BOOL IsDebuggerPresent3() {

  // getting the PEB structure
#ifdef _WIN64
	PPEB					pPeb = (PEB*)(__readgsqword(0x60));
#elif _WIN32
	PPEB					pPeb = (PEB*)(__readfsdword(0x30));
#endif

  // checking the 'NtGlobalFlag' element
  return (pPeb->NtGlobalFlag == (FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS));
}

int main() {
	if (IsDebuggerPresent3()) {
		printf("[!] Debugger present\n");
	} else {
		printf("[i] Debugger not detected\n");
	}
	
	printf("[#] Press <Enter> To Quit ...");
	getchar();

	return 0;
}