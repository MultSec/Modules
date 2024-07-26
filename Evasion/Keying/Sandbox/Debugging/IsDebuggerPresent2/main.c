#include <windows.h>
#include <stdio.h>
#include <winternl.h>

int IsDebuggerPresent2() {

  // getting the PEB structure
#ifdef _WIN64
	PPEB					pPeb = (PEB*)(__readgsqword(0x60));
#elif _WIN32
	PPEB					pPeb = (PEB*)(__readfsdword(0x30));
#endif

	// checking the 'BeingDebugged' element
	return (pPeb->BeingDebugged == 1);
}

int main() {
	if (IsDebuggerPresent2()) {
		printf("[!] Debugger present\n");
	} else {
		printf("[i] Debugger not detected\n");
	}
	
	printf("[#] Press <Enter> To Quit ...");
	getchar();

	return 0;
}