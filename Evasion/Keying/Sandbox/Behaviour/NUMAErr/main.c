#include <windows.h>
#include <stdio.h>

int CheckNuma() { 
	LPVOID mem = NULL; 
	mem = VirtualAllocExNuma(GetCurrentProcess(), NULL, 1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE,0); 
	
	if (mem != NULL) { 
		return TRUE;
	} 
		
	return FALSE;
}

int main() {
	if (!CheckNuma()) {
		printf("[!] Possible sandbox, NUMA related error encountered\n");
	} else {
		printf("[i] NUMA function applied\n");
	}
	
	printf("[#] Press <Enter> To Quit ...");
	getchar();

	return 0;
}

