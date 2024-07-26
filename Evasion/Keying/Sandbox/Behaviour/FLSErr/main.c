#include <windows.h>
#include <stdio.h>

int CheckNuma() { 
	DWORD result = FlsAlloc(NULL); 
	
	if (result != FLS_OUT_OF_INDEXES) { 
		return TRUE;
	} 
		
	return FALSE;
}

int main() {
	if (!CheckNuma()) {
		printf("[!] Possible sandbox, FLS related error encountered\n");
	} else {
		printf("[i] FLS allocation applied\n");
	}
	
	printf("[#] Press <Enter> To Quit ...");
	getchar();

	return 0;
}

