#include <windows.h>
#include <stdio.h>

#define TOO_MUCH_MEM 100000000 // 100mb

int AllocBigHeap() { 
	char * memdmp = NULL; 
	memdmp = (char *) malloc(TOO_MUCH_MEM);

	if(memdmp!=NULL) { 
		memset(memdmp,00, TOO_MUCH_MEM); 
		free(memdmp); 
		return TRUE;
	} 
		
	return FALSE;
}

int main() {
	if (!AllocBigHeap()) {
		printf("[!] Possible sandbox, allocation of %d mb wasn't applied\n", TOO_MUCH_MEM/100);
	} else {
		printf("[i] Allocation of %d mb was applied\n", TOO_MUCH_MEM/100);
	}
	
	printf("[#] Press <Enter> To Quit ...");
	getchar();

	return 0;
}

