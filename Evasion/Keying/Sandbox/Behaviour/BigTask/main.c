#include <windows.h>
#include <stdio.h>

#define MAX_OP 100000000

int DoBigTask() { 
	int cpt = 0; 
	int i = 0; 
	
	for(i =0; i < MAX_OP; i ++) { 
		cpt++; 
	} 
	
	if(cpt == MAX_OP) { 
		return TRUE;
	}

	return FALSE;
}

int main() {
	if (!DoBigTask()) {
		printf("[!] Possible sandbox, task of %d operations wasn't applied\n", MAX_OP);
	} else {
		printf("[i] Task of %d operations was applied\n", MAX_OP);
	}
	
	printf("[#] Press <Enter> To Quit ...");
	getchar();

	return 0;
}

