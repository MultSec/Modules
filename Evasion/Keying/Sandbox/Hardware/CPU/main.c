#include <windows.h>
#include <stdio.h>

#define MIN_PROCS 2

//Check for Computer Number of Processors
int checkProcNum() {
	SYSTEM_INFO   SysInfo   = { 0 };
	
	GetSystemInfo(&SysInfo);

	return (SysInfo.dwNumberOfProcessors <= MIN_PROCS);
}

int main() {
	if (checkProcNum()) {
		printf("[!] Possible sandbox, number of CPU processors less or equal than %d\n", MIN_PROCS);
	} else {
		printf("[i] Number of CPU processors more than %d\n", MIN_PROCS);
	}
	
	printf("[#] Press <Enter> To Quit ...");
	getchar();

	return 0;
}