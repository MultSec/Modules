#include <windows.h>
#include <stdio.h>

#define MIN_RAM 2 // 2GB

//Check for Computer Number of Processors
int checkMinRAM() {
	MEMORYSTATUSEX MemStatus = { .dwLength = sizeof(MEMORYSTATUSEX) };

	if (!GlobalMemoryStatusEx(&MemStatus)) {
		printf("\n\t[!] GlobalMemoryStatusEx Failed With Error : %d \n", GetLastError());
	}

	return ((MemStatus.ullTotalPhys / 1073741824) <= MIN_RAM);
}

int main() {
	if (checkMinRAM()) {
		printf("[!] Possible sandbox, amount of RAM less or equal than %d GB\n", MIN_RAM);
	} else {
		printf("[i] Amount of RAM more than %d GB\n", MIN_RAM);
	}
	
	printf("[#] Press <Enter> To Quit ...");
	getchar();

	return 0;
}