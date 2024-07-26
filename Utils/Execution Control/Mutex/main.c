#include <windows.h>
#include <stdio.h>

int main() {
	HANDLE hMutex = CreateMutexA(NULL, FALSE, "ControlString");

	if (hMutex != NULL && GetLastError() == ERROR_ALREADY_EXISTS)
		printf("[!] Payload Already Running\n");
	else
		printf("[i] Payload Running\n");
	
	printf("[#] Press <Enter> To Quit ...");
	getchar();

	return 0;
}