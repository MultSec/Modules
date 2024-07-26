#include <windows.h>
#include <stdio.h>

int main() {
	HANDLE hSemaphore = CreateSemaphoreA(NULL, 10, 10, "ControlString");

	if (hSemaphore != NULL && GetLastError() == ERROR_ALREADY_EXISTS)
		printf("[!] Payload Already Running\n");
	else
		printf("[i] Payload Running\n");
	
	printf("[#] Press <Enter> To Quit ...");
	getchar();

	return 0;
}