#include <windows.h>
#include <stdio.h>

int main() {
	HANDLE hEvent = CreateEventA(NULL, FALSE, FALSE, "ControlString");

	if (hEvent != NULL && GetLastError() == ERROR_ALREADY_EXISTS)
		printf("[!] Payload Already Running\n");
	else
		printf("[i] Payload Running\n");
	
	printf("[#] Press <Enter> To Quit ...");
	getchar();

	return 0;
}