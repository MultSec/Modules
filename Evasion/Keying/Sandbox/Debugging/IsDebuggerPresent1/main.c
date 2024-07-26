#include <windows.h>
#include <stdio.h>

int main() {
	if (IsDebuggerPresent()) {
		printf("[!] Debugger present\n");
	} else {
		printf("[i] Debugger not detected\n");
	}
	
	printf("[#] Press <Enter> To Quit ...");
	getchar();

	return 0;
}