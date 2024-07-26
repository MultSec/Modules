#include <windows.h>
#include <stdio.h>

int main() {
	if (IsUserAnAdmin()) {
		printf("[i] Executed as Admin\n");
	} else {
		printf("[i] Executed as non Admin\n");
	}
	
	printf("[#] Press <Enter> To Quit ...");
	getchar();

	return 0;
}

