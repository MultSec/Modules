#include <windows.h>
#include <stdio.h>

// Common screen resolutions
// - 1920x1080 (Full HD)
// - 2560x1440 (Quad HD)
// - 3840x2160 (4K UHD)
// - 1280x720 (HD)
#define MIN_HEIGHT 720

//Check for Screen Height
int checkScreenHeight() {
    return (GetSystemMetrics(SM_CYFULLSCREEN) <= MIN_HEIGHT);
}

int main() {
	if (checkScreenHeight()) {
		printf("[!] Possible sandbox, screen height lower than %d\n", MIN_HEIGHT);
	} else {
		printf("[i] Screen height bigger than %d\n", MIN_HEIGHT);
	}
	
	printf("[#] Press <Enter> To Quit ...");
	getchar();

	return 0;
}

