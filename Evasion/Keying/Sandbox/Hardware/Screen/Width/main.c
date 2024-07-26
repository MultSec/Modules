#include <windows.h>
#include <stdio.h>

// Common screen resolutions
// - 1920x1080 (Full HD)
// - 2560x1440 (Quad HD)
// - 3840x2160 (4K UHD)
// - 1280x720 (HD)
#define MIN_WIDTH 1280

//Check for Screen Width
int checkScreenWidth() {
    return (GetSystemMetrics(SM_CXFULLSCREEN) <= MIN_WIDTH);
}

int main() {
	if (checkScreenWidth()) {
		printf("[!] Possible sandbox, screen width lower than %d\n", MIN_WIDTH);
	} else {
		printf("[i] Screen width bigger than %d\n", MIN_WIDTH);
	}
	
	printf("[#] Press <Enter> To Quit ...");
	getchar();

	return 0;
}

