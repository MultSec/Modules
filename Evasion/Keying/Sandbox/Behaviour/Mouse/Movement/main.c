#include <windows.h>
#include <stdio.h>

#define TIME_DELAY 13000 //13 seconds

//Check for Mouse Movement
int checkMousePosition() {
    POINT pos1, pos2;

    GetCursorPos(&pos1);

	// If this sleep is fast forwarded then the mouse movement 
	// remains the same and therefore detects a sandbox env
    Sleep(TIME_DELAY);

    GetCursorPos(&pos2);

	// Check if position remains the same
    return ((pos1.x == pos2.x) && (pos1.y == pos2.y));

}

int main() {
	if (checkMousePosition()) {
		printf("[!] Possible sandbox, mouse didn't move in the span of %d ms\n", TIME_DELAY);
	} else {
		printf("[i] Mouse moved in the span of %d ms\n", TIME_DELAY);
	}
	
	printf("[#] Press <Enter> To Quit ...");
	getchar();

	return 0;
}

