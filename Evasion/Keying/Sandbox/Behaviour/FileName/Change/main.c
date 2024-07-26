#include <windows.h>
#include <stdio.h>
#include <string.h>

#define ORIGINAL_NAME "test_x64.exe"

int CheckNameChange() {
    char buffer[MAX_PATH];

    // Get path of executable
    GetModuleFileNameA(NULL, buffer, MAX_PATH);

    // Extracting just the file name from the path
    char *fileName = strrchr(buffer, '\\');
    if (fileName != NULL) {
        fileName++; // Move past the backslash
    } else {
        fileName = buffer; // If no backslash found, use the entire path
    }

    // Check if the file name matches the original name
    return strcmp(fileName, ORIGINAL_NAME);
}

int main() {
	if (CheckNameChange()) {
		printf("[!] Possible sandbox, executable name is not %s\n", ORIGINAL_NAME);
	} else {
		printf("[i] Executable name is %s\n", ORIGINAL_NAME);
	}
	
	printf("[#] Press <Enter> To Quit ...");
	getchar();

	return 0;
}

