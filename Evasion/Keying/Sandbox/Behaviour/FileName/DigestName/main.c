#include <windows.h>
#include <stdio.h>
#include <string.h>

#define MAX_DIGITS_NUM 3

int CheckDigestName() {
    char buffer[MAX_PATH];
    DWORD   dwNumberOfDigits	= NULL;

    // Get path of executable
    GetModuleFileNameA(NULL, buffer, MAX_PATH);

    // Extracting just the file name from the path
    char *fileName = strrchr(buffer, '\\');
    if (fileName != NULL) {
        fileName++; // Move past the backslash
    } else {
        fileName = buffer; // If no backslash found, use the entire path
    }

    // Count number of digits in the executable name
	for (int i = 0; i < lstrlenA(fileName); i++){
		if (isdigit(fileName[i]))
			dwNumberOfDigits++;
	}

    // Check if the file name has more digits than the minimum allowed
    return (dwNumberOfDigits > MAX_DIGITS_NUM);
}

int main() {
	if (CheckDigestName()) {
		printf("[!] Possible sandbox, executable name contains more than %d digits\n", MAX_DIGITS_NUM);
	} else {
		printf("[i] Executable name contains less than %d digits\n", MAX_DIGITS_NUM);
	}
	
	printf("[#] Press <Enter> To Quit ...");
	getchar();

	return 0;
}

