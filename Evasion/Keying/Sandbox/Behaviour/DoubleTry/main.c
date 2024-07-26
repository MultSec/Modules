#include <windows.h>

#define TIME_DELAY 5000 //5 seconds

int main() {
	HANDLE hMutex = CreateMutexA(NULL, FALSE, "ControlString");

	if (hMutex != NULL && GetLastError() == ERROR_ALREADY_EXISTS) {
		MessageBoxA(NULL, "Pwned!", "Payload", MB_ICONINFORMATION);
	} else {
  		Sleep(TIME_DELAY);
	}

	return 0;
}