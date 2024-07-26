#include <windows.h>
#include <stdio.h>

#define TIME_DELAY 13000 //13 seconds

int CheckFastForward() {
  DWORD T0 = GetTickCount64();
  
  // Delay the execution
  Sleep(TIME_DELAY);

  DWORD T1 = GetTickCount64();
  
  // If the execution wasnt delayed then the ticks count is not the same or higher than the delay
  return ((DWORD)(T1 - T0) < TIME_DELAY);
}

int main() {
	if (CheckFastForward()) {
		printf("[!] Possible sandbox, delay of %d ms wasn't applied\n", TIME_DELAY);
	} else {
		printf("[i] Delay of %d ms was applied\n", TIME_DELAY);
	}
	
	printf("[#] Press <Enter> To Quit ...");
	getchar();

	return 0;
}

