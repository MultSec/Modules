#include <windows.h>
#include <stdio.h>

#define TIME_LIMIT 1706832000 // Unix time for April 1, 2024

// Check the Kill Date Time
int checkTime() {
	// Get the current system time
    FILETIME ft;
    ULARGE_INTEGER current_ul;

    GetSystemTimeAsFileTime(&ft);

    // Convert the current system time to a ULARGE_INTEGER
    current_ul.LowPart = ft.dwLowDateTime;
    current_ul.HighPart = ft.dwHighDateTime;

    // Convert the predefined Unix time to a ULARGE_INTEGER
    ULARGE_INTEGER predefined_ul;
    predefined_ul.QuadPart = (ULONGLONG)((TIME_LIMIT * 10000000) + 116444736000000000ull);

	return (current_ul.QuadPart > predefined_ul.QuadPart);
}

int main() {
	if (checkTime()) {
		printf("[!] Out of scope, current date after %llu\n", TIME_LIMIT);
	} else {
		printf("[i] In scope, date is before or equal to %llu\n", TIME_LIMIT);
	}
	
	printf("[#] Press <Enter> To Quit ...");
	getchar();

	return 0;
}