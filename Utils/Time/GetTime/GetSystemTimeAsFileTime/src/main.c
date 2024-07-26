#include <windows.h>

unsigned long long GetTimestamp() {
	// Get the current system time
    FILETIME 		ft;
    ULARGE_INTEGER 	current_ul;
	
	const size_t UNIX_TIME_START    = 0x019DB1DED53E8000;   // Start of Unix epoch in ticks.
	const size_t TICKS_PER_SECOND   = 10000000;             // A tick is 100ns.

    GetSystemTimeAsFileTime(&ft);

    // Convert the current system time to a ULARGE_INTEGER
    current_ul.LowPart = ft.dwLowDateTime;
    current_ul.HighPart = ft.dwHighDateTime;

    // Convert the predefined Unix time to a ULARGE_INTEGER
    return (unsigned long long) ((current_ul.QuadPart - UNIX_TIME_START) / TICKS_PER_SECOND);
}

int main() {
    printf("[+] TimeStamp : %lld\n", GetTimestamp());

    return 0;
}