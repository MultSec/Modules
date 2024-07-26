#include <windows.h>

typedef struct _KSYSTEM_TIME {
     unsigned long LowPart;
     long High1Time;
     long High2Time;
} KSYSTEM_TIME, *PKSYSTEM_TIME;

unsigned long long GetTimestamp() {
	const size_t UNIX_TIME_START    = 0x019DB1DED53E8000;   // Start of Unix epoch in ticks.
	const size_t TICKS_PER_SECOND   = 10000000;             // A tick is 100ns.

	LARGE_INTEGER time;

	time.LowPart    = *(DWORD*)(0x7FFE0000 + 0x14);         // Read LowPart as unsigned long.
	time.HighPart   = *(long*)(0x7FFE0000 + 0x1c);          // Read High1Part as long.

	return (unsigned long long)((time.QuadPart - UNIX_TIME_START) / TICKS_PER_SECOND);
}

int main() {
    printf("[+] TimeStamp : %lld\n", GetTimestamp());

    return 0;
}