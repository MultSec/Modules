#include <windows.h>
#include <stdio.h>
#include <stdint.h>

typedef struct {
	uint32_t EAX;
	uint32_t EBX;
	uint32_t ECX;
	uint32_t EDX;
} _cpuid_buffer_t;

int checkCpuidPerf() {
	// If the CPUID instruction execution time is longer than the arithmetic
	// instruction it’s a reliable indication that the system is virtualized
	// because under no circumstances should the arithmetic instruction take
	// longer than the CPUID execution to grab vendor, or version information.
	// This detection will also catch those using TSC offsetting/scaling.

	int measure_times 	= 5;
	int positives		= 0;
	int threshold		= ( measure_times / 2 ) + 1;

	for (int i = 0; i < measure_times; i++) {
		int measure_time = 5;

		long long __cpuid_time   	= 0;
		long long __fyl2xp1_time 	= 0;

		LARGE_INTEGER frequency 	= { 0 };
		LARGE_INTEGER start     	= { 0 };
		LARGE_INTEGER end       	= { 0 };
		
		_cpuid_buffer_t cpuid_data 	= { 0 };

		QueryPerformanceFrequency(&frequency);

		// count the average time it takes to execute a CPUID instruction
		for (int i = 0; i < measure_time; ++i) {
			QueryPerformanceCounter(&start);
			__cpuid(&cpuid_data, 1);
			QueryPerformanceCounter(&end);

			__cpuid_time += (((end.QuadPart - start.QuadPart) * 1000000000) / frequency.QuadPart);
		}

		// count the average time it takes to execute a FYL2XP1 instruction
		for (int i = 0; i < measure_time; ++i) {
			QueryPerformanceCounter(&start);
            __asm__ (
                "FYL2XP1"
			);
			QueryPerformanceCounter(&end);

			__fyl2xp1_time += (((end.QuadPart - start.QuadPart) * 1000000000) / frequency.QuadPart);
		}

		if (__fyl2xp1_time <= __cpuid_time)
			positives++;
	}

	if (positives > threshold)
		return 1;
    return 0;
}

int main() {
	if (checkCpuidPerf()) {
		printf("[!] Possible sandbox, cpuinfo took too much time\n");
	} else {
		printf("[i] No VM files found\n");
	}
	
	printf("[#] Press <Enter> To Quit ...");
	getchar();

	return 0;
}