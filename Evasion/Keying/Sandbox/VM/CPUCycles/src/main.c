#include "header.h"

#define AVG_CPU_CYCLES 200	// Test on baremetal to better tweak

DWORD GetAvgCPUCycles( 
	VOID
) {
	long long tsc, acc = 0; 		// setup tsc and accumulator var
	int out[4]; 					// buffer for cpuidex to write into
	

	// loop a 1000 times for precision
	for (int i = 0; i < 1000; ++i) { 
		tsc = __rdtsc(); 			// get the amount of cpu cycles
		__cpuidex( out, 0, 0 ); 	// burn some cpu cycles
		acc += __rdtsc() - tsc; 	// add accumulator to current cpu timestamp minus the previous amount of cpu cycles registerd
	}

	return (DWORD) (acc / 100); 	// divide per 100 to get the average
}

BOOL checkCPUCycles(
	VOID
) {
	return (GetAvgCPUCycles() > AVG_CPU_CYCLES);
}

int main() {
    printf("[i] Using CPU cycles to check a VM\n");
	printf("[#] Press <Enter> check for a VM ... ");
    getchar();

	if (checkCPUCycles()) {
		printf("[!] Possible sandbox, CPU cycles too high!\n");
	} else {
		printf("[i] CPU cycles seem normal\n");
	}
	
	printf("[#] Press <Enter> To Quit ...");
	getchar();

	return 0;
}