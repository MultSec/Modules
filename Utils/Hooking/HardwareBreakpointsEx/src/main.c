#include <windows.h>
#include <stdio.h>
#include "HardwareHooking.h"

VOID SleepDetour(PCONTEXT pThreadCtx) {

	printf("[i] Sleep's Old Parameters: \n");
	printf("\t> %d \n", (DWORD)GETPARM_1(pThreadCtx));

	BLOCK_REAL(pThreadCtx);

	CONTINUE_EXECUTION(pThreadCtx);
}

VOID MessageBoxADetour(PCONTEXT pThreadCtx) {

	printf("[i] MessageBoxA's Old Parameters: \n");
	printf("\t> %s \n", (char*)GETPARM_2(pThreadCtx));
	printf("\t> %s \n", (char*)GETPARM_3(pThreadCtx));


	RETURN_VALUE(pThreadCtx, MessageBoxA(NULL, "This is the hook", "MessageBoxADetour", MB_OK | MB_ICONEXCLAMATION));
	BLOCK_REAL(pThreadCtx);

	CONTINUE_EXECUTION(pThreadCtx);
}

VOID NewlySpawnedThread() {
	// HOOKED
	MessageBoxA(NULL, "This Wont Execute", "Will it?", MB_OK);
	// HOOKED
	Sleep(-1);
}


int main() {

	// Initialize 
	if (!InitHardwareBreakpointHooking())
		return -1;

	printf("[i] Installing Hooks ... ");
	// Hook 'MessageBoxA' to call 'MessageBoxADetour' instead - using the Dr0 register
	if (!InstallHardwareBreakingPntHook(MessageBoxA, Dr0, MessageBoxADetour, ALL_THREADS))
		return -1;

	// Hook 'Sleep' to call 'SleepDetour' instead - using the Dr1 register
	if (!InstallHardwareBreakingPntHook(Sleep, Dr1, SleepDetour, ALL_THREADS))
		return -1;
	printf("[+] DONE \n");


	printf("[i] Installing The Same Hooks On New Threads ... ");
	// Install the same 'ALL_THREADS' hooks on new threads created in the future - using the Dr2 register
	if (!InstallHooksOnNewThreads(Dr2))
		return -1;
	printf("[+] DONE \n");


	// MessageBoxA & Sleep are called and hooked in a new thread
	WaitForSingleObject(CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)NewlySpawnedThread, NULL, NULL, NULL), INFINITE);
	
	
	printf("[#] Press <Enter> To Cleanup And Exit ... \n");
	getchar();
	// Clean up
	if (!CleapUpHardwareBreakpointHooking())
		return -1;
	
	return 0;
}