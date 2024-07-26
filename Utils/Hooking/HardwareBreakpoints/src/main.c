#include <windows.h>
#include <stdio.h>

#include "HardwareHooking.h"

VOID MessageBoxADetour(
    _In_ PCONTEXT pThreadCtx
) {

	printf("[i] MessageBoxA's Old Parameters: \n");
	printf("\t> %s \n", (char*)GETPARM_2(pThreadCtx));
	printf("\t> %s \n", (char*)GETPARM_3(pThreadCtx));

	//SETPARM_2(pThreadCtx, "This Is The Hook");
	//SETPARM_3(pThreadCtx, "MessageBoxADetour");
	//SETPARM_4(pThreadCtx, (MB_OK | MB_ICONEXCLAMATION));

	RETURN_VALUE(pThreadCtx, MessageBoxA(NULL, "This is the hook", "MessageBoxADetour", MB_OK | MB_ICONEXCLAMATION));
	BLOCK_REAL(pThreadCtx);

	CONTINUE_EXECUTION(pThreadCtx);
}


VOID SleepDetour(
    _In_ PCONTEXT pThreadCtx
) {

	printf("[i] Sleep's Old Parameters: \n");
	printf("\t> %d \n", (DWORD)GETPARM_1(pThreadCtx));

	//SETPARM_1(pThreadCtx, 0);

	BLOCK_REAL(pThreadCtx);
	
	CONTINUE_EXECUTION(pThreadCtx);
}

int main(
    _In_ VOID
) {

	// Initialize 
	if (!InitializeHardwareBPVariables())
		return -1;


	// NOT HOOKED
	MessageBoxA(NULL, "This Is A Normal MsgBoxA Call (0)", "Normal", MB_OK);


	printf("[i] Installing Hooks ... ");
	// Hook 'MessageBoxA' to call 'MessageBoxADetour' instead - using the Dr0 register
	if (!SetHardwareBreakingPnt(MessageBoxA, MessageBoxADetour, Dr0))
		return -1;
	
	// Hook 'Sleep' to call 'SleepDetour' instead - using the Dr1 register
	if (!SetHardwareBreakingPnt(Sleep, SleepDetour, Dr1))
		return -1;
	printf("[+] DONE \n");

	// HOOKED
	MessageBoxA(NULL, "This Wont Execute", "Will it ?", MB_OK);
	// HOOKED
	Sleep(-1);

	// Unhooking the installed hook on 'Dr0'
	printf("[i] Uninstalling Hooks ... ");
	if (!RemoveHardwareBreakingPnt(Dr0)) 
		return -1;
	printf("[+] DONE \n");
	
	// NOT HOOKED
	MessageBoxA(NULL, "This Is A Normal MsgBoxA Call (1)", "Normal", MB_OK);
	// HOOKED
	Sleep(-1);

	// Clean up
	UnintializeHardwareBPVariables();
	printf("[#] Press <Enter> To Quit ... ");
	getchar();
	return 0;
}