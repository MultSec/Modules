#include <windows.h>
#include <stdio.h>

#include "HardwareHooking.h"


// "Ret" Shellcode - Used to terminate original function execution
__attribute__((section(".text#"))) const unsigned char ucRet[] = { 0xC3 };

// Called in the detour function to block the execution of the original hooked function
VOID BLOCK_REAL(IN PCONTEXT pThreadCtx) {
#ifdef _WIN64
	pThreadCtx->Rip = (ULONG_PTR)&ucRet;
#elif _WIN32
	pThreadCtx->Eip = (DWORD)&ucRet;
#endif // _WIN64
}

//	Global Variables

PVOID				g_VectorHandler		= NULL;
CRITICAL_SECTION	g_CriticalSection	= { 0 };

// Array of detour function pointers
PVOID				g_DetourFuncs[4]	= { 0 }; // Maximum 4 hardware breakpoints 


// Privat Function - Used to print error messages
#define ERROR_BUF_SIZE	1024

BOOL ReportError(IN PCWSTR szApiFuncName, IN OPTIONAL ULONGLONG uError) {

	CHAR cBuffer[ERROR_BUF_SIZE];
	if (_snprintf_s(cBuffer, ERROR_BUF_SIZE, _TRUNCATE, "[!] %ws Failed With Error %s\n", szApiFuncName, uError != NULL ? "0x%0.8X" : "%d") == -1)
		printf("[!] _snprintf_s : String Exceed The Buffer Size [ %d ] \n", ERROR_BUF_SIZE);
	else
		printf(cBuffer, uError != NULL ? uError : GetLastError());

	return FALSE;
}

/*
	Used to modify the Dr7 register's flags
*/
unsigned long long SetDr7Bits(unsigned long long CurrentDr7Register, int StartingBitPosition, int NmbrOfBitsToModify, unsigned long long NewBitValue) {
	unsigned long long mask				= (1UL << NmbrOfBitsToModify) - 1UL;
	unsigned long long NewDr7Register	= (CurrentDr7Register & ~(mask << StartingBitPosition)) | (NewBitValue << StartingBitPosition);

	return NewDr7Register;
}

//-------------------------------------------------------------------------------------------------------------------------------------------------------------

/*
	Returns the hooked function's parameters from its thread context; called through the 'GETPARM_X' macro
*/
PBYTE GetFunctionArgument(IN PCONTEXT pThreadCtx, IN DWORD dwParmIndex) {

#ifdef _WIN64

	// the first 4 arguments in x64 are in the "RCX - RDX - R8 - R9" registers
	switch (dwParmIndex) {
	case 0x01:
		return (ULONG_PTR)pThreadCtx->Rcx;
	case 0x02:
		return (ULONG_PTR)pThreadCtx->Rdx;
	case 0x03:
		return (ULONG_PTR)pThreadCtx->R8;
	case 0x04:
		return (ULONG_PTR)pThreadCtx->R9;
	default:
		break;
	}

	// else more arguments are pushed to the stack
	return *(ULONG_PTR*)(pThreadCtx->Rsp + (dwParmIndex * sizeof(PVOID)));
#else
	return *(DWORD_PTR*)(pThreadCtx->Esp + (dwParmIndex * sizeof(PVOID)));
#endif // _WIN64

}

/*
	Edits the hooked function's parameters and set it to a custom value; called through the 'SETPARM_X' macro
*/

VOID SetFunctionArgument(IN PCONTEXT pThreadCtx, IN ULONG_PTR uValue, IN DWORD dwParmIndex) {

#ifdef _WIN64

	// the first 4 arguments in x64 are in the "RCX - RDX - R8 - R9" registers
	switch (dwParmIndex) {
	case 0x01:
		pThreadCtx->Rcx = (DWORD_PTR)uValue;
		return;
	case 0x02:
		pThreadCtx->Rdx = (DWORD_PTR)uValue;
		return;
	case 0x03:
		pThreadCtx->R8 = (DWORD_PTR)uValue;
		return;
	case 0x04:
		pThreadCtx->R9 = (DWORD_PTR)uValue;
		return;
	default:
		break;
	}

	// else more arguments are pushed to the stack
	*(ULONG_PTR*)(pThreadCtx->Rsp + (dwParmIndex * sizeof(PVOID))) = uValue;
#else
	*(DWORD_PTR*)(pThreadCtx->Esp + (dwParmIndex * sizeof(PVOID))) = uValue;
#endif // _WIN64

}

/*
	Used to install a hardware breakpoint on the local thread
		* pAddress			= Hardware breakpoint address (where to install)					 
		* fnHookFunc		= Pointer to the detour function 									 
		* Drx				= Can be Dr0->Dr3
*/

BOOL SetHardwareBreakingPnt(IN PVOID pAddress, IN PVOID fnHookFunc, IN DRX Drx) {

	// Check if not initialized
	if (!g_VectorHandler)
		return FALSE;

	if (!pAddress || !fnHookFunc)
		return FALSE;

	CONTEXT ThreadCtx = { .ContextFlags = CONTEXT_DEBUG_REGISTERS };

	// Get local thread context
	if (!GetThreadContext((HANDLE)-2, &ThreadCtx))
		return ReportError(TEXT("GetThreadContext"), NULL);

	// Sets the value of the Dr0-3 registers 
	switch (Drx) {
	case Dr0: {
		if (!ThreadCtx.Dr0)
			ThreadCtx.Dr0 = pAddress;
		break;
	}
	case Dr1: {
		if (!ThreadCtx.Dr1)
			ThreadCtx.Dr1 = pAddress;
		break;
	}
	case Dr2: {
		if (!ThreadCtx.Dr2)
			ThreadCtx.Dr2 = pAddress;
		break;
	}
	case Dr3: {
		if (!ThreadCtx.Dr3)
			ThreadCtx.Dr3 = pAddress;
		break;
	}
	default:
		return FALSE;
	}

	EnterCriticalSection(&g_CriticalSection);

	// Saves the address of the detour function at index 'Drx' in 'g_DetourFuncs'
	g_DetourFuncs[Drx] = fnHookFunc;

	LeaveCriticalSection(&g_CriticalSection);

	// Enable the breakpoint: Populate the G0-3 flags depending on the saved breakpoint position in the Dr0-3 registers
	ThreadCtx.Dr7 = SetDr7Bits(ThreadCtx.Dr7, (Drx * 2), 1, 1);

	// Set the thread context after editing it
	if (!SetThreadContext((HANDLE)-2, &ThreadCtx))
		return ReportError(TEXT("SetThreadContext"), NULL);

	return TRUE;
}

/*
	Remove hook on a specified register														
		* Drx				= Can be Dr0->Dr3
*/
BOOL RemoveHardwareBreakingPnt(IN DRX Drx) {

	// Check if not initialized
	if (!g_VectorHandler)
		return FALSE;

	CONTEXT ThreadCtx = { .ContextFlags = CONTEXT_DEBUG_REGISTERS };

	if (!GetThreadContext((HANDLE)-2, &ThreadCtx))
		return ReportError(TEXT("GetThreadContext"), NULL);


	// Remove the address of the hooked function from the thread context
	switch (Drx) {
		case Dr0: {
			ThreadCtx.Dr0 = 0x00;
			break;
		}
		case Dr1: {
			ThreadCtx.Dr1 = 0x00;
			break;
		}
		case Dr2: {
			ThreadCtx.Dr2 = 0x00;
			break;
		}
		case Dr3: {
			ThreadCtx.Dr3 = 0x00;
			break;
		}
		default:
			return FALSE;
	}

	// Disabling the hardware breakpoint by setting the target G0-3 flag to zero
	ThreadCtx.Dr7 = SetDr7Bits(ThreadCtx.Dr7, (Drx * 2), 1, 0);

	if (!SetThreadContext((HANDLE)-2, &ThreadCtx))
		return ReportError(TEXT("SetThreadContext"), NULL);

	return TRUE;
}

LONG WINAPI VectorHandler(PEXCEPTION_POINTERS pExceptionInfo) {

	// If the exception is 'EXCEPTION_SINGLE_STEP', then its caused by a breakpoint and we should handle it
	if (pExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {

		// Verfiy if the breakpoint is a hardware breakpoint we installed
		if (pExceptionInfo->ExceptionRecord->ExceptionAddress == pExceptionInfo->ContextRecord->Dr0 ||
			pExceptionInfo->ExceptionRecord->ExceptionAddress == pExceptionInfo->ContextRecord->Dr1 ||
			pExceptionInfo->ExceptionRecord->ExceptionAddress == pExceptionInfo->ContextRecord->Dr2 ||
			pExceptionInfo->ExceptionRecord->ExceptionAddress == pExceptionInfo->ContextRecord->Dr3) {

			DRX				dwDrx								= -1;
			VOID			(*fnHookFunc)(PCONTEXT)				= NULL;

			EnterCriticalSection(&g_CriticalSection);

			// Detect the hw bp register (Dr0-3)
			if (pExceptionInfo->ExceptionRecord->ExceptionAddress == pExceptionInfo->ContextRecord->Dr0)
				dwDrx = Dr0;
			if (pExceptionInfo->ExceptionRecord->ExceptionAddress == pExceptionInfo->ContextRecord->Dr1)
				dwDrx = Dr1;
			if (pExceptionInfo->ExceptionRecord->ExceptionAddress == pExceptionInfo->ContextRecord->Dr2)
				dwDrx = Dr2;
			if (pExceptionInfo->ExceptionRecord->ExceptionAddress == pExceptionInfo->ContextRecord->Dr3)
				dwDrx = Dr3;

			// Disable hw breakpoint to allow executing the hooked function from the detour function 
			RemoveHardwareBreakingPnt(dwDrx);

			// Execute the callback (detour function)
			fnHookFunc = g_DetourFuncs[dwDrx];
			fnHookFunc(pExceptionInfo->ContextRecord);

			// Enable the hw breakpoint again
			SetHardwareBreakingPnt(pExceptionInfo->ExceptionRecord->ExceptionAddress, g_DetourFuncs[dwDrx], dwDrx);

			LeaveCriticalSection(&g_CriticalSection);

			// Continue the execution - The exception is handled
			return EXCEPTION_CONTINUE_EXECUTION;
		}
	}

	// The exception is not handled:							\
	- Not from the hardware breakpoints	!(Dr0-3)			\
	- The exception code is not 'EXCEPTION_SINGLE_STEP'

	return EXCEPTION_CONTINUE_SEARCH;
}

BOOL InitializeHardwareBPVariables() {

	RtlSecureZeroMemory(&g_CriticalSection, sizeof(CRITICAL_SECTION));
	RtlSecureZeroMemory(&g_DetourFuncs, sizeof(g_DetourFuncs));

	// If 'g_CriticalSection' is not yet initialized
	if (g_CriticalSection.DebugInfo == NULL) {
		InitializeCriticalSection(&g_CriticalSection);
	}

	// If 'g_VectorHandler' is not yet initialized
	if (!g_VectorHandler) {
		// Add 'VectorHandler' as the VEH handler function
		if ((g_VectorHandler = AddVectoredExceptionHandler(1, (PVECTORED_EXCEPTION_HANDLER)&VectorHandler)) == NULL) 
			return ReportError(TEXT("AddVectoredExceptionHandler"), NULL);
	}

	return (g_VectorHandler && g_CriticalSection.DebugInfo);
}

VOID UnintializeHardwareBPVariables() {

	// Remove breakpoints
	for (int i = 0; i < 4; i++)
		RemoveHardwareBreakingPnt(i);
	// If critical section is initialized, delete it
	if (g_CriticalSection.DebugInfo)
		DeleteCriticalSection(&g_CriticalSection);
	// If VEH handler is registered, remove it
	if (g_VectorHandler)
		RemoveVectoredExceptionHandler(g_VectorHandler);

	// Cleanup the global variables
	RtlSecureZeroMemory(&g_CriticalSection, sizeof(CRITICAL_SECTION));
	RtlSecureZeroMemory(&g_DetourFuncs, sizeof(g_DetourFuncs));
	g_VectorHandler = NULL;
}
