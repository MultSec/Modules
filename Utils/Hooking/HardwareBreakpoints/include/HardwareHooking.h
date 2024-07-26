#pragma once

#include <windows.h>

#ifndef HARDWAREBP_H
#define HARDWAREBP_H

//---------------------------------------------------------------------------------------------------------------------------------------------------------
//---------------------------------------------------------------------------------------------------------------------------------------------------------
//	PRIVATE

PBYTE	GetFunctionArgument(IN PCONTEXT pThreadCtx, IN DWORD dwParmIndex);
VOID	SetFunctionArgument(IN PCONTEXT pThreadCtx, IN ULONG_PTR uValue, IN DWORD dwParmIndex);

typedef enum _DRX
{
	Dr0,
	Dr1,
	Dr2,
	Dr3

}DRX, * PDRX;


//---------------------------------------------------------------------------------------------------------------------------------------------------------
//---------------------------------------------------------------------------------------------------------------------------------------------------------
//				MACROS TO BE CALLED FROM WITHIN THE DETOURS FUNCTIONS

// Get Parameters
#define GETPARM_1(CTX)(GetFunctionArgument(CTX, 0x1))	
#define GETPARM_2(CTX)(GetFunctionArgument(CTX, 0x2))
#define GETPARM_3(CTX)(GetFunctionArgument(CTX, 0x3))
#define GETPARM_4(CTX)(GetFunctionArgument(CTX, 0x4))
#define GETPARM_5(CTX)(GetFunctionArgument(CTX, 0x5))
#define GETPARM_6(CTX)(GetFunctionArgument(CTX, 0x6))
#define GETPARM_7(CTX)(GetFunctionArgument(CTX, 0x7))
#define GETPARM_8(CTX)(GetFunctionArgument(CTX, 0x8))
#define GETPARM_9(CTX)(GetFunctionArgument(CTX, 0x9))
#define GETPARM_A(CTX)(GetFunctionArgument(CTX, 0xA))
#define GETPARM_B(CTX)(GetFunctionArgument(CTX, 0xB))

// Set Parameters
#define SETPARM_1(CTX, VALUE)(SetFunctionArgument(CTX, VALUE, 0x1))
#define SETPARM_2(CTX, VALUE)(SetFunctionArgument(CTX, VALUE, 0x2))
#define SETPARM_3(CTX, VALUE)(SetFunctionArgument(CTX, VALUE, 0x3))
#define SETPARM_4(CTX, VALUE)(SetFunctionArgument(CTX, VALUE, 0x4))
#define SETPARM_5(CTX, VALUE)(SetFunctionArgument(CTX, VALUE, 0x5))
#define SETPARM_6(CTX, VALUE)(SetFunctionArgument(CTX, VALUE, 0x6))
#define SETPARM_7(CTX, VALUE)(SetFunctionArgument(CTX, VALUE, 0x7))
#define SETPARM_8(CTX, VALUE)(SetFunctionArgument(CTX, VALUE, 0x8))
#define SETPARM_9(CTX, VALUE)(SetFunctionArgument(CTX, VALUE, 0x9))
#define SETPARM_A(CTX, VALUE)(SetFunctionArgument(CTX, VALUE, 0xA))
#define SETPARM_B(CTX, VALUE)(SetFunctionArgument(CTX, VALUE, 0xB))

// Called in the detour functions to continue execution
#define CONTINUE_EXECUTION(CTX)(CTX->EFlags = CTX->EFlags | (1 << 16))

// Called in the detour function to return a value
#ifdef _WIN64
#define RETURN_VALUE(CTX, VALUE) ((CTX)->Rax = (ULONG_PTR)(VALUE))
#elif _WIN32
#define RETURN_VALUE(CTX, VALUE) ((CTX)->Eax = (ULONG_PTR)(VALUE))
#endif // _WIN64

// Called in the detour function to terminate the hooked function execution 
VOID BLOCK_REAL(IN PCONTEXT pThreadCtx);

//---------------------------------------------------------------------------------------------------------------------------------------------------------
//---------------------------------------------------------------------------------------------------------------------------------------------------------
//			PUBLIC LIBRARY FUNCTIONS

// Initializes the hardware breaking point library 
BOOL InitializeHardwareBPVariables();
// Disable all the breaking points set and delete the veh handler
VOID UnintializeHardwareBPVariables();


// Install hook on a specified address														\
	* pAddress			= Hardware breaking point address (where to install)				\
	* fnHookFunc		= Pointer to the detour function 									\
	* Drx				= Can be Dr0->Dr3													
BOOL SetHardwareBreakingPnt(IN PVOID pAddress, IN PVOID fnHookFunc, IN DRX Drx);

// Remove hook on a specified register														\
	* Drx				= Can be Dr0->Dr3
BOOL RemoveHardwareBreakingPnt(IN DRX Drx);


#endif // !HARDWAREBP_H