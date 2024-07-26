#include <windows.h>
#include <stdio.h>

// Define a global variable to store the pointer to the original exception handler
PVOID g_OldExceptionHandler = NULL;

// Vectored Exception Handler function
LONG WINAPI VectoredExceptionHandler(
	_In_ PEXCEPTION_POINTERS ExceptionInfo
) {
    // Check if the exception is an access violation
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
        printf("[!] Possible sandbox, Access Violation Exception caught!\n");
        return EXCEPTION_EXECUTE_HANDLER; // Handle the exception
    }

    // Call the original exception handler if it exists
    if (g_OldExceptionHandler != NULL)
        return ((LONG(WINAPI*)(PEXCEPTION_POINTERS))g_OldExceptionHandler)(ExceptionInfo);

    return EXCEPTION_CONTINUE_SEARCH; // Continue searching for another handler
}

// Function to install the Vectored Exception Handler
BOOL InstallVectoredExceptionHandler(
	_In_ VOID
) {
    g_OldExceptionHandler = AddVectoredExceptionHandler(1, VectoredExceptionHandler);
    if (g_OldExceptionHandler == NULL) {
        printf("[!] Failed to install Vectored Exception Handler!\n");
        return FALSE;
    }
    return TRUE;
}

VOID invalidMSR(
	_In_ VOID
) {
    ULONGLONG result = __readmsr(0x40000000);
    if (result == 0xFFFFFFFFFFFFFFFFULL && GetLastError() != NO_ERROR) {
        printf("[!] __readmsr Failed With Error : %d\n", GetLastError());
        return;
    }
	
    return;
}

int main() {
    // Install the Vectored Exception Handler
    if (!InstallVectoredExceptionHandler()) {
        printf("[!] Exiting...\n");
        return 1;
    }

	// Check if exception was triggered
    invalidMSR();
    
	printf("[i] No Exception caught\n");

    printf("[#] Press <Enter> To Quit ...");
    getchar();

    return 0;
}
