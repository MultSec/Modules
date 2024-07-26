#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include "structs.h"

// https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/thread.htm?ts=0,313
#define STATUS_SUCCESS              0x00000000
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004

// https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation
typedef NTSTATUS (WINAPI* fnNtQuerySystemInformation)(
   SYSTEM_INFORMATION_CLASS SystemInformationClass,
   PVOID                    SystemInformation,
   ULONG                    SystemInformationLength,
   PULONG                   ReturnLength
);

BOOL GetLocalThreadHandle(IN DWORD dwMainThreadId, OUT DWORD* dwThreadId, OUT HANDLE* hThread) {
	// Getting the local process ID
	DWORD				dwProcessId		= GetCurrentProcessId();
    fnNtQuerySystemInformation		pNtQuerySystemInformation   = NULL;
    ULONG							uReturnLen1                 = NULL,
                                    uReturnLen2                 = NULL;
    PSYSTEM_PROCESS_INFORMATION		SystemProcInfo              = NULL;
    PVOID							pValueToFree                = NULL;
    NTSTATUS						STATUS                      = NULL;

    // Fetching NtQuerySystemInformation's address from ntdll.dll
    pNtQuerySystemInformation = (fnNtQuerySystemInformation)GetProcAddress(GetModuleHandle("NTDLL.DLL"), "NtQuerySystemInformation");
    if (pNtQuerySystemInformation == NULL) {
        printf("[!] GetProcAddress Failed With Error : %d\n", GetLastError());
        goto _EndOfFunc;
    }

    // First NtQuerySystemInformation call - retrieve the size of the return buffer (uReturnLen1)
    if ((STATUS = pNtQuerySystemInformation(SystemProcessInformation, NULL, NULL, &uReturnLen1)) != STATUS_SUCCESS && STATUS != STATUS_INFO_LENGTH_MISMATCH) {
        printf("[!] NtQuerySystemInformation [1] Failed With Error : 0x%0.8X \n", STATUS);
        goto _EndOfFunc;
    }

    // Allocating buffer of size "uReturnLen1" 
    SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)uReturnLen1);
    if (SystemProcInfo == NULL) {
        printf("[!] HeapAlloc Failed With Error : %d\n", GetLastError());
        goto _EndOfFunc;
    }

    // Setting a fixed variable to be used later to free, because "SystemProcInfo" will be modefied
    pValueToFree = SystemProcInfo;

    // Second NtQuerySystemInformation call - returning the SYSTEM_PROCESS_INFORMATION array (SystemProcInfo)
    if ((STATUS = pNtQuerySystemInformation(SystemProcessInformation, SystemProcInfo, uReturnLen1, &uReturnLen2)) != STATUS_SUCCESS) {
        printf("[!] NtQuerySystemInformation [2] Failed With Error : 0x%0.8X \n", STATUS);
        goto _EndOfFunc;
    }

    // Enumerating SystemProcInfo, looking for process "szProcName"
    while (TRUE) {
		// Iterate over each proc
        if ((DWORD)SystemProcInfo->UniqueProcessId == dwProcessId) {
			// On the target proc, iterate each thread
			for (int i = 0; i < SystemProcInfo->NumberOfThreads; i++) {
				// The '(DWORD)SystemProcInfo->Threads[i].ClientId.UniqueThread != dwMainThreadId' is to 
				// avoid targeting the main thread of our local process
				if((DWORD)SystemProcInfo->Threads[i].ClientId.UniqueThread != dwMainThreadId){
					// Opening a handle to the thread 
					*dwThreadId = (DWORD)SystemProcInfo->Threads[i].ClientId.UniqueThread;
					*hThread	= OpenThread(THREAD_ALL_ACCESS, FALSE, (DWORD)SystemProcInfo->Threads[0].ClientId.UniqueThread);

					if (*hThread == NULL)
						printf("\n\t[!] OpenThread Failed With Error : %d \n", GetLastError());

					break;
				}
			}
		}

        // If we reached the end of the SYSTEM_PROCESS_INFORMATION structure
        if (!SystemProcInfo->NextEntryOffset)
            break;

        // Calculate the next SYSTEM_PROCESS_INFORMATION element in the array
        SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)SystemProcInfo + SystemProcInfo->NextEntryOffset);
    }

    // Free the SYSTEM_PROCESS_INFORMATION structure
_EndOfFunc:
    if (pValueToFree)
        HeapFree(GetProcessHeap(), 0, pValueToFree);
	if (*dwThreadId == NULL || *hThread == NULL)
		return FALSE;
	return TRUE;
}

int main() {
	HANDLE		hThread			= NULL;
	DWORD		dwMainThreadId	= NULL,
				dwThreadId		= NULL;
	
	// getting the main thread id, since we are calling from our main thread, and not from a worker thread
	// 'GetCurrentThreadId' will return the main thread ID
	dwMainThreadId	= GetCurrentThreadId();

	printf("[i] Searching For A Thread Under The Local Process ... \n");
	if (!GetLocalThreadHandle(dwMainThreadId, &dwThreadId, &hThread)) {
		printf("[!] No Thread is Found \n");
		return -1;
	}
	printf("\t[i] Found Target Thread Of Id: %d \n", dwThreadId);
	printf("[+] DONE \n\n");

	printf("[#] Press <Enter> To Quit ... ");
	getchar();

	return 0;
}