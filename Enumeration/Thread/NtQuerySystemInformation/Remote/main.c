#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include "structs.h"

#define TARGET_PROCESS L"notepad.exe"

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

BOOL GetRemoteProcessHandle(LPCWSTR szProcName, DWORD* pdwPid, HANDLE* phProcess) {

	fnNtQuerySystemInformation   pNtQuerySystemInformation = NULL;
	ULONG                        uReturnLen1               = NULL,
                                 uReturnLen2               = NULL;
    PSYSTEM_PROCESS_INFORMATION  SystemProcInfo            = NULL;
    NTSTATUS                     STATUS                    = NULL;
	PVOID                        pValueToFree              = NULL;
	
	// Retrieve NtQuerySystemInformation's Address
	pNtQuerySystemInformation = (fnNtQuerySystemInformation)GetProcAddress(GetModuleHandle("NTDLL.DLL"), "NtQuerySystemInformation");
	if (pNtQuerySystemInformation == NULL) {
		printf("[!] GetProcAddress Failed With Error : %d\n", GetLastError());
		return FALSE;
	}

	// First NtQuerySystemInformation call
	// This will fail with STATUS_INFO_LENGTH_MISMATCH
	// But it will provide information about how much memory to allocate (uReturnLen1)
	pNtQuerySystemInformation(SystemProcessInformation, NULL, NULL, &uReturnLen1);

	// Allocating enough buffer for the returned array of `SYSTEM_PROCESS_INFORMATION` struct
	SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)uReturnLen1);
	if (SystemProcInfo == NULL) {
		printf("[!] HeapAlloc Failed With Error : %d\n", GetLastError());
		return FALSE;
	}

	// Since we will modify 'SystemProcInfo', we will save its initial value before the while loop to free it later
	pValueToFree = SystemProcInfo;

	// Second NtQuerySystemInformation call
	// Calling NtQuerySystemInformation with the correct arguments, the output will be saved to 'SystemProcInfo
	STATUS = pNtQuerySystemInformation(SystemProcessInformation, SystemProcInfo, uReturnLen1, &uReturnLen2);
	if (STATUS != 0x0) {
		printf("[!] NtQuerySystemInformation Failed With Error : 0x%0.8X \n", STATUS);
		return FALSE;
	}

	while (TRUE) {
		// Check the process's name size
		// Comparing the enumerated process name to the intended target process
		if (SystemProcInfo->ImageName.Length && (wcscmp(SystemProcInfo->ImageName.Buffer, szProcName) == 0)) {
			
			// Opening a handle to the target process, saving it, and then breaking 
			*pdwPid		= (DWORD)SystemProcInfo->UniqueProcessId;
			*phProcess	= OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)SystemProcInfo->UniqueProcessId);
			break;
		}

		// If NextEntryOffset is 0, we reached the end of the array
		if (!SystemProcInfo->NextEntryOffset)
			break;

		// Move to the next element in the array
		SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)SystemProcInfo + SystemProcInfo->NextEntryOffset);
	}

	// Free using the initial address
	HeapFree(GetProcessHeap(), 0, pValueToFree);

	// Check if we successfully got the target process handle
	if (*pdwPid == NULL || *phProcess == NULL)
		return FALSE;
	else
		return TRUE;
}

BOOL GetRemoteThreadhandle(IN DWORD dwProcessId, OUT DWORD* dwThreadId, OUT HANDLE* hThread) {
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

			// Opening a handle to the thread 
			*dwThreadId = (DWORD)SystemProcInfo->Threads[0].ClientId.UniqueThread;
			*hThread	= OpenThread(THREAD_ALL_ACCESS, FALSE, (DWORD)SystemProcInfo->Threads[0].ClientId.UniqueThread);

			if (*hThread == NULL)
				printf("\n\t[!] OpenThread Failed With Error : %d \n", GetLastError());

			break;
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
	HANDLE		hProcess		= NULL,
				hThread			= NULL;
	DWORD		dwProcessId 	= NULL,
				dwThreadId		= NULL;
	
	wprintf(L"[i] Searching For Process Id Of \"%ls\" ... \n", TARGET_PROCESS);
	if (!GetRemoteProcessHandle(TARGET_PROCESS, &dwProcessId, &hProcess)) {
		printf("[!] Process is Not Found \n");
		return -1;
	}
	printf("\t[i] Found Target Process Pid: %d \n", dwProcessId);
	printf("[+] DONE \n\n");

	printf("[i] Searching For A Thread Under The Target Process ... \n");
	if (!GetRemoteThreadhandle(dwProcessId, &dwThreadId, &hThread)) {
		printf("[!] No Thread is Found \n");
		return -1;
	}
	printf("\t[i] Found Target Thread Of Id: %d \n", dwThreadId);
	printf("[+] DONE \n\n");

	CloseHandle(hThread);
	CloseHandle(hProcess);

	printf("[#] Press <Enter> To Quit ... ");
	getchar();

	return 0;
}