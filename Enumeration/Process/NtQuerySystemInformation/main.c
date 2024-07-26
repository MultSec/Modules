#include <windows.h>
#include <stdio.h>
#include <psapi.h>
#include <winternl.h>

#define TARGET_PROCESS L"notepad.exe"

// https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation
typedef NTSTATUS (NTAPI* fnNtQuerySystemInformation)(
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

int main() {

	DWORD		Pid				= NULL;
	HANDLE		hProcess		= NULL;

	if (!GetRemoteProcessHandle(TARGET_PROCESS, &Pid, &hProcess)) {
		wprintf(L"[!] Process \"%ls\" NOT FOUND\n", TARGET_PROCESS);
		printf("[#] Press <Enter> To Quit ... ");
		getchar();
		return -1;
	}

	wprintf(L"[+] FOUND \"%ls\" - Of Pid : %d \n", TARGET_PROCESS, Pid);

	printf("[#] Press <Enter> To Quit ... ");
	getchar();

	return 0;
}
