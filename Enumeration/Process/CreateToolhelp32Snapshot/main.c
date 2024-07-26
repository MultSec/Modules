#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

#define TARGET_PROCESS "notepad.exe"

BOOL GetRemoteProcessHandle(IN LPWSTR szProcessName, OUT DWORD* dwProcessId, OUT HANDLE* hProcess) {
	// According to the documentation:
	// Before calling the Process32First function, set this member to sizeof(PROCESSENTRY32).
	// If dwSize is not initialized, Process32First fails.
	PROCESSENTRY32	Proc = {
		.dwSize = sizeof(PROCESSENTRY32) 
	};

	HANDLE hSnapShot = NULL;

	// Takes a snapshot of the currently running processes 
	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (hSnapShot == INVALID_HANDLE_VALUE){
		printf("[!] CreateToolhelp32Snapshot Failed With Error : %d \n", GetLastError());
		goto _EndOfFunction;
	}

	// Retrieves information about the first process encountered in the snapshot.
	if (!Process32First(hSnapShot, &Proc)) {
		printf("[!] Process32First Failed With Error : %d \n", GetLastError());
		goto _EndOfFunction;
	}

	do {
		// Use the dot operator to extract the process name from the populated struct
		// If the process name matches the process we're looking for
		if (strcmp(Proc.szExeFile, szProcessName) == 0) {
			// Use the dot operator to extract the process ID from the populated struct
			// Save the PID
			*dwProcessId = Proc.th32ProcessID;
			// Open a handle to the process
			*hProcess    = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Proc.th32ProcessID);
			if (*hProcess == NULL)
				printf("[!] OpenProcess Failed With Error : %d \n", GetLastError());

			break; // Exit the loop
		}

	// Retrieves information about the next process recorded the snapshot.
	// While a process still remains in the snapshot, continue looping
	} while (Process32Next(hSnapShot, &Proc));
	
	// Cleanup
	_EndOfFunction:
		if (hSnapShot != NULL)
			CloseHandle(hSnapShot);
		if (*dwProcessId == NULL || *hProcess == NULL)
			return FALSE;
		return TRUE;
}

int main() {
	DWORD		Pid				= NULL;
	HANDLE		hProcess		= NULL;

	if (!GetRemoteProcessHandle(TARGET_PROCESS, &Pid, &hProcess)) {
		printf("[!] Process \"%s\" NOT FOUND\n", TARGET_PROCESS);
		printf("[#] Press <Enter> To Quit ... ");
		getchar();
		return -1;
	}

	printf("[+] FOUND \"%s\" - Of Pid : %d \n", TARGET_PROCESS, Pid);

	printf("[#] Press <Enter> To Quit ... ");
	getchar();

	return 0;
}