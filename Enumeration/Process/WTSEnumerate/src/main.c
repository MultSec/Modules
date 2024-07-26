#include <windows.h>
#include <stdio.h>
#include <psapi.h>
#include <wtsapi32.h>

#define TARGET_PROCESS "Notepad.exe"

BOOL GetRemoteProcessHandle(IN LPCWSTR szProcName, OUT DWORD* pdwPid, OUT HANDLE* phProcess) {
	HANDLE		            hProcess	= NULL;
	HMODULE		            hModule		= NULL;
    DWORD                   level       = 1,
                            dwNmbrOfPids;
    WTS_PROCESS_INFOA*      info;
	
	// Query processes information
	if (!WTSEnumerateProcesses(WTS_CURRENT_SERVER_HANDLE, NULL, 1, (LPWSTR*)&info, &dwNmbrOfPids)) {
        printf("[!] WTSEnumerateProcessesEx Failed With Error : %d \n", GetLastError());
        return 1;
    }

	printf("[i] Number Of Processes Detected : %d \n", dwNmbrOfPids);

	for (DWORD i = 0; i < dwNmbrOfPids; i++){
        // Compare process name to target
        if (strcmp(szProcName, info[i].pProcessName) == 0) {
            // Open handle for process
            if ((hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, info[i].ProcessId)) != NULL) {
                // return by reference
                *pdwPid		= info[i].ProcessId;
                *phProcess	= hProcess;
                break;	
            }
        }
	}

    // Cleanup
    WTSFreeMemory(info);

	// Check if pdwPid or phProcess are NULL
	if (*pdwPid == NULL || *phProcess == NULL)
		return FALSE;
	else
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
