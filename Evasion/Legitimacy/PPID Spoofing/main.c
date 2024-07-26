#include <windows.h>
#include <stdio.h>
#include <psapi.h>

#define TARGET_PROCESS		"RuntimeBroker.exe -Embedding"
#define TARGET_PARENT       "notepad.exe"

BOOL GetRemoteProcessHandle(IN LPCWSTR szProcName, OUT DWORD* pdwPid, OUT HANDLE* phProcess) {

	DWORD		adwProcesses		[1024 * 2],
				dwReturnLen1		= NULL,
				dwReturnLen2		= NULL,
				dwNmbrOfPids		= NULL;

	HANDLE		hProcess			= NULL;
	HMODULE		hModule				= NULL;

	WCHAR		szProc				[MAX_PATH];
	
	// Get the array of pid's in the system
	if (!EnumProcesses(adwProcesses, sizeof(adwProcesses), &dwReturnLen1)) {
		printf("[!] EnumProcesses Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	
	// Calculating the number of elements in the array returned 
	dwNmbrOfPids = dwReturnLen1 / sizeof(DWORD);

	printf("[i] Number Of Processes Detected : %d \n", dwNmbrOfPids);

	for (int i = 0; i < dwNmbrOfPids; i++){

		// If process is NULL
		if (adwProcesses[i] != NULL) {
			
			// Opening a process handle 
			if ((hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, adwProcesses[i])) != NULL) {
				
				// If handle is valid
				// Get a handle of a module in the process 'hProcess'.
				// The module handle is needed for 'GetModuleBaseName'
				if (!EnumProcessModules(hProcess, &hModule, sizeof(HMODULE), &dwReturnLen2)) {
					printf("[!] EnumProcessModules Failed [ At Pid: %d ] With Error : %d \n", adwProcesses[i], GetLastError());
				}
				else {
					// if EnumProcessModules succeeded
					// get the name of 'hProcess', and saving it in the 'szProc' variable 
					if (!GetModuleBaseName(hProcess, hModule, szProc, sizeof(szProc) / sizeof(WCHAR))) {
						printf("[!] GetModuleBaseName Failed [ At Pid: %d ] With Error : %d \n", adwProcesses[i], GetLastError());
					}
					else {
						// Perform the comparison logic
						if (strcmp(szProcName, szProc) == 0) {
							// return by reference
							*pdwPid		= adwProcesses[i];
							*phProcess	= hProcess;
							break;	
						}
					}
				}

				CloseHandle(hProcess);
			}
		}
	}

	// Check if pdwPid or phProcess are NULL
	if (*pdwPid == NULL || *phProcess == NULL)
		return FALSE;
	else
		return TRUE;
}

BOOL CreatePPidSpoofedProcess(IN HANDLE hParentProcess, IN LPCSTR lpProcessName, OUT DWORD* dwProcessId, OUT HANDLE* hProcess, OUT HANDLE* hThread) {

	CHAR					lpPath		[MAX_PATH * 2];
	CHAR					CurrentDir	[MAX_PATH];
	CHAR					WnDr		[MAX_PATH];

	SIZE_T							sThreadAttList	= NULL;
	PPROC_THREAD_ATTRIBUTE_LIST		pThreadAttList	= NULL;

	STARTUPINFOEXA			SiEx	= { 0 };
	PROCESS_INFORMATION		Pi		= { 0 };

	// cleaning the structs (setting elements values to 0)
	RtlSecureZeroMemory(&SiEx, sizeof(STARTUPINFOEXA));
	RtlSecureZeroMemory(&Pi, sizeof(PROCESS_INFORMATION));

	// setting the size of the structure
	SiEx.StartupInfo.cb = sizeof(STARTUPINFOEXA);

	// getting the %windir% system variable path (this is 'C:\Windows')
	if (!GetEnvironmentVariableA("WINDIR", WnDr, MAX_PATH)) {
		printf("[!] GetEnvironmentVariableA Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// making the target process path
	sprintf(lpPath, "%s\\System32\\%s", WnDr, lpProcessName);

	// making the `lpCurrentDirectory` parameter in CreateProcessA
	sprintf(CurrentDir, "%s\\System32\\", WnDr);

	// this will fail with ERROR_INSUFFICIENT_BUFFER / 122
	InitializeProcThreadAttributeList(NULL, 1, NULL, &sThreadAttList);

	// allocating enough memory
	pThreadAttList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sThreadAttList);
	if (pThreadAttList == NULL){
		printf("[!] HeapAlloc Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// calling InitializeProcThreadAttributeList again passing the right parameters
	if (!InitializeProcThreadAttributeList(pThreadAttList, 1, NULL, &sThreadAttList)) {
		printf("[!] InitializeProcThreadAttributeList Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	if (!UpdateProcThreadAttribute(pThreadAttList, NULL, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParentProcess, sizeof(HANDLE), NULL, NULL)) {
		printf("[!] UpdateProcThreadAttribute Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// setting the `LPPROC_THREAD_ATTRIBUTE_LIST` element in `SiEx` to be equal to what was
	// created using `UpdateProcThreadAttribute` - that is the parent process
	SiEx.lpAttributeList = pThreadAttList;

	printf("[i] Running : \"%s\" ... ", lpPath);

	if (!CreateProcessA(
		NULL,
		lpPath,
		NULL,
		NULL,
		FALSE,
		EXTENDED_STARTUPINFO_PRESENT,
		NULL,
		CurrentDir,
		&SiEx.StartupInfo,
		&Pi)) {
		printf("[!] CreateProcessA Failed with Error : %d \n", GetLastError());
		return FALSE;
	}

	printf("[+] DONE \n");


	// filling up the OUTPUT parameter with 'CreateProcessA's output'
	*dwProcessId	= Pi.dwProcessId;
	*hProcess		= Pi.hProcess;
	*hThread		= Pi.hThread;


	// cleaning up
	DeleteProcThreadAttributeList(pThreadAttList);
	CloseHandle(hParentProcess);

	// doing a small check to verify we got everything we need
	if (*dwProcessId != NULL && *hProcess != NULL && *hThread != NULL)
		return TRUE;

	return FALSE;
}

int main(int argc, char* argv[]) {
	DWORD		dwPPid			= NULL,
				dwProcessId		= NULL;

	HANDLE		hPProcess		= NULL,
				hProcess		= NULL,
				hThread			= NULL;

    // get parent PID
    if (!GetRemoteProcessHandle(TARGET_PARENT, &dwPPid, &hPProcess)) {
		printf("[!] Process \"%s\" NOT FOUND\n", TARGET_PARENT);
		printf("[#] Press <Enter> To Quit ... ");
		getchar();
		return -1;
	}

	printf("[i] Spawning Target Process \"%s\" With Parent : %d \n", TARGET_PROCESS, dwPPid);
	if (!CreatePPidSpoofedProcess(hPProcess, TARGET_PROCESS, &dwProcessId, &hProcess, &hThread)) {
		return -1;
	}
	printf("[i] Target Process Created With Pid : %d \n", dwProcessId);

	printf("[#] Press <Enter> To Quit ... ");
	getchar();
	CloseHandle(hProcess);
	CloseHandle(hThread);
	
	return 0;
}