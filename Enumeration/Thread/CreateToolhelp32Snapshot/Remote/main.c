#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

#define TARGET_PROCESS "notepad.exe"

BOOL GetRemoteProcessHandle(IN LPWSTR szProcessName, OUT DWORD* dwProcessId, OUT HANDLE* hProcess) {

	HANDLE			hSnapShot = NULL;
	PROCESSENTRY32	Proc = {
					.dwSize = sizeof(PROCESSENTRY32)
	};

	// Takes a snapshot of the currently running processes 
	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (hSnapShot == INVALID_HANDLE_VALUE) {
		printf("\t[!] CreateToolhelp32Snapshot Failed With Error : %d \n", GetLastError());
		goto _EndOfFunction;
	}

	// Retrieves information about the first process encountered in the snapshot.
	if (!Process32First(hSnapShot, &Proc)) {
		printf("\n\t[!] Process32First Failed With Error : %d \n", GetLastError());
		goto _EndOfFunction;
	}

	do {
		// compare the enumerated process path with what is passed, if equal ..
		if (strcmp(Proc.szExeFile, szProcessName) == 0) {
			// we save the process id 
			*dwProcessId = Proc.th32ProcessID;
			// we open a process handle and return
			*hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Proc.th32ProcessID);
			if (*hProcess == NULL)
				printf("\n\t[!] OpenProcess Failed With Error : %d \n", GetLastError());

			break;
		}

		// Retrieves information about the next process recorded the snapshot.
	} while (Process32Next(hSnapShot, &Proc));
	// while we can still have a valid output ftom Process32Net, continue looping


_EndOfFunction:
	if (hSnapShot != NULL)
		CloseHandle(hSnapShot);
	if (*dwProcessId == NULL || *hProcess == NULL)
		return FALSE;
	return TRUE;
}


//	get the thread handle of a remote process of pid : `dwProcessId`
BOOL GetRemoteThreadhandle(IN DWORD dwProcessId, OUT DWORD* dwThreadId, OUT HANDLE* hThread) {
	
	HANDLE			hSnapShot = NULL;
	THREADENTRY32	Thr = {
					.dwSize = sizeof(THREADENTRY32)
	};

	// Takes a snapshot of the currently running processes's threads 
	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, NULL);
	if (hSnapShot == INVALID_HANDLE_VALUE) {
		printf("\n\t[!] CreateToolhelp32Snapshot Failed With Error : %d \n", GetLastError());
		goto _EndOfFunction;
	}

	// Retrieves information about the first thread encountered in the snapshot.
	if (!Thread32First(hSnapShot, &Thr)) {
		printf("\n\t[!] Thread32First Failed With Error : %d \n", GetLastError());
		goto _EndOfFunction;
	}

	do {
		// If the thread's PID is equal to the PID of the target process then
		// this thread is running under the target process
		if (Thr.th32OwnerProcessID == dwProcessId){
			
			*dwThreadId = Thr.th32ThreadID;
			*hThread	= OpenThread(THREAD_ALL_ACCESS, FALSE, Thr.th32ThreadID);
			
			if (*hThread == NULL)
				printf("\n\t[!] OpenThread Failed With Error : %d \n", GetLastError());

			break;
		}

		// While there are threads remaining in the snapshot
	} while (Thread32Next(hSnapShot, &Thr));


_EndOfFunction:
	if (hSnapShot != NULL)
		CloseHandle(hSnapShot);
	if (*dwThreadId == NULL || *hThread == NULL)
		return FALSE;
	return TRUE;
}

int main() {
	HANDLE		hProcess	= NULL,
				hThread		= NULL;
	
	DWORD		dwProcessId = NULL,
				dwThreadId	= NULL;
	
	wprintf(L"[i] Searching For Process Id Of \"%s\" ... \n", TARGET_PROCESS);
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