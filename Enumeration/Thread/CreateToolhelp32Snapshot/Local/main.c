#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

BOOL GetLocalThreadHandle(IN DWORD dwMainThreadId, OUT DWORD* dwThreadId, OUT HANDLE* hThread) {
	// Getting the local process ID
	DWORD				dwProcessId		= GetCurrentProcessId();
	HANDLE				hSnapShot		= NULL;
	THREADENTRY32		Thr				= {
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
		// The 'Thr.th32ThreadID != dwMainThreadId' is to avoid targeting the main thread of our local process
		if (Thr.th32OwnerProcessID == dwProcessId && Thr.th32ThreadID != dwMainThreadId) {

			// Opening a handle to the thread 
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