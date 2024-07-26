#include <windows.h>
#include <stdio.h>
#include "structs.h"

#ifndef STRUCTS
#include <winternl.h>
#endif // !STRUCTS

// https://learn.microsoft.com/en-us/windows/win32/api/ntdef/nf-ntdef-containing_record
#define CONTAINING_RECORD(address, type, field) \
    ((type *)((PCHAR)(address) - (ULONG_PTR)(&((type *)0)->field)))

BOOL IsStringEqual (IN LPCWSTR Str1, IN LPCWSTR Str2) {

	WCHAR	lStr1	[MAX_PATH],
			lStr2	[MAX_PATH];

	int		len1	= lstrlenW(Str1),
			len2	= lstrlenW(Str2);

	int		i		= 0,
			j		= 0;

	// checking - we dont want to overflow our buffers
	if (len1 >= MAX_PATH || len2 >= MAX_PATH)
		return FALSE;

	// converting Str1 to lower case string (lStr1)
	for (i = 0; i < len1; i++){
		lStr1[i] = (WCHAR)tolower(Str1[i]);
	}
	lStr1[i++] = L'\0'; // null terminating


	// converting Str2 to lower case string (lStr2)
	for (j = 0; j < len2; j++) {
		lStr2[j] = (WCHAR)tolower(Str2[j]);
	}
	lStr2[j++] = L'\0'; // null terminating


	// comparing the lower-case strings
	if (lstrcmpiW(lStr1, lStr2) == 0)
		return TRUE;

	return FALSE;
}

HMODULE GetModuleHandle_C(IN LPCWSTR szModuleName) {
	// getting peb
#ifdef _WIN64 // if compiling as x64
	PPEB					pPeb		= (PEB*)(__readgsqword(0x60));
#elif _WIN32 // if compiling as x32
	PPEB					pPeb		= (PEB*)(__readfsdword(0x30));
#endif

	// geting Ldr
	PPEB_LDR_DATA			pLdr		= (PPEB_LDR_DATA)(pPeb->Ldr);
	// getting the first element in the linked list (contains information about the first module)
	PLDR_DATA_TABLE_ENTRY	pDte		= (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);
	
	while (pDte) {
		
		// if not null
		if (pDte->FullDllName.Length != NULL) {

			// check if both equal
			if (IsStringEqual(pDte->FullDllName.Buffer, szModuleName)) {
				wprintf(L"[+] Found Dll \"%ls\" \n", pDte->FullDllName.Buffer);
#ifdef STRUCTS
				return (HMODULE)(pDte->InInitializationOrderLinks.Flink);
#else
				return (HMODULE)pDte->Reserved2[0];
#endif // STRUCTS

			}

			// wprintf(L"[i] \"%s\" \n", pDte->FullDllName.Buffer);
		}
		else {
			break;
		}
		
		// next element in the linked list
		pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);

	}

	return NULL;
}

int main() {
	HMODULE			hModule				= NULL;

	hModule = GetModuleHandleW(L"NTDLL.DLL");
	if (hModule == NULL){
		printf("[!] GetModuleHandleW Failed With Error : %d \n", GetLastError());
		return -1;
	}
	printf("[i] Original 0x%p \n", hModule);

	hModule = GetModuleHandle_C(L"NTDLL.DLL");
	if (hModule == NULL){
		printf("[!] GetModuleHandle_C Failed With Error : %d \n", GetLastError());
		return -1;
	}
	printf("[i] Replacement 0x%p \n", hModule);

	printf("[#] Press <Enter> To Quit ... ");
	getchar();

	return 0;
}