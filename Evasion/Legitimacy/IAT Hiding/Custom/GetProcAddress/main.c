#include <windows.h>
#include <stdio.h>
#include <winternl.h>

typedef LPVOID (WINAPI* fnMessageBoxA)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);

FARPROC GetProcAddress_C(HMODULE hModule, LPCSTR lpApiName) {

	// We do this to avoid casting at each time we use 'hModule'
	PBYTE pBase = (PBYTE)hModule;
	
	// Getting the dos header and doing a signature check
	printf("[i] Getting dos header ... ");
	PIMAGE_DOS_HEADER	pImgDosHdr		= (PIMAGE_DOS_HEADER)pBase;
	if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE) {
		printf("[!] DOS Header signature check failed!\n");
		return NULL;
	}
	printf("[+] DONE\n");

	// Getting the nt headers and doing a signature check
	printf("[i] Getting nt header ... ");
	PIMAGE_NT_HEADERS	pImgNtHdrs		= (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE) {
		printf("[!] NT Headers signature check failed!\n");
		return NULL;
	}
	printf("[+] DONE\n");

	// Getting the optional header
	printf("[i] Getting optional header ... ");
	IMAGE_OPTIONAL_HEADER	ImgOptHdr	= pImgNtHdrs->OptionalHeader;
	printf("[+] DONE\n");

	// Getting the image export table
	printf("[i] Getting image export table ... ");
	PIMAGE_EXPORT_DIRECTORY pImgExportDir = (PIMAGE_EXPORT_DIRECTORY) (pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	printf("[+] DONE\n");

	// Getting the function's names array pointer
	printf("[i] Getting the function's names array pointer ... ");
	PDWORD FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);
	printf("[+] DONE\n");
	
	// Getting the function's addresses array pointer
	printf("[i] Getting the function's addresses array pointer ... ");
	PDWORD FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);
	printf("[+] DONE\n");
	
	// Getting the function's ordinal array pointer
	printf("[i] Getting the function's ordinal array pointer ... ");
	PWORD  FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);
	printf("[+] DONE\n");

	// Looping through all the exported functions
	printf("[#] Getting function ...\n");
	for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++){
		
		// Getting the name of the function
		CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);
		
		// Getting the address of the function through its ordinal
		PVOID pFunctionAddress	= (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);
		
		// Searching for the function specified
		if (strcmp(lpApiName, pFunctionName) == 0){
			printf("[ %0.4d ] FOUND API -\t NAME: %s -\t ADDRESS: 0x%p  -\t ORDINAL: %d\n", i, pFunctionName, pFunctionAddress, FunctionOrdinalArray[i]);
			return pFunctionAddress;
		}
	}

	printf("[!] Function not found!\n");
	
	return NULL;
}

int main() {
	HMODULE			hModule				= NULL;
	fnMessageBoxA 	pMessageBoxA		= NULL;

	hModule = LoadLibraryA("User32.dll");
	if (hModule == NULL){
		printf("[!] LoadLibraryA Failed With Error : %d \n", GetLastError());
		return -1;
	}

	pMessageBoxA = GetProcAddress_C(hModule, "MessageBoxA");
	if(pMessageBoxA == NULL) {
		printf("[!] GetProcAddress_C Failed With Error : %d\n", GetLastError());
		return -1;
	}

	printf("[#] Press <Enter> To Run ... ");
	getchar();

	pMessageBoxA(NULL, "World!", "Hello", MB_ICONINFORMATION);

	printf("[#] Press <Enter> To Quit ... ");
	getchar();

	return 0;
}