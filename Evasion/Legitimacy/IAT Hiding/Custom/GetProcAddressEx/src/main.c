#include <windows.h>
#include <stdio.h>
#include <winternl.h>

typedef LPVOID (WINAPI* fnVirtualAlloc)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);


FARPROC GetProcAddressEx_C(HMODULE hModule, LPCSTR lpApiName) {

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

	// Getting the export table size
	printf("[i] Getting export table size ... ");
    DWORD dwImgExportDirSize = ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
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
			
			// check if the function is a forwarded function.
            if ( ( ( ( ULONG_PTR ) pFunctionAddress ) >= ( ( ULONG_PTR ) pImgExportDir ) ) && 
			     ( ( ( ULONG_PTR ) pFunctionAddress ) <  ( ( ULONG_PTR ) pImgExportDir ) + dwImgExportDirSize ) 
			) {
                CHAR  ForwarderName[ MAX_PATH ] = { 0 };
				DWORD DotOffset	   = 0;
				PCHAR FunctionMod  = NULL;
				PCHAR FunctionName = NULL;

				// save the forwarder string into our ForwarderName buffer 
				memcpy( ForwarderName, pFunctionAddress, strlen( ( PCHAR ) pFunctionAddress ) );
				
				// first find the offset of the dot '.'
				for ( int i = 0; i < strlen( ( PCHAR ) ForwarderName ); i++ ) 
				{
					// check for the '.'
				    if ( ( ( PCHAR ) ForwarderName )[ i ] == '.' )
				    {
						DotOffset = i;			   // save the dot offset/index 
						ForwarderName[ i ] = NULL; // replace the dot with a NULL terminator
				        break; 
				    }
				}

				FunctionMod  = ForwarderName;
				FunctionName = ForwarderName + DotOffset + 1;
				
				return GetProcAddressEx_C( LoadLibraryA( FunctionMod ), FunctionName );
			}
			
			printf("[ %0.4d ] FOUND API -\t NAME: %s -\t ADDRESS: 0x%p  -\t ORDINAL: %d\n", i, pFunctionName, pFunctionAddress, FunctionOrdinalArray[i]);
			return pFunctionAddress;
		}
	}

	printf("[!] Function not found!\n");
	
	return NULL;
}

int main() {
	fnVirtualAlloc	pVirtualAlloc	= NULL;

    pVirtualAlloc = GetProcAddressEx_C( GetModuleHandleA( "Kernel32" ), "VirtualAlloc" );
	if(pVirtualAlloc == NULL) {
		printf("[!] GetProcAddressEx_C Failed With Error : %d\n", GetLastError());
		return -1;
	}

	printf("[#] Press <Enter> To Quit ... ");
	getchar();

	return 0;
}