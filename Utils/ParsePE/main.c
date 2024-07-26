#include <windows.h>
#include <stdio.h>
#include <winternl.h>

// read the `lpFileName` file from disk 
// and return the base address and the size of it
BOOL ReadPeFile(LPCSTR lpFileName, PBYTE* pPe, SIZE_T* sPe) {

	HANDLE	hFile					= INVALID_HANDLE_VALUE;
	PBYTE	pBuff					= NULL;
	DWORD	dwFileSize				= NULL,
			dwNumberOfBytesRead		= NULL;

	printf("[i] Reading \"%s\" ... ", lpFileName);

	hFile = CreateFileA(lpFileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("[!] CreateFileA Failed With Error : %d \n", GetLastError());
		goto _EndOfFunction;
	}

	dwFileSize = GetFileSize(hFile, NULL);
	if (dwFileSize == NULL) {
		printf("[!] GetFileSize Failed With Error : %d \n", GetLastError());
		goto _EndOfFunction;
	}

	pBuff = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwFileSize);
	if (pBuff == NULL) {
		printf("[!] HeapAlloc Failed With Error : %d \n", GetLastError());
		goto _EndOfFunction;
	}

	if (!ReadFile(hFile, pBuff, dwFileSize, &dwNumberOfBytesRead, NULL) || dwFileSize != dwNumberOfBytesRead) {
		printf("[!] ReadFile Failed With Error : %d \n", GetLastError());
		printf("[!] Bytes Read : %d of : %d \n", dwNumberOfBytesRead, dwFileSize);
		goto _EndOfFunction;
	}

	printf("[+] DONE \n");


_EndOfFunction:
	*pPe = (PBYTE)pBuff;
	*sPe = (SIZE_T)dwFileSize;
	if (hFile)
		CloseHandle(hFile);
	if (*pPe == NULL || *sPe == NULL)
		return FALSE;
	return TRUE;
}

// function to print details of a pe file
// `pPE` is the base address of a pe file in memory
VOID ParsePe (PBYTE pPE) {

    // Get DOS Header
	PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)pPE;
	if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE){
		return;
	}

	// 
	PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)(pPE + pImgDosHdr->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE) {
		return;
	}

	printf("\n\t#####################[ FILE HEADER ]#####################\n\n");
	
	IMAGE_FILE_HEADER		ImgFileHdr	= pImgNtHdrs->FileHeader;


	if (ImgFileHdr.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) {

		printf("[i] Executable File Detected As : ");

		if (ImgFileHdr.Characteristics & IMAGE_FILE_DLL)
			printf("DLL\n");
		else if (ImgFileHdr.Characteristics & IMAGE_SUBSYSTEM_NATIVE)
			printf("SYS\n");
		else
			printf("EXE\n");
	}

	printf("[i] File Arch : %s \n", ImgFileHdr.Machine == IMAGE_FILE_MACHINE_I386 ? "x32" : "x64");
	printf("[i] Number Of Sections : %d \n", ImgFileHdr.NumberOfSections);
	printf("[i] Size Of The Optional Header : %d Byte \n", ImgFileHdr.SizeOfOptionalHeader);


	// 
	printf("\n\t#####################[ OPTIONAL HEADER ]#####################\n\n");

	IMAGE_OPTIONAL_HEADER	ImgOptHdr = pImgNtHdrs->OptionalHeader;
	if (ImgOptHdr.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC) {
		return;
	}

	printf("[i] File Arch (Second way) : %s \n", ImgOptHdr.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC ? "x32" : "x64");


	printf("[+] Size Of Code Section : %d \n", ImgOptHdr.SizeOfCode);
	printf("[+] Address Of Code Section : 0x%p \n\t\t[RVA : 0x%0.8X]\n", (PVOID)(pPE + ImgOptHdr.BaseOfCode), ImgOptHdr.BaseOfCode);
	printf("[+] Size Of Initialized Data : %d \n", ImgOptHdr.SizeOfInitializedData);
	printf("[+] Size Of Unitialized Data : %d \n", ImgOptHdr.SizeOfUninitializedData);
	printf("[+] Preferable Mapping Address : 0x%p \n", (PVOID)ImgOptHdr.ImageBase);
	printf("[+] Required Version : %d.%d \n", ImgOptHdr.MajorOperatingSystemVersion, ImgOptHdr.MinorOperatingSystemVersion);
	printf("[+] Address Of The Entry Point : 0x%p \n\t\t[RVA : 0x%0.8X]\n", (PVOID)(pPE + ImgOptHdr.AddressOfEntryPoint), ImgOptHdr.AddressOfEntryPoint);
	printf("[+] Size Of The Image : %d \n", ImgOptHdr.SizeOfImage);
	printf("[+] File CheckSum : 0x%0.8X \n", ImgOptHdr.CheckSum);
	printf("[+] Number of entries in the DataDirectory array : %d \n", ImgOptHdr.NumberOfRvaAndSizes); // this is the same as `IMAGE_NUMBEROF_DIRECTORY_ENTRIES` - `16`

	
	//
	printf("\n\t#####################[ DIRECTORIES ]#####################\n\n");

	printf("[*] Export Directory At 0x%p Of Size : %d \n\t\t[RVA : 0x%0.8X]\n", 
		(PVOID)(pPE + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress),
		ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size,
		ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	printf("[*] Import Directory At 0x%p Of Size : %d \n\t\t[RVA : 0x%0.8X]\n",
		(PVOID)(pPE + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress),
		ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size,
		ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	printf("[*] Resource Directory At 0x%p Of Size : %d \n\t\t[RVA : 0x%0.8X]\n",
		(PVOID)(pPE + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress),
		ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size,
		ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress);

	printf("[*] Exception Directory At 0x%p Of Size : %d \n\t\t[RVA : 0x%0.8X]\n",
		(PVOID)(pPE + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress),
		ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size,
		ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress);

	printf("[*] Base Relocation Table At 0x%p Of Size : %d \n\t\t[RVA : 0x%0.8X]\n",
		(PVOID)(pPE + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress),
		ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size,
		ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

	printf("[*] TLS Directory At 0x%p Of Size : %d \n\t\t[RVA : 0x%0.8X]\n",
		(PVOID)(pPE + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress),
		ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size,
		ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);

	printf("[*] Import Address Table At 0x%p Of Size : %d \n\t\t[RVA : 0x%0.8X]\n",
		(PVOID)(pPE + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress),
		ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size,
		ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress);



	//
	printf("\n\t#####################[ SECTIONS ]#####################\n\n");


	PIMAGE_SECTION_HEADER pImgSectionHdr = (PIMAGE_SECTION_HEADER)(((PBYTE)pImgNtHdrs) + sizeof(IMAGE_NT_HEADERS));
	for (size_t i = 0; i < pImgNtHdrs->FileHeader.NumberOfSections; i++) {
		printf("[#] %s \n", (CHAR*)pImgSectionHdr->Name);
		printf("\tSize : %d \n", pImgSectionHdr->SizeOfRawData);
		printf("\tRVA : 0x%0.8X \n", pImgSectionHdr->VirtualAddress);
		printf("\tAddress : 0x%p \n", (PVOID)(pPE + pImgSectionHdr->VirtualAddress));
		printf("\tRelocations : %d \n", pImgSectionHdr->NumberOfRelocations);
		printf("\tPermissions : ");
		if (pImgSectionHdr->Characteristics & IMAGE_SCN_MEM_READ)
			printf("PAGE_READONLY | ");
		if (pImgSectionHdr->Characteristics & IMAGE_SCN_MEM_WRITE && pImgSectionHdr->Characteristics & IMAGE_SCN_MEM_READ)
			printf("PAGE_READWRITE | ");
		if (pImgSectionHdr->Characteristics & IMAGE_SCN_MEM_EXECUTE)
			printf("PAGE_EXECUTE | ");
		if (pImgSectionHdr->Characteristics & IMAGE_SCN_MEM_EXECUTE && pImgSectionHdr->Characteristics & IMAGE_SCN_MEM_READ)
			printf("PAGE_EXECUTE_READWRITE");
		printf("\n\n");

		pImgSectionHdr = (PIMAGE_SECTION_HEADER)((PBYTE)pImgSectionHdr + (DWORD)sizeof(IMAGE_SECTION_HEADER));
	}
}

int main(int argc, char* argv[]) {

	if (argc < 2){
		printf("[!] Please Enter Pe File To Parse ... \n");
		return -1;
	}

	PBYTE	pPE		= NULL;
	SIZE_T	sPE		= NULL;

	if (!ReadPeFile(argv[1], &pPE, &sPE)) {
		return -1;
	}

	printf("[+] \"%s\" Read At : 0x%p Of Size : %d \n", argv[1], pPE, sPE);

	ParsePe(pPE);

	
	printf("[#] Press <Enter> To Quit ... ");
	getchar();

	HeapFree(GetProcessHeap(), NULL, pPE);

	return 0;
}