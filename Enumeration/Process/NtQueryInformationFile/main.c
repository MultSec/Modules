#include <windows.h>
#include <stdio.h>
#include <psapi.h>
#include "structs.h"

#define TARGET_PROCESS "notepad.exe"

BOOL GetRemoteProcessHandle(IN LPCWSTR szProcName, OUT DWORD* pdwPid, OUT HANDLE* phProcess) {
    UNICODE_STRING                              ntPath;
    OBJECT_ATTRIBUTES                           oaDev;
    IO_STATUS_BLOCK                             ioStatusBlock,
                                                statusBlock             = { 0 };
    NTSTATUS                                    CreateFileSTATUS        = { 0 },
                                                FileInformation         = { 0 };
    HANDLE                                      hFile                   = { 0 },
	                                            hProcess			    = NULL;
    fnRtlInitUnicodeString                      pRtlInitUnicodeString   = NULL;
    fnNtCreateFile                              pNtCreateFile           = NULL;
    fnNtQueryInformationFile                    pNtQueryInformationFile = NULL;
    PFILE_PROCESS_IDS_USING_FILE_INFORMATION    pProcessInfo            = NULL;
	HMODULE		                                hModule				    = NULL;
    DWORD                       				dwReturnLen		        = NULL;
	WCHAR		                                szProc				    [MAX_PATH];

    // Retrieve RtlInitUnicodeString's Address
	pRtlInitUnicodeString = (fnRtlInitUnicodeString)GetProcAddress(GetModuleHandle("NTDLL.DLL"), "RtlInitUnicodeString");
	if (pRtlInitUnicodeString == NULL) {
		printf("[!] GetProcAddress Failed With Error : %d\n", GetLastError());
		goto _EndOfFunction;
	}
    pRtlInitUnicodeString(&ntPath, NTFS_ROOT);

    RtlSecureZeroMemory(&ioStatusBlock, sizeof(ioStatusBlock));

    InitializeObjectAttributes(&oaDev, &ntPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

    pNtCreateFile = (fnNtCreateFile)GetProcAddress(GetModuleHandleA("ntdll"), "NtCreateFile");
    if (pNtCreateFile == NULL) {
        printf("[!] GetProcAddress Failed With Error : %d\n", GetLastError());
        goto _EndOfFunction;
    }

    CreateFileSTATUS =  pNtCreateFile(&hFile, GENERIC_READ, &oaDev, &ioStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, 0, NULL, 0);
    if(!NT_SUCCESS(CreateFileSTATUS)){
        printf("[!] NtCreateFile Failed With Error : %0.8X\n", CreateFileSTATUS);
        goto _EndOfFunction;
    }

    pNtQueryInformationFile = (fnNtQueryInformationFile)GetProcAddress(GetModuleHandleA("ntdll"), "NtQueryInformationFile");
    if (pNtQueryInformationFile == NULL) {
        printf("[!] GetProcAddress Failed With Error : %d\n", GetLastError());
        goto _EndOfFunction;
    }

    pProcessInfo = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, FILE_PROC_BUFFER_SIZE);
    if(pProcessInfo == NULL){
        printf("[!] HeapAlloc Failed With Error : %d\n", GetLastError());
		goto _EndOfFunction;
	}

    RtlSecureZeroMemory(&statusBlock, sizeof(statusBlock));

    printf("[i] Querying for access to the base NTFS object");
    FileInformation = pNtQueryInformationFile(hFile, &statusBlock, pProcessInfo, FILE_PROC_BUFFER_SIZE, FileProcessIdsUsingFileInformation);
    if(!NT_SUCCESS(FileInformation)){
        printf("\n[!] NtQueryInformationFile Failed With Error : %0.8X\n", FileInformation);
		goto _EndOfFunction;
	}
    printf(" [+] Done\n");

    printf("[i] Number Of Processes Detected : %d \n", pProcessInfo->NumberOfProcessIdsInList);

    for (ULONG i = 0; i < pProcessInfo->NumberOfProcessIdsInList; i++) {
        // Opening a process handle 
        if ((hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pProcessInfo->ProcessIdList[i])) != NULL) {
            
            // If handle is valid
            // Get a handle of a module in the process 'hProcess'.
            // The module handle is needed for 'GetModuleBaseName'
            if (!EnumProcessModules(hProcess, &hModule, sizeof(HMODULE), &dwReturnLen)) {
                printf("[!] EnumProcessModules Failed [ At Pid: %d ] With Error : %d \n", pProcessInfo->ProcessIdList[i], GetLastError());
            }
            else {
                // if EnumProcessModules succeeded
                // get the name of 'hProcess', and saving it in the 'szProc' variable 
                if (!GetModuleBaseName(hProcess, hModule, szProc, sizeof(szProc) / sizeof(WCHAR))) {
                    printf("[!] GetModuleBaseName Failed [ At Pid: %d ] With Error : %d \n", pProcessInfo->ProcessIdList[i], GetLastError());
                }
                else {
                    // Perform the comparison logic
                    if (strcmp(szProcName, szProc) == 0) {
                        // return by reference
                        *pdwPid		= pProcessInfo->ProcessIdList[i];
                        *phProcess	= hProcess;
                        break;	
                    }
                }
            }

            CloseHandle(hProcess);
        }
    }

    HeapFree(GetProcessHeap(), (DWORD)pProcessInfo, 0);

    // Cleanup
    _EndOfFunction:
    if (hFile != NULL)
        CloseHandle(hFile);
    if (hProcess != NULL)
        CloseHandle(hProcess);
    if (hModule != NULL)
        CloseHandle(hModule);
    
    if(*pdwPid == NULL || *phProcess == NULL)
		return FALSE;
	else
		return TRUE;
}

int main() {
	DWORD		Pid				= NULL;
	HANDLE		hProcess		= NULL;

	if (!GetRemoteProcessHandle(TARGET_PROCESS, &Pid, &hProcess)) {
		printf("[!] Process \"%s\" NOT FOUND\n", TARGET_PROCESS);
		printf("[#] Press <Enter> To Quit ... ");
		getchar();
		return -1;
	}

	printf("[+] FOUND \"%s\" - Of Pid : %d \n", TARGET_PROCESS, Pid);

	printf("[#] Press <Enter> To Quit ... ");
	getchar();

	return 0;
}