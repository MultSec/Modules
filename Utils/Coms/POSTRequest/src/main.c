#include <windows.h>
#include <stdio.h>
#include <wininet.h>

// python3 .\server.py
#define SERVER		L"127.0.0.1"
#define PORT        8080
#define ENDPOINT	L"/test"

BOOL PostPayload(const wchar_t* server, int port, const wchar_t* endpoint, const char* payload) {

	BOOL		bSTATE            = TRUE;

	HINTERNET	hInternet         = NULL,
			    hConnect          = NULL,
			    hRequest          = NULL;

    // Open An Internet Session
	hInternet = InternetOpenW(NULL, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, NULL);
	if (hInternet == NULL) {
		printf("[!] InternetOpenW Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; 
		goto _EndOfFunction;
	}

    // Connect to the server
    hConnect = InternetConnectW(hInternet, server, port, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (!hConnect) {
        printf("[!] InternetConnect Failed With Error : %d \n", GetLastError());
        bSTATE = FALSE; 
		goto _EndOfFunction;
    }

    // Open a request handle
    hRequest = HttpOpenRequestW(hConnect, L"POST", endpoint, NULL, NULL, NULL, 0, 0);
    if (!hRequest) {
        printf("[!] HttpOpenRequest Failed With Error : %d \n", GetLastError());
        bSTATE = FALSE; 
		goto _EndOfFunction;
    }

    const char* headers = "Content-Type: application/json\r\n";
    if (!HttpAddRequestHeadersA(hRequest, headers, -1, HTTP_ADDREQ_FLAG_ADD)) {
        printf("[!] HttpAddRequestHeaders Failed With Error : %d \n", GetLastError());
        bSTATE = FALSE; 
		goto _EndOfFunction;
    }

    // Send the request
	if (!HttpSendRequestA(hRequest, NULL, 0, (LPVOID)payload, strlen(payload))) {
        printf("[!] HttpSendRequest Failed With Error : %d \n", GetLastError());
        bSTATE = FALSE; 
		goto _EndOfFunction;
    }

    // Read and print the response
    char buffer[1024];
    DWORD bytesRead;
    while (InternetReadFile(hRequest, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
        printf("\n%.*s", bytesRead, buffer);
    }

_EndOfFunction:
	if (hInternet)
		InternetCloseHandle(hInternet);
	if (hConnect)
		InternetCloseHandle(hConnect);
	if (hRequest)
		InternetCloseHandle(hRequest);
	return bSTATE;
}

int main() {
	const char* payload = "{\"key\": \"payload\"}";

	// Making POST request with payload
	printf("[#] Making POST request to \"%ls:%d\" on the endpoint \"%ls\"... ", SERVER, PORT, ENDPOINT);
	if (!PostPayload(SERVER, PORT, ENDPOINT, payload)) {
		return -1;
	}
    printf("\n[+] Done\n");
	
    printf("[#] Press <Enter> To Quit ... ");
    getchar();

	return 0;
}
