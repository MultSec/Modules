#include <windows.h>
#include <stdio.h>
#include "sha256.h"

int main() {
	BYTE sha256[SHA256_BLOCK_SIZE];
	PCHAR AsciiString = "Pengrey";
	PWCHAR WideString = L"Pengrey";

	sha256_hash((char*)AsciiString, sizeof(AsciiString), sha256);
	printf("[+] Digest for the Ascii string \"%s\": [%lu]\n", AsciiString, sha256);

	sha256_hash((char*)WideString, sizeof(WideString), sha256);
	printf("[+] Digest for the wide-character string \"%ls\": [%lu]\n", WideString, sha256);
	
	printf("[#] Press <Enter> To Quit ...");
	getchar();

	return 0;
}