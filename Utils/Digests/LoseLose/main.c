#include <windows.h>
#include <stdio.h>

#define INITIAL_SEED	2

// Generate LoseLose hashes from ASCII input string
DWORD HashStringLoseLoseA(_In_ PCHAR String)
{
	ULONG Hash = 0;
	INT c;

	while (c = *String++) {
		Hash += c;
		Hash *= c + INITIAL_SEED;	// update
	}
	return Hash;
}

// Generate LoseLose hashes from wide-character input string
DWORD HashStringLoseLoseW(_In_ PWCHAR String)
{
	ULONG Hash = 0;
	INT c;

	while (c = *String++) {
		Hash += c;
		Hash *= c + INITIAL_SEED;	// update
	}

	return Hash;
}

int main() {
	PCHAR AsciiString = "Pengrey";
	PWCHAR WideString = L"Pengrey";

	printf("[+] Digest for the Ascii string \"%s\": [%lu]\n", AsciiString, HashStringLoseLoseA(AsciiString));
	printf("[+] Digest for the wide-character string \"%ls\": [%lu]\n", WideString, HashStringLoseLoseW(WideString));
	
	printf("[#] Press <Enter> To Quit ...");
	getchar();

	return 0;
}