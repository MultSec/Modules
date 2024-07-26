#include <windows.h>
#include <stdio.h>

#define INITIAL_HASH	3731  // added to randomize the hash
#define INITIAL_SEED	7     

// generate Djb2 hashes from Ascii input string
DWORD HashStringDjb2A(_In_ PCHAR String)
{
	ULONG Hash = INITIAL_HASH;
	INT c;

	while (c = *String++)
		Hash = ((Hash << INITIAL_SEED) + Hash) + c;

	return Hash;
}

// generate Djb2 hashes from wide-character input string
DWORD HashStringDjb2W(_In_ PWCHAR String)
{
	ULONG Hash = INITIAL_HASH;
	INT c;

	while (c = *String++)
		Hash = ((Hash << INITIAL_SEED) + Hash) + c;

	return Hash;
}

int main() {
	PCHAR AsciiString = "Pengrey";
	PWCHAR WideString = L"Pengrey";

	printf("[+] Digest for the Ascii string \"%s\": [%lu]\n", AsciiString, HashStringDjb2A(AsciiString));
	printf("[+] Digest for the wide-character string \"%ls\": [%lu]\n", WideString, HashStringDjb2W(WideString));
	
	printf("[#] Press <Enter> To Quit ...");
	getchar();

	return 0;
}