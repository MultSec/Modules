#include <windows.h>
#include <stdio.h>

#define INITIAL_SEED	7	

// Generate JenkinsOneAtATime32Bit hashes from Ascii input string
UINT32 HashStringJenkinsOneAtATime32BitA(_In_ PCHAR String)
{
	SIZE_T Index = 0;
	UINT32 Hash = 0;
	SIZE_T Length = lstrlenA(String);

	while (Index != Length)
	{
		Hash += String[Index++];
		Hash += Hash << INITIAL_SEED;
		Hash ^= Hash >> 6;
	}

	Hash += Hash << 3;
	Hash ^= Hash >> 11;
	Hash += Hash << 15;

	return Hash;
}

// Generate JenkinsOneAtATime32Bit hashes from wide-character input string
UINT32 HashStringJenkinsOneAtATime32BitW(_In_ PWCHAR String)
{
	SIZE_T Index = 0;
	UINT32 Hash = 0;
	SIZE_T Length = lstrlenW(String);

	while (Index != Length)
	{
		Hash += String[Index++];
		Hash += Hash << INITIAL_SEED;
		Hash ^= Hash >> 6;
	}

	Hash += Hash << 3;
	Hash ^= Hash >> 11;
	Hash += Hash << 15;

	return Hash;
}

int main() {
	PCHAR AsciiString = "Pengrey";
	PWCHAR WideString = L"Pengrey";

	printf("[+] Digest for the Ascii string \"%s\": [%lu]\n", AsciiString, HashStringJenkinsOneAtATime32BitA(AsciiString));
	printf("[+] Digest for the wide-character string \"%ls\": [%lu]\n", WideString, HashStringJenkinsOneAtATime32BitW(WideString));
	
	printf("[#] Press <Enter> To Quit ...");
	getchar();

	return 0;
}