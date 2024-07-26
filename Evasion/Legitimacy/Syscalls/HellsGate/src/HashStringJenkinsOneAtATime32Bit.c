#include "apihash.h"

// Generate JenkinsOneAtATime32Bit hashes from Ascii input string
DWORD HashStringJenkinsOneAtATime32BitA(_In_ PCHAR String) {
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

	return (DWORD) Hash;
}

// Generate JenkinsOneAtATime32Bit hashes from wide-character input string
DWORD HashStringJenkinsOneAtATime32BitW(_In_ PWCHAR String) {
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

	return (DWORD) Hash;
}