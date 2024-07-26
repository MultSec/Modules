#include "apihash.h"

// Generate LoseLose hashes from ASCII input string
DWORD HashStringLoseLoseA(_In_ PCHAR String) {
	ULONG Hash = 0;
	INT c;

	while (c = *String++) {
		Hash += c;
		Hash *= c + INITIAL_SEED;	// update
	}
	return Hash;
}

// Generate LoseLose hashes from wide-character input string
DWORD HashStringLoseLoseW(_In_ PWCHAR String) {
	ULONG Hash = 0;
	INT c;

	while (c = *String++) {
		Hash += c;
		Hash *= c + INITIAL_SEED;	// update
	}

	return Hash;
}