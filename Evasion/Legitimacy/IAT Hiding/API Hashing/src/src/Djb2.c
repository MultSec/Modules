// Generate Djb2 hashes from Ascii input string
DWORD HashStringDjb2A(_In_ PCHAR String) {
	ULONG Hash = INITIAL_HASH;
	INT c;

	while (c = *String++)
		Hash = ((Hash << INITIAL_SEED) + Hash) + c;

	return Hash;
}

// Generate Djb2 hashes from wide-character input string
DWORD HashStringDjb2W(_In_ PWCHAR String) {
	ULONG Hash = INITIAL_HASH;
	INT c;

	while (c = *String++)
		Hash = ((Hash << INITIAL_SEED) + Hash) + c;

	return Hash;
}