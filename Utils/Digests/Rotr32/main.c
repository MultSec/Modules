#include <windows.h>
#include <stdio.h>

#define INITIAL_SEED	5	

// Helper function that apply the bitwise rotation
UINT32 HashStringRotr32Sub(UINT32 Value, UINT Count)
{
	DWORD Mask = (CHAR_BIT * sizeof(Value) - 1);
	Count &= Mask;
#pragma warning( push )
#pragma warning( disable : 4146)
	return (Value >> Count) | (Value << ((-Count) & Mask));
#pragma warning( pop ) 
}

// Generate Rotr32 hashes from Ascii input string
INT HashStringRotr32A(_In_ PCHAR String)
{
	INT Value = 0;

	for (INT Index = 0; Index < lstrlenA(String); Index++)
		Value = String[Index] + HashStringRotr32Sub(Value, INITIAL_SEED);

	return Value;
}

// Generate Rotr32 hashes from wide-character input string
INT HashStringRotr32W(_In_ PWCHAR String)
{
	INT Value = 0;

	for (INT Index = 0; Index < lstrlenW(String); Index++)
		Value = String[Index] + HashStringRotr32Sub(Value, INITIAL_SEED);

	return Value;
}

int main() {
	PCHAR AsciiString = "Pengrey";
	PWCHAR WideString = L"Pengrey";

	printf("[+] Digest for the Ascii string \"%s\": [%lu]\n", AsciiString, HashStringRotr32A(AsciiString));
	printf("[+] Digest for the wide-character string \"%ls\": [%lu]\n", WideString, HashStringRotr32W(WideString));
	
	printf("[#] Press <Enter> To Quit ...");
	getchar();

	return 0;
}