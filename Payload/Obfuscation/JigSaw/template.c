#include <windows.h>
#include <stdio.h>

#define SHELLCODE_SIZE	{{SHELLCODE_SIZE}}

// Printing the input buffer as a hex char array
VOID PrintHexData(LPCSTR Name, PBYTE Data, SIZE_T Size) {

	printf("unsigned char %s[] = {", Name);

	for (int i = 0; i < Size; i++) {
		if (i % 16 == 0) {
			printf("\n\t");
		}
		if (i < Size - 1) {
			printf("0x%0.2X, ", Data[i]);
		}
		else {
			printf("0x%0.2X\n", Data[i]);
		}
	}

	printf("};\n\n\n");

}

// Deobfuscate the shellcode
VOID DeobfuscateShellcode(PBYTE ObfuscatedShellcode, int Positions[], PBYTE DeobfuscatedShellcode) {
	int position;

    // Iterate over the Obfuscated shellcode
    for (int i = 0; i < SHELLCODE_SIZE; i++) {
		// Get original position
		position = Positions[i];
		
		// Assign value
        DeobfuscatedShellcode[position] = ObfuscatedShellcode[i];
    }
}

// Positions used
int Positions[] = {
	{{POSITIONS}}
};

// msfvenom -p windows/x64/exec CMD=calc.exe -f c
unsigned char ObsShellcode[] = {
	{{SHELLCODE}}
};

int main() {
	// Printing the address of the shellcode
	printf("[i] shellcode : 0x%p \n", ObsShellcode);
	printf("[#] Press <Enter> To Decrypt ...");
	getchar();

	// Allocating buffer to hold decrypted shellcode
	PBYTE DeobsShellcode = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, SHELLCODE_SIZE);

	// Copy encrypted shellcode to decrypted shellcode buffer
	if (DeobsShellcode)
		// Deobfuscate the shellcode
        DeobfuscateShellcode(ObsShellcode, Positions, DeobsShellcode);

	// Printing the decrypted buffer
	PrintHexData("Shellcode", DeobsShellcode, SHELLCODE_SIZE);

	// Freeing the allocated buffer
	HeapFree(GetProcessHeap(), 0, DeobsShellcode);

	// Exit
	printf("[#] Press <Enter> To Quit ...");
	getchar();
	return 0;
}
