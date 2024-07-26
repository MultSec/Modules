#include <windows.h>
#include <stdio.h>

#define SHELLCODE_SIZE	{{SHELLCODE_SIZE}}
#define NUM_MACS	  	{{NUM_MACS}}

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
VOID DeobfuscateShellcode(unsigned char *ObsShellcode[], PBYTE DeobsShellcode) {
    // Filler variable to track progress
    int filler = 0;
    // For each MAC
    for (int i = 0; i < NUM_MACS; i++) {
        // For each byte in the MAC
        for (int j = 0; j < strlen(ObsShellcode[i]); j++) {
            if (ObsShellcode[i][j] == '-') {
                continue;
            }
            else {
                // If we have filled the buffer, break
                if (filler >= SHELLCODE_SIZE) {
                    break;
                }
                // Convert the hex string to a byte
                char hex[3] = { ObsShellcode[i][j], ObsShellcode[i][j + 1], '\0' };
                DeobsShellcode[filler] = (BYTE)strtol(hex, NULL, 16);
                filler++;
                j++;
            }
        }
    }
}

// msfvenom -p windows/x64/exec CMD=calc.exe -f c
unsigned char *ObsShellcode[] = {
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
        DeobfuscateShellcode(ObsShellcode, DeobsShellcode);

	// Printing the decrypted buffer
	PrintHexData("Shellcode", DeobsShellcode, SHELLCODE_SIZE);

	// Freeing the allocated buffer
	HeapFree(GetProcessHeap(), 0, DeobsShellcode);

	// Exit
	printf("[#] Press <Enter> To Quit ...");
	getchar();
	return 0;
}
