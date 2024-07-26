#include <windows.h>
#include <stdio.h>

VOID XorByInputKey(IN PBYTE pShellcode, IN SIZE_T sShellcodeSize, IN PBYTE bKey, IN SIZE_T sKeySize) {
	for (size_t i = 0, j = 0; i < sShellcodeSize; i++, j++) {
		if (j >= sKeySize){
			j = 0;
		}
		pShellcode[i] = pShellcode[i] ^ bKey[j];
	}
}

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
			printf("0x%0.2X ", Data[i]);
		}
	}

	printf("};\n\n\n");

}

// msfvenom -p windows/x64/exec CMD=calc.exe -f c
unsigned char EncShellcode[] = {
	{{SHELLCODE}}
};

// Key to be used on decryption
unsigned char key[] = {
	{{KEY}}
};

int main() {
	// Printing the address of the shellcode
	printf("[i] shellcode : 0x%p \n", EncShellcode);
	printf("[#] Press <Enter> To Decrypt ...");
	getchar();

	// Allocating buffer to hold decrypted shellcode
	PBYTE DecryptedShellcode = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(EncShellcode));

	// Copy encrypted shellcode to decrypted shellcode buffer
	if (DecryptedShellcode)
		memcpy(DecryptedShellcode, EncShellcode, sizeof(EncShellcode));

	// Decryption
	XorByInputKey(DecryptedShellcode, sizeof(EncShellcode), key, sizeof(key));

	// Printing the decrypted buffer
	PrintHexData("Shellcode", DecryptedShellcode, sizeof(EncShellcode));

	// Freeing the allocated buffer
	HeapFree(GetProcessHeap(), 0, DecryptedShellcode);

	// Exit
	printf("[#] Press <Enter> To Quit ...");
	getchar();
	return 0;
}
