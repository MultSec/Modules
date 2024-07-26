#include <windows.h>
#include <stdio.h>
#include "ctaes.h"

// Print the input buffer as a hex char array
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

	printf("\n};\n\n\n");

}

// Key
unsigned char pKey[] = {
	{{KEY}}
};

// IV
unsigned char pIv[] = {
	{{IV}}
};

// msfvenom -p windows/x64/exec CMD=calc.exe -f c
unsigned char pEncShellcode[] = {
	{{SHELLCODE}}
};

int main() {
	// Struct needed for Tiny-AES library
	AES256_CBC_ctx	ctx  			= {0};
	SIZE_T      	sPayloadSize	= sizeof(pEncShellcode);
	
	// Printing the address of the shellcode
	printf("[i] shellcode : 0x%p \n", pEncShellcode);
	printf("[#] Press <Enter> To Decrypt ...");
	getchar();

	// Allocating buffer to hold decrypted shellcode
	PBYTE DecryptedShellcode = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sPayloadSize);

	// Copy encrypted shellcode to decrypted shellcode buffer
	if (DecryptedShellcode)
		memcpy(DecryptedShellcode, pEncShellcode, sPayloadSize);

	// Initializing the Tiny-AES Library
	AES256_CBC_init(&ctx, pKey, pIv);

	// Decrypting
	AES256_CBC_decrypt(&ctx, pEncShellcode, sPayloadSize, &DecryptedShellcode);
	 
	// Printing the decrypted buffer
	PrintHexData("Shellcode", DecryptedShellcode, sPayloadSize);

	// Freeing the allocated buffer
	HeapFree(GetProcessHeap(), 0, DecryptedShellcode);

	// Exit
	printf("[#] Press <Enter> To Quit ...");
	getchar();
	return 0;
}