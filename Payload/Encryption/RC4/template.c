#include <windows.h>
#include <stdio.h>

// Reference - https://www.oryx-embedded.com/doc/rc4_8c_source.html

typedef struct {
	unsigned int i;
	unsigned int j;
	unsigned char s[256];
} Rc4Context;

void rc4Init(Rc4Context* context, const unsigned char* key, size_t length) {
	unsigned int i;
	unsigned int j;
	unsigned char temp;

	// Check parameters
	if (context == NULL || key == NULL)
		return ERROR_INVALID_PARAMETER;

	// Clear context
	context->i = 0;
	context->j = 0;

	// Initialize the S array with identity permutation
	for (i = 0; i < 256; i++)
	{
		context->s[i] = i;
	}

	// S is then processed for 256 iterations
	for (i = 0, j = 0; i < 256; i++)
	{
		//Randomize the permutations using the supplied key
		j = (j + context->s[i] + key[i % length]) % 256;

		//Swap the values of S[i] and S[j]
		temp = context->s[i];
		context->s[i] = context->s[j];
		context->s[j] = temp;
	}

}


void rc4Cipher(Rc4Context* context, const unsigned char* input, unsigned char* output, size_t length) {
	unsigned char temp;

	// Restore context
	unsigned int i = context->i;
	unsigned int j = context->j;
	unsigned char* s = context->s;

	// Encryption loop
	while (length > 0)
	{
		// Adjust indices
		i = (i + 1) % 256;
		j = (j + s[i]) % 256;

		// Swap the values of S[i] and S[j]
		temp = s[i];
		s[i] = s[j];
		s[j] = temp;

		// Valid input and output?
		if (input != NULL && output != NULL)
		{
			//XOR the input data with the RC4 stream
			*output = *input ^ s[(s[i] + s[j]) % 256];

			//Increment data pointers
			input++;
			output++;
		}

		// Remaining bytes to process
		length--;
	}

	// Save context
	context->i = i;
	context->j = j;
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

	// Initialization
	Rc4Context ctx = { 0 };

	// Key used to decrypt
	rc4Init(&ctx, key, strlen(key));

	// Decryption
	rc4Cipher(&ctx, EncShellcode, DecryptedShellcode, sizeof(EncShellcode));

	// Printing the decrypted buffer
	PrintHexData("Shellcode", DecryptedShellcode, sizeof(EncShellcode));

	// Freeing the allocated buffer
	HeapFree(GetProcessHeap(), 0, DecryptedShellcode);

	// Exit
	printf("[#] Press <Enter> To Quit ...");
	getchar();
	return 0;
}
