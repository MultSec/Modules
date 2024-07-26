#include <windows.h>
#include <stdio.h>

#define KEYSIZE		16

unsigned char* bruteforce(unsigned char* protected_key, unsigned char hint_byte, size_t hint_byte_pos) {
    for (int xor_key = 0; xor_key < 256; xor_key++) {
        unsigned char* key = (unsigned char*)malloc(sizeof(unsigned char) * KEYSIZE);
        unsigned char previous_byte = 0;

        for (size_t i = 0; i < KEYSIZE; i++) {
            unsigned char decrypted_byte = protected_key[i] ^ xor_key ^ previous_byte;
            key[i] = decrypted_byte;
            previous_byte = protected_key[i];
        }

        if (key[hint_byte_pos] == hint_byte) {
            return key;
        }

        free(key);
    }

    printf("[!] Key not found.\n");
    return NULL;
}

int main() {
    unsigned char protected_key[] = { {{ENCRYPTED_KEY}} };
    unsigned char hint_byte = {{HINT_BYTE}};
    size_t hint_byte_pos = {{HINT_BYTE_POS}};

    printf("[+] Brute forcing key...\n");
    unsigned char* found_key = bruteforce(protected_key, hint_byte, hint_byte_pos);
    if (found_key != NULL) {
        printf("[+] Key found:\n");
        for (int i = 0; i < 16; i++) {
            printf("%02X ", found_key[i]);
        }
        printf("\n");
        free(found_key);
    }

    printf("[#] Press <Enter> To Quit ... ");
	getchar();

    return 0;
}