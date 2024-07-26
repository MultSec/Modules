import os
import sys
import random

def generate_protected_key(key):
    # Generate a random number between 0 and 255 to use as the XOR key
    xor_key = random.randint(0, 255)

    # Encrypt the key using the XOR key, with feedback from the previous byte
    protected_key = bytearray()
    previous_byte = 0

    for byte in key:
        encrypted_byte = byte ^ xor_key ^ previous_byte
        protected_key.append(encrypted_byte)
        previous_byte = encrypted_byte

    return protected_key

def bruteforce(protected_key, hint_byte, hint_byte_pos):
    for xor_key in range(256):
        key = bytearray()
        previous_byte = 0

        for byte in protected_key:
            decrypted_byte = byte ^ xor_key ^ previous_byte
            key.append(decrypted_byte)
            previous_byte = byte

        if key[hint_byte_pos] == hint_byte:
            return key

    print("[!] Key not found.")
    return None

def fill_template(hint_byte_str, hint_byte_pos, protected_key_str):
    try:
        # Read the content of the input file
        with open("template.c", 'r') as file:
            content = file.read()

        # Replace the strings
        modified_content = content.replace("{{HINT_BYTE}}", hint_byte_str).replace("{{HINT_BYTE_POS}}", str(hint_byte_pos)).replace("{{ENCRYPTED_KEY}}", protected_key_str)

        # Write the modified content to the output file
        with open("main.c", 'w') as file:
            file.write(modified_content)

        print("[i] Template filled successfully.")
    
    except IOError as e:
        print("[!] I/O error({0}): {1}".format(e.errno, e.strerror))

if __name__ == '__main__':
    # Generate random key (size 16)
    key = bytearray(random.randint(0, 255) for _ in range(16))
    key_str = ", ".join([f"0x{byte:02x}" for byte in key])
    print(f"[i] Key: {key_str}")

    # Choose random number between 0 and the key size
    hint_byte_pos = random.randint(0, 15)
    print(f"[i] Hint byte position: {hint_byte_pos}")
    hint_byte = key[hint_byte_pos]
    hint_byte_str = f"0x{hint_byte:02x}"
    print(f"[i] Hint byte: {hint_byte_str}")

    # Encrypt key
    protected_key = generate_protected_key(key)
    protected_key_str = ", ".join([f"0x{byte:02x}" for byte in protected_key])
    print(f"[i] Encrypted key: {protected_key_str}")

    # Fill the template
    fill_template(hint_byte_str, hint_byte_pos, protected_key_str)