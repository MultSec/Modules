import os
import sys
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def generate_key():
    # Generate a random 32-byte (256-bit) key
    return os.urandom(32)

def generate_iv():
    # Generate a random 16-byte (128-bit) IV
    return os.urandom(16)

def encrypt_message(key, iv, message):
    # Pad the message if its length is not a multiple of 16
    if len(message) % 16 != 0:
        message = message.ljust(len(message) + (16 - len(message) % 16))
    
    # Create a Cipher object
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Encrypt the message
    ciphertext = encryptor.update(message) + encryptor.finalize()
    
    return ciphertext

def file_data(filename):
    try:
        with open(filename, 'rb') as file:
            # Read the entire file
            file_content = file.read()
            return file_content
    except IOError as e:
        print("[!] I/O error({0}): {1}".format(e.errno, e.strerror))
        raise

def get_hex_string(data):
    result = ''

    for i in range(0, len(data), 16):
        result += "\t"
        chunk = data[i:i+16]
        for byte in chunk:
            result += f"0x{byte:02x}, "
        result += "\n"

    return result[1:-3]

def fill_template(encrypted, key, iv):
    try:
        # Read the content of the input file
        with open("./src_t/main.c", 'r') as file:
            content = file.read()

        # Replace the strings
        modified_content = content.replace("{{SHELLCODE}}", encrypted).replace("{{KEY}}", key).replace("{{IV}}", iv)

        # Write the modified content to the output file
        with open("./src/main.c", 'w') as file:
            file.write(modified_content)

        print("[i] Template filled successfully.")
    
    except IOError as e:
        print("[!] I/O error({0}): {1}".format(e.errno, e.strerror))

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("[i] Usage: python script.py <file_path>")
        sys.exit(1)
    
    filename = sys.argv[1]
    if os.path.isfile(filename):
        original_data = file_data(filename)

        # Generate random key (size 32)
        key = generate_key()
        key_str = ", ".join([f"0x{byte:02x}" for byte in bytearray(key)])

        # Generate random iv
        iv = generate_iv()
        iv_str = ", ".join([f"0x{byte:02x}" for byte in bytearray(iv)])

        # Encrypt data
        encrypted_data = encrypt_message(key, iv, original_data)
        encrypted_str = get_hex_string(encrypted_data)

        # Fill template
        fill_template(encrypted_str, key_str, iv_str)

    else:
        print("[!] File not found or invalid path:", filename)
