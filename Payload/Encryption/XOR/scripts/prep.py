import os
import sys
import random

def file_to_bytearray(filename):
    try:
        with open(filename, 'rb') as file:
            # Read the entire file
            file_content = file.read()
            return bytearray(file_content)
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

def xor_by_input_key(payload, key):
    modified_payload = bytearray(len(payload))
    key_size = len(key)
    j = 0
    for i in range(len(payload)):
        if j >= key_size:
            j = 0
        modified_payload[i] = payload[i] ^ key[j]
        j += 1
    return modified_payload

def fill_template(encrypted, key):
    try:
        # Read the content of the input file
        with open("template.c", 'r') as file:
            content = file.read()

        # Replace the strings
        modified_content = content.replace("{{SHELLCODE}}", encrypted).replace("{{KEY}}", key)

        # Write the modified content to the output file
        with open("main.c", 'w') as file:
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
        original_data = file_to_bytearray(filename)

        # Generate random key (size 16)
        key = bytearray(random.randint(0, 255) for _ in range(16))
        key_str = ", ".join([f"0x{byte:02x}" for byte in key])

        # Encrypt data
        encrypted_data = xor_by_input_key(original_data, key)
        encrypted_str = get_hex_string(encrypted_data)

        # Fill template
        fill_template(encrypted_str, key_str)

    else:
        print("[!] File not found or invalid path:", filename)
