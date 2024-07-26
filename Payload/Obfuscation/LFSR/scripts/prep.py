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

def fill_template(obfuscated_data, seed, original_data_size):
    try:
        # Read the content of the input file
        with open("template.c", 'r') as file:
            content = file.read()

        # Replace the strings
        modified_content = content.replace("{{SHELLCODE}}", obfuscated_data).replace("{{SEED}}", seed).replace("{{SHELLCODE_SIZE}}", original_data_size)

        # Write the modified content to the output file
        with open("main.c", 'w') as file:
            file.write(modified_content)

        print("[i] Template filled successfully.")
    
    except IOError as e:
        print("[!] I/O error({0}): {1}".format(e.errno, e.strerror))

def lfsr_obfuscate(original_data, seed):
    obfuscated_data = []
    lfsr_value = seed

    for original_byte in original_data:
        obfuscated_data.append(lfsr_value ^ original_byte)
        feedback = lfsr_value & 1
        lfsr_value >>= 1
        if feedback & 1 == 1:
            lfsr_value ^= 0x110

    return obfuscated_data

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("[i] Usage: python script.py <file_path>")
        sys.exit(1)
    
    filename = sys.argv[1]
    if os.path.isfile(filename):
        original_data = file_to_bytearray(filename)

        # Number of bytes in the original data
        original_data_size = len(original_data)

        # Generate random seed
        seed = random.randint(0, 511)

        # Obfuscate the original data through an XOR between it and a LFSR
        obfuscated_data = lfsr_obfuscate(original_data, seed)

        # Fill template
        fill_template(get_hex_string(obfuscated_data), str(seed), str(original_data_size))

    else:
        print("[!] File not found or invalid path:", filename)
