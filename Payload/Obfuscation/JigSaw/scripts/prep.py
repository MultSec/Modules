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

def get_int_string(data):
    result = ''

    for i in range(0, len(data), 16):
        result += "\t"
        chunk = data[i:i+16]
        for byte in chunk:
            result += f"{byte}, "
        result += "\n"

    return result[1:-3]

def fill_template(obfuscated_data, positions_data, original_data_size):
    try:
        # Read the content of the input file
        with open("template.c", 'r') as file:
            content = file.read()

        # Replace the strings
        modified_content = content.replace("{{SHELLCODE}}", obfuscated_data).replace("{{POSITIONS}}", positions_data).replace("{{SHELLCODE_SIZE}}", original_data_size)

        # Write the modified content to the output file
        with open("main.c", 'w') as file:
            file.write(modified_content)

        print("[i] Template filled successfully.")
    
    except IOError as e:
        print("[!] I/O error({0}): {1}".format(e.errno, e.strerror))

def jigsaw_obfuscate(original_data, positions):
    obfuscated_data = []

    for position in positions:
        obfuscated_data.append(original_data[position])

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

        # Generate a positions list
        positions = list(range(0,original_data_size))

        # Shuffle it randomly
        random.shuffle(positions)

        # Obfuscate the original data through a shuffle
        obfuscated_data = jigsaw_obfuscate(original_data, positions)

        # Fill template
        fill_template(get_hex_string(obfuscated_data), get_int_string(positions), str(original_data_size))

    else:
        print("[!] File not found or invalid path:", filename)
