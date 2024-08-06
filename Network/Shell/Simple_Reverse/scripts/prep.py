import sys

def fill_template(ip, port, bin_path):
    try:
        # Read the content of the input file
        with open("./src_t/main.c", 'r') as file:
            content = file.read()

        # Replace the strings
        modified_content = content.replace("{{IP_ADDR}}", ip).replace("{{PORT_NUM}}", port).replace("{{BIN_PATH}}", bin_path)

        # Write the modified content to the output file
        with open("./src/main.c", 'w') as file:
            file.write(modified_content)

        print("[i] Template filled successfully.")
    
    except IOError as e:
        print("[!] I/O error({0}): {1}".format(e.errno, e.strerror))

if __name__ == '__main__':
    if len(sys.argv) != 4:
        print("[i] Usage: python3 prep.py ip port bin_path")
        sys.exit(1)
    
    fill_template(sys.argv[1], sys.argv[2], sys.argv[3])

