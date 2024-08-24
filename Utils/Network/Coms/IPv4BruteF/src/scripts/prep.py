from pathlib import Path
from shutil import rmtree
import os
import sys
import re
from ctypes import c_int32, c_int64

class Logger:
    @staticmethod
    def info(message):
        print(f"\033[34m[*]\033[0m {message}")

    @staticmethod
    def success(message):
        print(f"\033[32m[+]\033[0m {message}")

    @staticmethod
    def debug(message):
        print(f"\033[33m[^]\033[0m {message}")

    @staticmethod
    def error(message):
        print(f"\033[31m[-]\033[0m {message}")

def merge_headers(header, search_paths):
    header_buff = f'//\n// header: {header}\n//'

    # Iterate through search paths
    for search_path in search_paths:
        # Ensure the search path exists
        if not os.path.exists(search_path):
            pLog.error( f"Search path '{search_path}' does not exist" )
            continue

        # Iterate through files in the search path
        for file_name in os.listdir(search_path):
            if file_name.endswith('.h'):  # Check if it's a .h file
                Log.info( f"\t- include/{file_name}" )
                file_path = os.path.join(search_path, file_name)
                with open(file_path, 'r') as file:
                    header_buff += ('\n\n' + file.read())  # Append file contents to header_buff

    # Replace anything here
    header_buff = header_buff.replace("{{INITIAL_HASH}}", str(INITIAL_HASH)).replace("{{INITIAL_SEED}}", str(INITIAL_SEED))

    hash_func = ''
    if (HASH_TYPE == "Djb2"):
        hash_func = "HashStringDjb2"
    elif (HASH_TYPE == "JenkinsOneAtATime32Bit"):
        hash_func = "HashStringJenkinsOneAtATime32Bit"
    elif (HASH_TYPE == "LoseLose"):
        hash_func = "HashStringLoseLose"

    header_buff = header_buff.replace("{{HASH_TYPE}}", hash_func)

    return header_buff

def merge_sources(source_dir):
    source_buff = '#include "header.h"\n'

    # Ensure the search path exists
    if not os.path.exists(source_dir):
        Log.error( f"Search path '{source_dir}' does not exist" )

    # Iterate through files in the search path
    for file_name in os.listdir(source_dir):
        if file_name.endswith('.c'):  # Check if it's a .c file
            Log.info( f"\t- src/{file_name}" )
            file_path = os.path.join(source_dir, file_name)
            with open(file_path, 'r') as file:
                source_buff += ('\n\n' + file.read())  # Append file contents to source_buff

    return source_buff

def read_template():
    file_path = Path( src ) / 'templates/main.c'

    with open(file_path, 'r') as file:
        return ('\n\n' + file.read())

def djb2_hash(s):
    Hash = INITIAL_HASH
    for c in s:
        Hash = ((Hash << INITIAL_SEED) + Hash) + ord(c)
    return Hash & 0xFFFFFFFF

def jenkins_one_at_a_time_hash(String):
    Hash = 0
    Index = 0
    Length = len(String)

    while Index != Length:
        Hash += ord(String[Index])
        Hash = c_int32(Hash).value & 0xFFFFFFFF
        Hash += Hash << INITIAL_SEED
        Hash = c_int32(Hash).value & 0xFFFFFFFF
        Hash ^= Hash >> 6
        Hash = c_int32(Hash).value & 0xFFFFFFFF
        Index += 1

    Hash += Hash << 3
    Hash = c_int32(Hash).value & 0xFFFFFFFF
    Hash ^= Hash >> 11
    Hash = c_int32(Hash).value & 0xFFFFFFFF
    Hash += Hash << 15
    Hash = c_int32(Hash).value & 0xFFFFFFFF

    return Hash

def lose_lose_hash(s):
    Hash = 0
    for c in s:
        Hash += ord(c)
        Hash *= ord(c) + INITIAL_SEED
    return Hash & 0xFFFFFFFF

def replace_with_digest(match):
    global HASH_COUNT

    # Extract the string inside the brackets
    inner_string = match.group(1)

    HASH_COUNT += 1

    # Calculate the digest
    if (HASH_TYPE == "Djb2"):
        return djb2_hash(inner_string)
    elif (HASH_TYPE == "JenkinsOneAtATime32Bit"):
        return jenkins_one_at_a_time_hash(inner_string)
    elif (HASH_TYPE == "LoseLose"):
        return lose_lose_hash(inner_string)
   
    # Return the digest to replace the original substring
    return None

def fill_template(src_buf):
    result = src_buf

    matches = re.finditer(r"\[\[\"(.*?)\"\]\]", src_buf)

    for match in matches:
        result = result.replace(match.group(0), str(replace_with_digest(match)))

    return result

def main():
    outdir = Path( out )
    if outdir.exists():
        Log.debug( "output directory already exists, removing it..." )
        rmtree( out )

    outdir.mkdir()

    Log.info( "merging headers:" )
    with  open( outdir / 'header.h', 'w+' ) as f:
        f.write( merge_headers(
            header = 'header.h',
            search_paths = [ Path( src ) / 'include' ]
        ))

    Log.success( f"wrote merge headers to {out}/header.h")

    Log.info( "parsing source files:" )
    src_buf = merge_sources(
        source_dir = Path( src ) / 'src'
    )

    Log.info( "parsing source files" )
    src_buf += read_template()
    
    with  open( outdir / 'main.c', 'w+' ) as f:
        f.write( fill_template(src_buf) )

    Log.debug( f"computed {HASH_COUNT} hashes of type {HASH_TYPE}" )
    Log.success( f"wrote merged/parsed source to {out}/main.c")

# Init logger
Log = Logger()

# Define src and out dirs
src = './src'
out = './out'

# Number of API hashes created
HASH_COUNT = 0
HASH_TYPE = 'LoseLose' # Djb2, LoseLose, JenkinsOneAtATime32Bit
INITIAL_HASH = 3731
INITIAL_SEED = 7

if __name__ == '__main__':
    main()
