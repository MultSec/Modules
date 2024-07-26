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

#
# Custom Stuff
#

def fill_header():
    header = ''

    # Read header file
    with open('src_t/include/apihash.h', 'r') as file:
        header = file.read()

    # Replace hashes
    header = header.replace("{{INITIAL_HASH}}", str(INITIAL_HASH)) \
                 .replace("{{INITIAL_SEED}}", str(INITIAL_SEED)) \
                 .replace("{{HASH_FUNC}}", HASH_TYPE)

    # Write header file
    with  open( 'src/include/apihash.h', 'w' ) as file:
        file.write( header )

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

def fill_source():
    # Read header file
    with open('src_t/main.c', 'r') as file:
        source = file.read()

    matches = re.finditer(r"\[\[\"(.*?)\"\]\]", source)

    # Replace hashes
    for match in matches:
        source = source.replace(match.group(0), str(replace_with_digest(match)))

    # Write source file
    with  open( 'src/main.c', 'w' ) as file:
        file.write( source )

# Number of API hashes created
HASH_COUNT = 0
HASH_TYPE = 'LoseLose' # Djb2, LoseLose, JenkinsOneAtATime32Bit
INITIAL_HASH = 3731
INITIAL_SEED = 7

def main():
    # Init logger
    Log = Logger()

    Log.info( "Preparing header:" )
    fill_header()
    Log.success( f"Wrote header")

    Log.info( "Preparing source:" )
    fill_source()
    Log.success( f"Wrote source")
    
    Log.debug( f"Computed {HASH_COUNT} hashes of type {HASH_TYPE}" )

if __name__ == '__main__':
    main()
