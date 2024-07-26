import os
import sys
import random

def fill_template(words):
    try:
        # Read the content of the input file
        with open("template.c", 'r') as file:
            content = file.read()

        # Replace the strings
        modified_content = content.replace("{{WORDS}}", words)

        # Write the modified content to the output file
        with open("main.c", 'w') as file:
            file.write(modified_content)

        print("[i] Template filled successfully.")
    
    except IOError as e:
        print("[!] I/O error({0}): {1}".format(e.errno, e.strerror))

def get_words():
    words = []
    try:
        with open("words.txt", 'r') as file:
            # For each word in the file add it to the list
            for line in file:
                for word in line.split():
                    words.append(word)
    except IOError as e:
        print("[!] I/O error({0}): {1}".format(e.errno, e.strerror))
    return words

def create_words_string(words, words_num):
    words_str = ""
    for i in range(int(words_num)):
        words_str += "\"" + random.choice(words) + "\", "
    return words_str[:-2]

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("[i] Usage: python script.py <Number of Words>")
        sys.exit(1)
    
    words_num = sys.argv[1]
    
    # Get words from words.txt
    words = get_words()

    # Create words string
    word_arr_str = create_words_string(words, words_num)

    # Fill template
    fill_template(word_arr_str)