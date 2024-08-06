# Makefile for compiling the reverse shell code on Windows using MinGW

# Compiler
CC = i686-w64-mingw32-gcc

# Compiler flags
CFLAGS = -Wall -Wextra -O2

# Source file
SRC = windows_reverse_shell.c

# Output executable
OUT = windows_reverse_shell.exe

# Targets
all: $(OUT)

$(OUT): $(SRC)
	$(CC) $(CFLAGS) -o $(OUT) $(SRC) -lws2_32

clean:
	del $(OUT)

# Phony targets to avoid conflicts with filenames
.PHONY: all clean
