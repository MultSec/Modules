ProjectName		= test

CCX64			= x86_64-w64-mingw32-gcc
CCX86			= i686-w64-mingw32-gcc

CFLAGS			=  -Os -fno-asynchronous-unwind-tables
CFLAGS 			+= -fno-ident -fpack-struct=8 -falign-functions=1
CFLAGS  		+= -s -ffunction-sections -falign-jumps=1 -w
CFLAGS			+= -Wl,-s,--no-seh,--enable-stdcall-fixup
CFLAGS			+= -masm=intel

CHEADERS		=  -I src/include

SOURCES			=  src/*.c

all: pre x64 x86

pre:
	@ echo "[*] Preparing files ..."
	@ python3 scripts/apihash.py

x64:
	@ echo "[*] Compiling x64 executable..."
	@ nasm -f win64 src_t/hellsgate_64.asm -o src/hellsgate_64.o
	@ $(CCX64) $(SOURCES) src/hellsgate_64.o $(CHEADERS) $(CFLAGS) -o bin/$(ProjectName).x64.exe
	@ echo "[*] DONE"

x86:
	@ echo "[*] Compiling x86 executable..."
	@ nasm -f win32 src_t/hellsgate_32.asm -o src/hellsgate_86.o
	@ $(CCX86) $(SOURCES) src/hellsgate_86.o $(CHEADERS) $(CFLAGS) -o bin/$(ProjectName).x86.exe
	@ echo "[*] DONE"

clean:
	@ rm -rf src/*.o
	@ rm -rf src/main.c
	@ rm -rf src/include/apihash.h
	@ rm -rf bin/*.bin
	@ rm -rf bin/*.exe