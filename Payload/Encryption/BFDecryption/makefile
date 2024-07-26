ProjectName		= test

CCX64			= x86_64-w64-mingw32-gcc

CFLAGS			=  -Os -fno-asynchronous-unwind-tables
CFLAGS 			+= -fno-ident -fpack-struct=8 -falign-functions=1
CFLAGS  		+= -s -ffunction-sections -falign-jumps=1 -w
CFLAGS			+= -Wl,-s,--no-seh,--enable-stdcall-fixup

EXECUTABLE_X64	= $(ProjectName)_x64.exe

all: x64 clean

x64:
	@ echo "[*] Prepping key ..."
	@ python3 scripts/prep.py
	@ echo "[*] DONE"
	@ echo "[*] Compiling x64 executable..."
	@ $(CCX64) main.c -o $(EXECUTABLE_X64) $(CFLAGS) 
	@ echo "[*] DONE"

clean:
	@ rm -rf *.o
	@ rm main.c