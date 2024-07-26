ProjectName		= test

CCX64			= x86_64-w64-mingw32-gcc

CFLAGS			=  -Os -fno-asynchronous-unwind-tables
CFLAGS 			+= -fno-ident -fpack-struct=8 -falign-functions=1
CFLAGS  		+= -s -ffunction-sections -falign-jumps=1 -w
CFLAGS			+= -Wl,-s,--no-seh,--enable-stdcall-fixup

EXECUTABLE_X64	= $(ProjectName)_x64.exe
PAYLOAD			= payload.bin

SOURCES 		= $(filter-out template.c, $(wildcard *.c))

all: prep x64 clean

prep:
	@ echo "[*] Prepping payload ..."
	@ python3 scripts/prep.py $(PAYLOAD)
	@ echo "[*] DONE"

x64:
	@ echo "[*] Compiling x64 executable..."
	@ $(CCX64) $(SOURCES) -o $(EXECUTABLE_X64) $(CFLAGS)
	@ echo "[*] DONE"

clean:
	@ rm -rf *.o
	@ rm main.c