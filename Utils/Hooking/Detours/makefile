ProjectName		= test

CCX64			= x86_64-w64-mingw32-gcc

CFLAGS			=  -Os -fno-asynchronous-unwind-tables
CFLAGS 			+= -fno-ident -fpack-struct=8 -falign-functions=1
CFLAGS  		+= -s -ffunction-sections -falign-jumps=1 -w
CFLAGS			+= -Wl,-s,--no-seh,--enable-stdcall-fixup
CHEADERS		= -I include

LDFLAGS_X64		= -L -l lib/detoursx64.lib
LDFLAGS_X86		= -L -l lib/detoursx86.lib

EXECUTABLE_X64	= $(ProjectName)_x64.exe

all: x64 clean

x64:
	@ echo "[*] Compile x64 executable..."
	@ $(CCX64) main.c $(CHEADERS) $(LDFLAGS_X64) $(CFLAGS) -o $(EXECUTABLE_X64)
	@ echo "[*] DONE"

clean:
	@ rm -rf *.o