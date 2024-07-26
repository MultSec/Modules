ProjectName     = test

CCX64           = x86_64-w64-mingw32-gcc
RC              = x86_64-w64-mingw32-windres

CFLAGS          = -Os -fno-asynchronous-unwind-tables
CFLAGS          += -fno-ident -fpack-struct=8 -falign-functions=1
CFLAGS          += -s -ffunction-sections -falign-jumps=1 -w
CFLAGS          += -Wl,-s,--no-seh,--enable-stdcall-fixup

EXECUTABLE_X64  = $(ProjectName)_x64.exe

all: x64 clean

x64: resources.o
	@ echo "[*] Compile x64 executable..."
	@ $(CCX64) main.c resources.o -o $(EXECUTABLE_X64) $(CFLAGS)
	@ echo "[*] DONE"

resources.o: resources.rc
	@ echo "[*] Compile resources..."
	@ $(RC) -i resources.rc -O coff -o resources.o

clean:
	@ rm -rf *.o
