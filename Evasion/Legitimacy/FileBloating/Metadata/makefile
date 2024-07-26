ProjectName     = test

CCX64           = x86_64-w64-mingw32-gcc
RC              = x86_64-w64-mingw32-windres

CFLAGS          = -Os -fno-asynchronous-unwind-tables
CFLAGS          += -fno-ident -fpack-struct=8 -falign-functions=1
CFLAGS          += -s -ffunction-sections -falign-jumps=1 -w
CFLAGS          += -Wl,-s,--no-seh,--enable-stdcall-fixup

EXECUTABLE      = $(ProjectName).exe
BLOAT_SIZE		= 200

all: x64 clean

x64: metadata.o
	@ echo "[*] Compiling x64 executable..."
	@ $(CCX64) main.c metadata.o -o $(EXECUTABLE) $(CFLAGS)
	@ echo "[*] DONE"

metadata.o: metadata.rc
	@ echo "[*] Inflating file.bin..."
	@ dd if=/dev/zero bs=1M count=$(BLOAT_SIZE) 2>/dev/null | tr '\000' '\377' > bloat.bin
	@ echo "[*] DONE"
	@ echo "[*] Compile metadata..."
	@ $(RC) -i metadata.rc -O coff -o metadata.o
	@ echo "[*] DONE"

clean:
	@ rm -rf *.o
	@ rm bloat.bin
