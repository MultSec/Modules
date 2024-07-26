ProjectName		= test

CCX64			= x86_64-w64-mingw32-gcc
CCX86			= i686-w64-mingw32-gcc

CFLAGS			=  -Os -fno-asynchronous-unwind-tables
CFLAGS 			+= -fno-ident -fpack-struct=8 -falign-functions=1
CFLAGS  		+= -s -ffunction-sections -falign-jumps=1 -w
CFLAGS			+= -Wl,-s,--no-seh,--enable-stdcall-fixup
CFLAGS			+= -masm=intel

SOURCES			=  src/*.c

all: x64 x86

pre64:
	@ echo "[*] Preparing x64 files ..."
	@ python3 scripts/SysWhispers3/syswhispers.py --arch x64 -c mingw -m jumper --functions NtAllocateVirtualMemory,NtProtectVirtualMemory -o src/Syscalls

pre86:
	@ echo "[*] Preparing x86 files ..."
	@ python3 scripts/SysWhispers3/syswhispers.py --arch x86 -c mingw -m jumper --functions NtAllocateVirtualMemory,NtProtectVirtualMemory -o src/Syscalls

x64: pre64
	@ echo "[*] Compiling x64 executable..."
	@ $(CCX64) $(SOURCES) $(CFLAGS) -o bin/$(ProjectName).x64.exe
	@ echo "[*] DONE"

x86: pre86
	@ echo "[*] Compiling x86 executable..."
	@ $(CCX86) $(SOURCES) $(CFLAGS) -o bin/$(ProjectName).x86.exe
	@ echo "[*] DONE"

clean:
	@ rm -rf *.o
	@ rm -rf src/Syscalls*
	@ rm -rf bin/*.bin
	@ rm -rf bin/*.exe