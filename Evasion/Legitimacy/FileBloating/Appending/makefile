ProjectName     = test

EXECUTABLE      = $(ProjectName).exe
EXECUTABLE_INF  = $(ProjectName)_inf.exe
BLOAT_SIZE		= 200

all: x64

x64:
	@ echo "[*] Copying original file to inflate..."
	@ cp $(EXECUTABLE) $(EXECUTABLE_INF)
	@ echo "[*] DONE"
	@ echo "[*] Appending bloat..."
	@ dd if=/dev/zero bs=1M count=$(BLOAT_SIZE) 2>/dev/null >> $(EXECUTABLE_INF)

clean:
	@ rm -rf *_inf.exe
