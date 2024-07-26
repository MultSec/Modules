ProjectName     = maldev

OSSL            = openssl
ESC             = osslsigncode

EXECUTABLE      = $(ProjectName).exe
SIGNED_EXEC     = $(ProjectName)_signed.exe
CONFIG          = openssl.cnf
PASSWORD        = verysecuresecretpassword

all: x64 clean

x64:
	@ echo "[*] Removing any previously signed file ..."
	@ rm -rf *_signed.exe
	@ echo "[*] Generating pem files ..."
	@ $(OSSL) req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 365 -nodes -config $(CONFIG) 2> /dev/null
	@ echo "[*] DONE"
	@ echo "[*] Generating pfx file ..."
	@ $(OSSL) pkcs12 -export -in cert.pem -inkey key.pem -passin pass:$(PASSWORD) -out sign.pfx -passout pass:$(PASSWORD)
	@ echo "[*] DONE"
	@ echo "[*] Signing executable file ..."
	@ $(ESC) sign -pkcs12 sign.pfx -in $(EXECUTABLE) -out $(SIGNED_EXEC) -pass $(PASSWORD) > /dev/null
	@ echo "[*] DONE"

clean:
	@ rm -rf *.pem 
	@ rm -f sign.pfx