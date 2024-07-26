# Concept

Usage of the IPv4 obfuscation to hide shellcode. 

## The shellcode was generated as follows:
```bash
msfvenom -p windows/x64/exec CMD=calc.exe -f raw -o calc.bin
```

# Compiling

```bash
$ make
```