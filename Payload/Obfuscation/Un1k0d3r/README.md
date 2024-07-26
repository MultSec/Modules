# Concept

Usage of the [Mr.Un1k0d3r](https://mr.un1k0d3r.world/)'s obfuscation to hide shellcode. 

## The shellcode was generated as follows:
```bash
msfvenom -p windows/x64/exec CMD=calc.exe -f raw -o calc.bin
```

# Compiling

```bash
$ make
```