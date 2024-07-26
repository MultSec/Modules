# Concept

Usage of the [Jigsaw](https://redsiege.com/blog/2024/03/jigsaw/) techinque to hide shellcode. 

## The shellcode was generated as follows:
```bash
msfvenom -p windows/x64/exec CMD=calc.exe -f raw -o calc.bin
```

# Compiling

```bash
$ make
```