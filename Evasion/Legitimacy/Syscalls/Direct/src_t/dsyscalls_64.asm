section .data
    wSystemCall dq 420

section .text
    global SetSSn
    global RunSyscall

SetSSn:
    mov dword [rel wSystemCall], 0
    mov dword [rel wSystemCall], ecx
    ret

RunSyscall:
    mov r10, rcx
    mov eax, dword [rel wSystemCall]

    syscall
    ret