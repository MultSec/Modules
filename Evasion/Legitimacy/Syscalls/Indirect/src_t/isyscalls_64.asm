section .data
    wSystemCall         dq  420
    qSyscallInsAdress   dq  420

section .text
    global SetSSn
    global RunSyscall

SetSSn:
    mov dword [rel wSystemCall], 0
    mov qword [rel qSyscallInsAdress], 0
    mov dword [rel wSystemCall], ecx
    mov qword [rel qSyscallInsAdress], rdx
    ret

RunSyscall:
    mov r10, rcx
    mov eax, dword [rel wSystemCall]
    jmp qword [rel qSyscallInsAdress]
    ret