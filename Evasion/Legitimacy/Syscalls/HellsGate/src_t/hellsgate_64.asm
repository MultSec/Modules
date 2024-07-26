section .data
    wSystemCall dq 420

section .text
    global HellsGate
    global HellDescent

HellsGate:
    mov dword [rel wSystemCall], 0
    mov dword [rel wSystemCall], ecx
    ret

HellDescent:
    mov r10, rcx
    mov eax, dword [rel wSystemCall]

    syscall
    ret