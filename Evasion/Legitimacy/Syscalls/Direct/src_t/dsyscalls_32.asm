section .data
    wSystemCall dd 0

section .text
    global _SetSSn
    global _RunSyscall

_SetSSn:
    mov dword [rel wSystemCall], 0
    mov dword [rel wSystemCall], ecx
    ret

_RunSyscall:
    mov ecx, [wSystemCall]
    int 0x2e
    ret