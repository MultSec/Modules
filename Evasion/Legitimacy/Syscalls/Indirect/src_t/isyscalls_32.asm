section .data
    wSystemCall         dd  0
    qSyscallInsAdress   dd  0

section .text
    global _SetSSn
    global _RunSyscall

_SetSSn:
    xor eax, eax
    mov dword [wSystemCall], ecx
    xor edx, edx
    mov dword [qSyscallInsAdress], edx
    mov eax, dword [wSystemCall]
    mov edx, dword [qSyscallInsAdress + 4]  ; Load high dword of the address
    push eax  ; Push low dword of the address
    push edx  ; Push high dword of the address
    ret

_RunSyscall:
    mov ecx, [wSystemCall]
    mov edx, [qSyscallInsAdress + 4]  ; Load high dword of the address
    push ecx  ; Push low dword of the address
    push edx  ; Push high dword of the address
    retf      ; Far jump to the address
