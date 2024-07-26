section .data
    wSystemCall dd 0

section .text
    global _HellsGate
    global _HellDescent

_HellsGate:
    mov dword [rel wSystemCall], 0
    mov dword [rel wSystemCall], ecx
    ret

_HellDescent:
    mov ecx, [wSystemCall]
    int 0x2e
    ret