[BITS 64]

GLOBAL Syscall
EXTERN GetSsn

[SECTION .text]

Syscall:
    call get_info
    mov [rsp - 0x8],  rsi
    mov [rsp - 0x10], rdi
    mov [rsp - 0x18], r12

    mov r12, rcx
    mov rcx, rdx

    mov r10, r8
    mov rdx, r9

    mov  r8,  [rsp + 0x28]
    mov  r9,  [rsp + 0x30]

    sub rcx, 0x4
    jle skip

    lea rsi,  [rsp + 0x38]
    lea rdi,  [rsp + 0x28]

    rep movsq
skip:

    mov rcx, r12

    mov rsi, [rsp - 0x8]
    mov rdi, [rsp - 0x10]
    mov r12, [rsp - 0x18]

    jmp rcx

get_info:
    push rdx

    lea rdx, [rsp - 0x08]
    sub rsp, 0x38
    call GetSsn
    add rsp, 0x38
    mov rcx, [rsp - 0x08]

    ;rax holds ssn
    ;rcx holds addr of syscall

    pop rdx
    ret