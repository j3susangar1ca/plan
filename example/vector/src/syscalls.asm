SECTION .text
GLOBAL InvokeSyscall

InvokeSyscall:
    mov r10, rcx
    mov rax, r10
    mov r10, rdx
    
    mov rcx, r8
    mov rdx, r9
    mov r8, [rsp + 40]
    mov r9, [rsp + 48]
    
    jmp r10
