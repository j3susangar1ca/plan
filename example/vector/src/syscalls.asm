SECTION .text
GLOBAL InvokeSyscall
GLOBAL FindCleanSyscallStub

; ----------------------------------------------------------------------------
; InvokeSyscall(WORD ssn, PVOID cleanStub, ...)
;   rcx = ssn (System Service Number)
;   rdx = cleanStub (dirección del stub syscall;ret limpio)
;   r8  = arg1
;   r9  = arg2
;   [rsp+0x28] = arg3 (NT original)
;   [rsp+0x30] = arg4
;   [rsp+0x38] = arg5
; ----------------------------------------------------------------------------
InvokeSyscall:
    ; Guardar registros no volátiles (7 registros = 56 bytes)
    push    rbx
    push    rdi
    push    rsi
    push    r12
    push    r13
    push    r14
    push    r15
    
    ; rax = SSN
    mov     eax, ecx
    
    ; r10 = arg1 (primer argumento real de la syscall)
    mov     r10, r8
    
    ; Guardar el gadget en r11 para liberar rdx
    mov     r11, rdx
    
    ; Reorganizar argumentos para el syscall
    ; rdx debe ser arg2 (que está en r9)
    mov     rdx, r9
    
    ; Cargar argumentos 3-6 desde stack original
    ; Offset = pushes (56) + return_addr (8) + shadow_space (32) = 96 (0x60)
    mov     r8,  [rsp + 0x60]   ; arg3
    mov     r9,  [rsp + 0x68]   ; arg4
    mov     rbx, [rsp + 0x70]   ; arg5
    mov     rdi, [rsp + 0x78]   ; arg6
    
    ; Preparar stack para el gadget (shadow space + args 5-6)
    sub     rsp, 0x30           ; 48 bytes (alineado a 16)
    mov     [rsp + 0x20], rbx   ; arg5
    mov     [rsp + 0x28], rdi   ; arg6
    
    ; Llamada indirecta al gadget limpio
    call    r11
    
    ; Restaurar stack
    add     rsp, 0x30
    
    ; Restaurar registros
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rsi
    pop     rdi
    pop     rbx
    
    ret

; ----------------------------------------------------------------------------
; FindCleanSyscallStub(PVOID cleanNtdllBase, DWORD funcRva)
;   Busca el patrón 0F 05 C3 (syscall; ret) en el stub limpio
; ----------------------------------------------------------------------------
FindCleanSyscallStub:
    mov     r8, rcx           ; r8 = cleanNtdllBase
    mov     r9d, edx          ; r9d = funcRva
    add     r8, r9            ; r8 = dirección de función en copia limpia
    
    xor     rcx, rcx
.search_loop:
    cmp     rcx, 32
    jge     .not_found
    
    movzx   eax, word [r8 + rcx]
    cmp     ax, 0x050F        ; syscall (0F 05)
    jne     .next_byte
    
    movzx   eax, byte [r8 + rcx + 2]
    cmp     al, 0xC3          ; ret
    je      .found
    
.next_byte:
    inc     rcx
    jmp     .search_loop

.found:
    mov     rax, r8
    add     rax, rcx
    ret

.not_found:
    xor     rax, rax
    ret
