SECTION .text
GLOBAL InvokeSyscall

; =============================================================================
; InvokeSyscall(WORD ssn, PVOID gadget, ...)
;   rcx = ssn (System Service Number)
;   rdx = gadget (address of syscall;ret in ntdll)
;   r8  = arg1 (first real NT argument)
;   r9  = arg2
;   [rsp+0x28] = arg3
;   [rsp+0x30] = arg4
;   [rsp+0x38] = arg5
;   [rsp+0x40] = arg6
;
; OPTIMIZED: only 1 non-volatile register saved (rbx) to minimise
;            stack footprint and avoid unnecessary push/pop overhead.
; =============================================================================

InvokeSyscall:
    push    rbx                 ; save only rbx (non-volatile)

    ; eax = SSN
    mov     eax, ecx

    ; r10 = arg1 (NT syscall convention: first arg in r10)
    mov     r10, r8

    ; Save gadget address, free rdx for arg2
    mov     r11, rdx

    ; rdx = arg2
    mov     rdx, r9

    ; Load remaining arguments from caller's stack
    ; Offset: push(8) + ret_addr(8) + shadow(32) = 48 = 0x30
    mov     r8,  [rsp + 0x30]   ; arg3
    mov     r9,  [rsp + 0x38]   ; arg4
    mov     rbx, [rsp + 0x40]   ; arg5 (temp in rbx)

    ; Allocate shadow space + room for arg5 on callee stack
    sub     rsp, 0x28           ; 40 bytes (shadow + 1 slot, 16-aligned with push)
    mov     [rsp + 0x20], rbx   ; place arg5

    ; Indirect call through clean gadget (syscall;ret)
    call    r11

    ; Clean up
    add     rsp, 0x28
    pop     rbx
    ret
