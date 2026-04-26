#ifndef SYSCALLS_H
#define SYSCALLS_H

#include <windows.h>

typedef struct _SYSCALL_ENTRY {
    WORD ssn;
    PVOID address;
} SYSCALL_ENTRY;

static PVOID FindSyscallGadget() {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    PBYTE pNtProtect = (PBYTE)GetProcAddress(hNtdll, "NtProtectVirtualMemory");
    
    for (int i = 0; i < 100; i++) {
        if (pNtProtect[i] == 0x0F && pNtProtect[i+1] == 0x05 && pNtProtect[i+2] == 0xC3) {
            return (PVOID)(pNtProtect + i);
        }
    }
    return NULL;
}

static WORD GetSSN(PVOID pFunc) {
    PBYTE pFuncByte = (PBYTE)pFunc;
    if (pFuncByte[0] == 0x4C && pFuncByte[1] == 0x8B && pFuncByte[2] == 0xD1 && pFuncByte[3] == 0xB8) {
        return *(WORD*)(pFuncByte + 4);
    }
    for (WORD idx = 1; idx <= 32; idx++) {
        PBYTE pUp = pFuncByte - (idx * 32);
        if (pUp[0] == 0x4C && pUp[1] == 0x8B && pUp[2] == 0xD1 && pUp[3] == 0xB8) return *(WORD*)(pUp + 4) + idx;
        PBYTE pDown = pFuncByte + (idx * 32);
        if (pDown[0] == 0x4C && pDown[1] == 0x8B && pDown[2] == 0xD1 && pDown[3] == 0xB8) return *(WORD*)(pDown + 4) - idx;
    }
    return 0;
}

extern "C" NTSTATUS InvokeSyscall(WORD ssn, PVOID gadget, ...);
extern "C" PVOID FindCleanSyscallStub(PVOID cleanNtdllBase, DWORD funcRva);

#endif
