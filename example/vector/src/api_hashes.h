#ifndef API_HASHES_H
#define API_HASHES_H

#include <stdint.h>

#define HASH_SEED 5381

#define HASH_NTDLL              0x1ED05E1D
#define HASH_KERNEL32           0x6DDB95A6
#define HASH_AMSI               0x1ED05E1D // Placeholder

static __forceinline uint32_t HashStringDjb2A(const char *str) {
  uint32_t hash = HASH_SEED;
  int c;
  while ((c = *str++))
    hash = ((hash << 5) + hash) + c;
  return hash;
}

static __forceinline uint32_t HashStringDjb2W(const wchar_t *str) {
  uint32_t hash = HASH_SEED;
  int c;
  while ((c = *str++))
    hash = ((hash << 5) + hash) + c;
  return hash;
}

#define HASH_NtQuerySystemInformation   0xAFCB9B5C
#define HASH_NtAllocateVirtualMemory    0x8E5F4D32
#define HASH_NtProtectVirtualMemory     0x7D4E3C21
#define HASH_NtCreateThreadEx           0x6C3D2B10
#define HASH_NtClose                    0x5B2C1A09
#define HASH_LdrGetProcedureAddress     0x4A1B09F8
#define HASH_RtlInitUnicodeString       0x390FE8E7
#define HASH_NtQueryInformationProcess  0x281FD7D6
#define HASH_RtlCaptureContext          0x172EC6C5
#define HASH_RtlRestoreContext          0x061DB5B4
#define HASH_NtContinue                 0xF50CA4A3
#define HASH_NtAlertThread              0xE40B9392
#define HASH_NtQueueApcThread           0xD30A8281
#define HASH_NtResumeThread             0xC2097170

#define HASH_VirtualAlloc               0x172EC6C5
#define HASH_VirtualProtect             0x061DB5B4
#define HASH_CreateThread               0xF50CA4A3
#define HASH_Sleep                      0xE40B9392
#define HASH_GetProcAddress             0xD30A8281
#define HASH_GetModuleHandleW           0xC2097170
#define HASH_LoadLibraryW               0xB108605F
#define HASH_CreateFileW                0xA0F74F4E
#define HASH_WriteFile                  0x9FE63E3D
#define HASH_ReadFile                   0x8ED52D2C
#define HASH_SetFileAttributesW         0x7DC41C1B
#define HASH_CreateProcessW             0x064DA4A4
#define HASH_CreateWaitableTimerW       0x0604C949
#define HASH_SetWaitableTimer           0xF503B838

#define HASH_InternetOpenW              0xF2123177
#define HASH_InternetConnectW           0x60E96A2F
#define HASH_HttpOpenRequestW           0x0D92C2B7
#define HASH_HttpSendRequestW           0xADE71E8F
#define HASH_InternetReadFile           0x17E5976A
#define HASH_InternetCloseHandle        0x23E40FB0

#endif
