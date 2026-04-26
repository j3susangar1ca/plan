# Advanced Windows 11 Entry Vector

This directory contains a sophisticated, multi-stage attack vector for Windows 11 environments, utilizing state-of-the-art evasion and persistence techniques.

## Components

### 1. Delivery: ISO Image Smuggling + LNK
Instead of a simple HTA, we now use a more robust **ISO image** delivery.
- **MOTW Bypass**: Files inside an ISO often bypass the Mark-of-the-Web (MOTW) flag in many Windows versions.
- **Obfuscated LNK**: The ISO contains a shortcut (LNK) file that executes a legitimate, signed Microsoft binary (like `cmd.exe`) with a highly obfuscated command.
- **ESET/AMSI Evasion**: The initial command includes a stage-0 AMSI bypass to ensure the Stage 1 loader can be dropped and executed without triggering heuristics.

### 2. Stage 1 Loader (`src/loader.cpp`)
A highly evasive C++ loader designed for the latest Windows 11 Pro security features.
- **AMSI Bypass (Memory-Patching)**: Patches `amsi.dll!AmsiScanBuffer` in memory using hashed/indirect syscalls to disable script and buffer scanning.
- **Silent UAC Bypass**: Implements the `fodhelper.exe` registry hijacking technique to automatically elevate itself to Administrator privileges without any user prompt.
- **API Hashing**: Eliminates the Import Address Table (IAT).
- **Sleep Obfuscation**: Implements the *Ekko* technique.
- **Persistence**: 
    - **Admin Mode**: Creates an "immortal" directory in `C:\Windows\Tasks\CON`.
    - **User Mode (Fallback)**: Uses **COM Hijacking** in `HKCU` if elevation fails.

### 3. Crypto Module (`src/crypto.h`)
Standard implementation of **ChaCha20**, used for encrypting the Stage 2 payload and communication with the C2 infrastructure.

## Building

To compile the loader using MinGW-w64 on a Linux system:

```bash
make
```

The resulting binary will be located in `bin/loader.exe`.

## Usage

1. Compile the loader.
2. Embed the loader (or a download command) into the VBScript section of the `entry_vector.pdf.hta`.
3. Deliver the polyglot file to the target.

## Disclaimer

This code is provided for educational and authorized testing purposes only. The techniques demonstrated here are representative of advanced persistent threats (APTs) and should be used to improve defensive postures.
