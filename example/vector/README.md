# Advanced Windows 11 Entry Vector

This directory contains a sophisticated, multi-stage attack vector for Windows 11 environments, utilizing state-of-the-art evasion and persistence techniques.

## Components

### 1. Delivery: Polyglot PDF/HTA (`delivery/entry_vector.pdf.hta`)
A dual-purpose file that appears as a standard PDF document but contains an HTA payload. This bypasses many email and web filters that only inspect file extensions or headers.
- **Stealth**: Valid PDF header and cross-reference table.
- **Execution**: Runs VBScript when executed via `mshta.exe`.

### 2. Stage 1 Loader (`src/loader.cpp`)
A highly evasive C++ loader designed for the latest Windows 11 security features.
- **API Hashing**: Eliminates the Import Address Table (IAT) to hide intended functionality from static analysis tools.
- **Sleep Obfuscation**: Implements a variation of the *Ekko* technique, leveraging waitable timers and context switching to hide the process from memory scanners during sleep cycles.
- **Environmental Awareness**: Silent termination if a debugger, sandbox, or virtual machine is detected.
- **Persistence**: Creates an "immortal" directory in `C:\Windows\Tasks\CON` (using reserved names) to complicate manual removal.

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
