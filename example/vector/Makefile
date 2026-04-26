CC = x86_64-w64-mingw32-g++
AS = nasm
ASFLAGS = -f win64
CFLAGS = -Wall -O2 -mwindows -static -I./src
LDFLAGS = -shared -lntdll -lwininet

TARGET = bin/version.dll
SRC = src/loader.cpp
ASM_SRC = src/syscalls.asm
OBJ = bin/loader.o bin/syscalls.o

all: $(TARGET)

bin/syscalls.o: $(ASM_SRC)
	mkdir -p bin
	$(AS) $(ASFLAGS) $(ASM_SRC) -o bin/syscalls.o

bin/loader.o: $(SRC)
	mkdir -p bin
	$(CC) $(CFLAGS) -c $(SRC) -o bin/loader.o

$(TARGET): bin/loader.o bin/syscalls.o
	$(CC) $(LDFLAGS) bin/loader.o bin/syscalls.o -o $(TARGET)

clean:
	rm -rf bin

.PHONY: all clean
