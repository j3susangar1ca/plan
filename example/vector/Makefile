CC = x86_64-w64-mingw32-g++
AS = nasm
ASFLAGS = -f win64
CFLAGS = -Wall -O2 -mwindows -static -I./src
LDFLAGS = -lntdll -lwininet

TARGET = bin/loader.exe
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
	$(CC) bin/loader.o bin/syscalls.o -o $(TARGET) $(LDFLAGS)

clean:
	rm -rf bin

.PHONY: all clean
