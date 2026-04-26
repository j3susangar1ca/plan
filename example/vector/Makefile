# Makefile for Advanced Windows 11 Loader
# Uses MinGW-w64 for cross-compilation from Linux to Windows

CC = x86_64-w64-mingw32-g++
CFLAGS = -Wall -O2 -mwindows -static -I./src
LDFLAGS = -lntdll -lwininet

TARGET = bin/loader.exe
SRC = src/loader.cpp

all: $(TARGET)

$(TARGET): $(SRC) src/crypto.h src/api_hashes.h
	mkdir -p bin
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET) $(LDFLAGS)

clean:
	rm -rf bin

.PHONY: all clean
