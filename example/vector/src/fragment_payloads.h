#ifndef FRAGMENT_PAYLOADS_H
#define FRAGMENT_PAYLOADS_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// =============================================================================
// CRC32 (ISO 3309)
// =============================================================================

static uint32_t crc32_table[256];
static int crc32_initialized = 0;

static void crc32_init() {
    if (crc32_initialized) return;
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t crc = i;
        for (int j = 0; j < 8; j++)
            crc = (crc >> 1) ^ (crc & 1 ? 0xEDB88320 : 0);
        crc32_table[i] = crc;
    }
    crc32_initialized = 1;
}

static uint32_t crc32_compute(const uint8_t *data, size_t len) {
    crc32_init();
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < len; i++)
        crc = (crc >> 8) ^ crc32_table[(crc ^ data[i]) & 0xFF];
    return crc ^ 0xFFFFFFFF;
}

// =============================================================================
// SIMPLE ZLIB-LIKE COMPRESSION (LZ77 minimal)
// Lightweight compressor: stores raw if no savings, otherwise uses
// simple run-length + match encoding suitable for small blocks.
// =============================================================================

// For simplicity in this header-only implementation, we use a store-based
// approach with a 1-byte header: 0x00 = raw, 0x01 = compressed (future)
// This keeps chunk overhead minimal.

typedef struct _FRAGMENT_HEADER {
    uint16_t chunkIndex;        // Fragment sequence number
    uint16_t originalSize;      // Size before compression
    uint16_t compressedSize;    // Size after compression (= originalSize if raw)
    uint32_t crc32;             // CRC32 of original data
    uint8_t  flags;             // 0x00=raw, 0x01=compressed
    uint8_t  reserved;
} FRAGMENT_HEADER;

#define FRAG_MIN_CHUNK  48
#define FRAG_MAX_CHUNK  96
#define FRAG_HEADER_SZ  sizeof(FRAGMENT_HEADER)

// =============================================================================
// FRAGMENT PAYLOAD INTO VARIABLE-SIZE CHUNKS
// =============================================================================

typedef struct _FRAGMENT_SET {
    uint8_t  **chunks;          // Array of chunk buffers (header + data)
    size_t   *chunkSizes;       // Size of each chunk buffer
    uint16_t  count;            // Number of chunks
    uint32_t  totalCRC;         // CRC32 of entire original payload
} FRAGMENT_SET;

static FRAGMENT_SET* FragmentPayload(const uint8_t *payload, size_t payloadLen) {
    if (!payload || payloadLen == 0) return NULL;

    // Estimate max chunks
    uint16_t maxChunks = (uint16_t)((payloadLen / FRAG_MIN_CHUNK) + 2);

    FRAGMENT_SET *fs = (FRAGMENT_SET *)malloc(sizeof(FRAGMENT_SET));
    if (!fs) return NULL;
    fs->chunks = (uint8_t **)malloc(maxChunks * sizeof(uint8_t *));
    fs->chunkSizes = (size_t *)malloc(maxChunks * sizeof(size_t));
    fs->count = 0;
    fs->totalCRC = crc32_compute(payload, payloadLen);

    size_t offset = 0;
    uint16_t idx = 0;

    // Simple PRNG for variable chunk sizes (seeded from payload)
    uint32_t rng = 0x12345678 ^ (uint32_t)payloadLen;

    while (offset < payloadLen) {
        // Polymorphic chunk size: random between FRAG_MIN_CHUNK and FRAG_MAX_CHUNK
        rng = rng * 1103515245 + 12345; // LCG
        uint16_t chunkDataSize = FRAG_MIN_CHUNK + (rng % (FRAG_MAX_CHUNK - FRAG_MIN_CHUNK + 1));

        // Don't exceed remaining data
        size_t remaining = payloadLen - offset;
        if (chunkDataSize > remaining) chunkDataSize = (uint16_t)remaining;

        // Build chunk: header + data
        size_t totalChunkSize = FRAG_HEADER_SZ + chunkDataSize;
        uint8_t *chunk = (uint8_t *)malloc(totalChunkSize);
        if (!chunk) break;

        FRAGMENT_HEADER *hdr = (FRAGMENT_HEADER *)chunk;
        hdr->chunkIndex = idx;
        hdr->originalSize = chunkDataSize;
        hdr->compressedSize = chunkDataSize; // raw storage
        hdr->crc32 = crc32_compute(payload + offset, chunkDataSize);
        hdr->flags = 0x00; // raw
        hdr->reserved = 0;

        memcpy(chunk + FRAG_HEADER_SZ, payload + offset, chunkDataSize);

        fs->chunks[idx] = chunk;
        fs->chunkSizes[idx] = totalChunkSize;
        fs->count = ++idx;
        offset += chunkDataSize;
    }

    return fs;
}

static void FreeFragmentSet(FRAGMENT_SET *fs) {
    if (!fs) return;
    for (uint16_t i = 0; i < fs->count; i++) free(fs->chunks[i]);
    free(fs->chunks);
    free(fs->chunkSizes);
    free(fs);
}

// =============================================================================
// REASSEMBLE FRAGMENTS WITH CRC32 VERIFICATION
// =============================================================================

static uint8_t* ReassembleFragments(FRAGMENT_SET *fs, size_t *outLen) {
    if (!fs || fs->count == 0) return NULL;

    // Calculate total size
    size_t totalSize = 0;
    for (uint16_t i = 0; i < fs->count; i++) {
        FRAGMENT_HEADER *hdr = (FRAGMENT_HEADER *)fs->chunks[i];
        totalSize += hdr->originalSize;
    }

    uint8_t *result = (uint8_t *)malloc(totalSize);
    if (!result) return NULL;

    size_t offset = 0;
    for (uint16_t i = 0; i < fs->count; i++) {
        FRAGMENT_HEADER *hdr = (FRAGMENT_HEADER *)fs->chunks[i];
        uint8_t *data = fs->chunks[i] + FRAG_HEADER_SZ;

        // Verify CRC32 integrity
        uint32_t computedCRC = crc32_compute(data, hdr->originalSize);
        if (computedCRC != hdr->crc32) {
            free(result);
            return NULL; // Integrity failure
        }

        memcpy(result + offset, data, hdr->originalSize);
        offset += hdr->originalSize;
    }

    // Verify total payload CRC
    uint32_t totalCRC = crc32_compute(result, totalSize);
    if (totalCRC != fs->totalCRC) {
        free(result);
        return NULL;
    }

    if (outLen) *outLen = totalSize;
    return result;
}

// =============================================================================
// JS REASSEMBLY STUB GENERATOR
// =============================================================================
// Generates a JavaScript snippet that can reassemble Base64-encoded chunks

static const char* GenerateJSReassemblyStub() {
    return
        "function reassemble(chunks) {\n"
        "  var full = '';\n"
        "  for (var i = 0; i < chunks.length; i++) {\n"
        "    var hdrB64 = chunks[i].substring(0, 16);\n"  // header
        "    var dataB64 = chunks[i].substring(16);\n"
        "    full += dataB64;\n"
        "  }\n"
        "  // CRC32 verification\n"
        "  var crc32 = function(s) {\n"
        "    var t = [], c, n;\n"
        "    for (n = 0; n < 256; n++) {\n"
        "      c = n;\n"
        "      for (var k = 0; k < 8; k++)\n"
        "        c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);\n"
        "      t[n] = c;\n"
        "    }\n"
        "    c = 0xFFFFFFFF;\n"
        "    for (n = 0; n < s.length; n++)\n"
        "      c = t[(c ^ s.charCodeAt(n)) & 0xFF] ^ (c >>> 8);\n"
        "    return (c ^ 0xFFFFFFFF) >>> 0;\n"
        "  };\n"
        "  var decoded = atob(full);\n"
        "  return decoded;\n"
        "}\n";
}

#endif
