#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdint.h>
#include <string.h>

// =============================================================================
// ROTL32 – MinGW compatible (no _rotl intrinsic dependency)
// =============================================================================

#ifdef _MSC_VER
#include <intrin.h>
#define ROTL32(x, n) _rotl((x), (n))
#else
#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#endif

// =============================================================================
// CONSTANTS
// =============================================================================

#define CHACHA_ROUNDS       20
#define CHACHA_KEY_SIZE     32
#define CHACHA_NONCE_SIZE   12
#define POLY1305_TAG_SIZE   16
#define POLY1305_KEY_SIZE   32

// =============================================================================
// SECURE WIPE – volatiles prevent compiler elision
// =============================================================================

static __forceinline void SecureWipe(void *ptr, size_t len) {
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len--) *p++ = 0;
}

// =============================================================================
// CHACHA20 CORE
// =============================================================================

#define QR(a, b, c, d)   \
    a += b; d ^= a; d = ROTL32(d, 16); \
    c += d; b ^= c; b = ROTL32(b, 12); \
    a += b; d ^= a; d = ROTL32(d, 8);  \
    c += d; b ^= c; b = ROTL32(b, 7)

typedef struct _CHACHA_CTX {
    uint32_t state[16];
    uint8_t  keystream[64];
    size_t   position;
} CHACHA_CTX;

static void ChaCha20_Block(uint32_t state[16], uint32_t out[16]) {
    int i;
    for (i = 0; i < 16; i++)
        out[i] = state[i];

    for (i = 0; i < CHACHA_ROUNDS / 2; i++) {
        QR(out[0], out[4], out[8],  out[12]);
        QR(out[1], out[5], out[9],  out[13]);
        QR(out[2], out[6], out[10], out[14]);
        QR(out[3], out[7], out[11], out[15]);
        QR(out[0], out[5], out[10], out[15]);
        QR(out[1], out[6], out[11], out[12]);
        QR(out[2], out[7], out[8],  out[13]);
        QR(out[3], out[4], out[9],  out[14]);
    }

    for (i = 0; i < 16; i++)
        out[i] += state[i];
}

static void ChaCha20_Init(CHACHA_CTX *ctx, const uint8_t key[CHACHA_KEY_SIZE],
                           const uint8_t nonce[CHACHA_NONCE_SIZE],
                           uint32_t counter) {
    const uint8_t *c = (const uint8_t *)"expand 32-byte k";

    ctx->state[0]  = ((uint32_t *)c)[0];
    ctx->state[1]  = ((uint32_t *)c)[1];
    ctx->state[2]  = ((uint32_t *)c)[2];
    ctx->state[3]  = ((uint32_t *)c)[3];
    ctx->state[4]  = ((uint32_t *)key)[0];
    ctx->state[5]  = ((uint32_t *)key)[1];
    ctx->state[6]  = ((uint32_t *)key)[2];
    ctx->state[7]  = ((uint32_t *)key)[3];
    ctx->state[8]  = ((uint32_t *)key)[4];
    ctx->state[9]  = ((uint32_t *)key)[5];
    ctx->state[10] = ((uint32_t *)key)[6];
    ctx->state[11] = ((uint32_t *)key)[7];
    ctx->state[12] = counter;
    ctx->state[13] = ((uint32_t *)nonce)[0];
    ctx->state[14] = ((uint32_t *)nonce)[1];
    ctx->state[15] = ((uint32_t *)nonce)[2];
    ctx->position  = 64;
}

static void ChaCha20_Encrypt(CHACHA_CTX *ctx, uint8_t *data, size_t len) {
    uint32_t block[16];
    for (size_t i = 0; i < len; i++) {
        if (ctx->position >= 64) {
            ChaCha20_Block(ctx->state, block);
            memcpy(ctx->keystream, block, 64);
            ctx->state[12]++;
            ctx->position = 0;
        }
        data[i] ^= ctx->keystream[ctx->position++];
    }
    SecureWipe(block, sizeof(block));
}

// =============================================================================
// POLY1305 MAC
// =============================================================================

typedef struct _POLY1305_CTX {
    uint32_t r[5];      // clamped key
    uint32_t h[5];      // accumulator
    uint32_t pad[4];    // final-add key
    uint8_t  buf[16];
    size_t   bufLen;
} POLY1305_CTX;

static void Poly1305_Init(POLY1305_CTX *ctx, const uint8_t key[32]) {
    // r = key[0..15] clamped
    ctx->r[0] = (((uint32_t)key[0]  | ((uint32_t)key[1]  << 8) | ((uint32_t)key[2]  << 16) | ((uint32_t)key[3]  << 24))) & 0x0FFFFFFF;
    ctx->r[1] = (((uint32_t)key[3]  >> 2) | ((uint32_t)key[4]  << 6) | ((uint32_t)key[5]  << 14) | ((uint32_t)key[6]  << 22)) & 0x0FFFFFFC;
    ctx->r[2] = (((uint32_t)key[6]  >> 4) | ((uint32_t)key[7]  << 4) | ((uint32_t)key[8]  << 12) | ((uint32_t)key[9]  << 20)) & 0x0FFFFFFC;
    ctx->r[3] = (((uint32_t)key[9]  >> 6) | ((uint32_t)key[10] << 2) | ((uint32_t)key[11] << 10) | ((uint32_t)key[12] << 18)) & 0x0FFFFFFC;
    ctx->r[4] = (((uint32_t)key[12] >> 8) | ((uint32_t)key[13])      | ((uint32_t)key[14] << 8)  | ((uint32_t)key[15] << 16)) & 0x00FFFFF;

    // pad = key[16..31]
    ctx->pad[0] = (uint32_t)key[16] | ((uint32_t)key[17] << 8) | ((uint32_t)key[18] << 16) | ((uint32_t)key[19] << 24);
    ctx->pad[1] = (uint32_t)key[20] | ((uint32_t)key[21] << 8) | ((uint32_t)key[22] << 16) | ((uint32_t)key[23] << 24);
    ctx->pad[2] = (uint32_t)key[24] | ((uint32_t)key[25] << 8) | ((uint32_t)key[26] << 16) | ((uint32_t)key[27] << 24);
    ctx->pad[3] = (uint32_t)key[28] | ((uint32_t)key[29] << 8) | ((uint32_t)key[30] << 16) | ((uint32_t)key[31] << 24);

    ctx->h[0] = ctx->h[1] = ctx->h[2] = ctx->h[3] = ctx->h[4] = 0;
    ctx->bufLen = 0;
}

static void Poly1305_ProcessBlock(POLY1305_CTX *ctx, const uint8_t *block, size_t len, uint32_t hibit) {
    uint32_t r0 = ctx->r[0], r1 = ctx->r[1], r2 = ctx->r[2], r3 = ctx->r[3], r4 = ctx->r[4];
    uint32_t s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;
    uint32_t h0 = ctx->h[0], h1 = ctx->h[1], h2 = ctx->h[2], h3 = ctx->h[3], h4 = ctx->h[4];

    // Add message block to accumulator
    uint32_t t0 = 0, t1 = 0, t2 = 0, t3 = 0;
    if (len >= 4)  t0 = (uint32_t)block[0] | ((uint32_t)block[1] << 8) | ((uint32_t)block[2] << 16) | ((uint32_t)block[3] << 24);
    if (len >= 8)  t1 = (uint32_t)block[4] | ((uint32_t)block[5] << 8) | ((uint32_t)block[6] << 16) | ((uint32_t)block[7] << 24);
    if (len >= 12) t2 = (uint32_t)block[8] | ((uint32_t)block[9] << 8) | ((uint32_t)block[10] << 16) | ((uint32_t)block[11] << 24);
    if (len >= 16) t3 = (uint32_t)block[12] | ((uint32_t)block[13] << 8) | ((uint32_t)block[14] << 16) | ((uint32_t)block[15] << 24);

    h0 += t0 & 0x3FFFFFF;
    h1 += ((t0 >> 26) | (t1 << 6)) & 0x3FFFFFF;
    h2 += ((t1 >> 20) | (t2 << 12)) & 0x3FFFFFF;
    h3 += ((t2 >> 14) | (t3 << 18)) & 0x3FFFFFF;
    h4 += (t3 >> 8) | hibit;

    // Multiply and reduce
    uint64_t d0 = (uint64_t)h0*r0 + (uint64_t)h1*s4 + (uint64_t)h2*s3 + (uint64_t)h3*s2 + (uint64_t)h4*s1;
    uint64_t d1 = (uint64_t)h0*r1 + (uint64_t)h1*r0 + (uint64_t)h2*s4 + (uint64_t)h3*s3 + (uint64_t)h4*s2;
    uint64_t d2 = (uint64_t)h0*r2 + (uint64_t)h1*r1 + (uint64_t)h2*r0 + (uint64_t)h3*s4 + (uint64_t)h4*s3;
    uint64_t d3 = (uint64_t)h0*r3 + (uint64_t)h1*r2 + (uint64_t)h2*r1 + (uint64_t)h3*r0 + (uint64_t)h4*s4;
    uint64_t d4 = (uint64_t)h0*r4 + (uint64_t)h1*r3 + (uint64_t)h2*r2 + (uint64_t)h3*r1 + (uint64_t)h4*r0;

    uint32_t c;
    c = (uint32_t)(d0 >> 26); h0 = (uint32_t)d0 & 0x3FFFFFF; d1 += c;
    c = (uint32_t)(d1 >> 26); h1 = (uint32_t)d1 & 0x3FFFFFF; d2 += c;
    c = (uint32_t)(d2 >> 26); h2 = (uint32_t)d2 & 0x3FFFFFF; d3 += c;
    c = (uint32_t)(d3 >> 26); h3 = (uint32_t)d3 & 0x3FFFFFF; d4 += c;
    c = (uint32_t)(d4 >> 26); h4 = (uint32_t)d4 & 0x3FFFFFF; h0 += c * 5;
    c = h0 >> 26; h0 &= 0x3FFFFFF; h1 += c;

    ctx->h[0] = h0; ctx->h[1] = h1; ctx->h[2] = h2; ctx->h[3] = h3; ctx->h[4] = h4;
}

static void Poly1305_Update(POLY1305_CTX *ctx, const uint8_t *data, size_t len) {
    // Fill partial buffer first
    if (ctx->bufLen) {
        size_t want = 16 - ctx->bufLen;
        if (want > len) want = len;
        memcpy(ctx->buf + ctx->bufLen, data, want);
        ctx->bufLen += want;
        data += want;
        len -= want;
        if (ctx->bufLen == 16) {
            Poly1305_ProcessBlock(ctx, ctx->buf, 16, (1 << 24));
            ctx->bufLen = 0;
        }
    }
    // Process full blocks
    while (len >= 16) {
        Poly1305_ProcessBlock(ctx, data, 16, (1 << 24));
        data += 16;
        len -= 16;
    }
    // Buffer remainder
    if (len) {
        memcpy(ctx->buf, data, len);
        ctx->bufLen = len;
    }
}

static void Poly1305_Final(POLY1305_CTX *ctx, uint8_t tag[POLY1305_TAG_SIZE]) {
    // Process remaining bytes
    if (ctx->bufLen) {
        ctx->buf[ctx->bufLen] = 1; // padding
        for (size_t i = ctx->bufLen + 1; i < 16; i++) ctx->buf[i] = 0;
        Poly1305_ProcessBlock(ctx, ctx->buf, ctx->bufLen, 0);
    }

    // Final reduction
    uint32_t h0 = ctx->h[0], h1 = ctx->h[1], h2 = ctx->h[2], h3 = ctx->h[3], h4 = ctx->h[4];
    uint32_t c;

    c = h1 >> 26; h1 &= 0x3FFFFFF; h2 += c;
    c = h2 >> 26; h2 &= 0x3FFFFFF; h3 += c;
    c = h3 >> 26; h3 &= 0x3FFFFFF; h4 += c;
    c = h4 >> 26; h4 &= 0x3FFFFFF; h0 += c * 5;
    c = h0 >> 26; h0 &= 0x3FFFFFF; h1 += c;

    // Compute h - p
    uint32_t g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3FFFFFF;
    uint32_t g1 = h1 + c; c = g1 >> 26; g1 &= 0x3FFFFFF;
    uint32_t g2 = h2 + c; c = g2 >> 26; g2 &= 0x3FFFFFF;
    uint32_t g3 = h3 + c; c = g3 >> 26; g3 &= 0x3FFFFFF;
    uint32_t g4 = h4 + c - (1 << 26);

    // Select h or g (constant-time)
    uint32_t mask = (g4 >> 31) - 1;
    h0 = (h0 & ~mask) | (g0 & mask);
    h1 = (h1 & ~mask) | (g1 & mask);
    h2 = (h2 & ~mask) | (g2 & mask);
    h3 = (h3 & ~mask) | (g3 & mask);
    h4 = (h4 & ~mask) | (g4 & mask);

    // Combine into 128-bit number and add pad
    uint64_t f0 = ((uint64_t)(h0 | (h1 << 26))) + (uint64_t)ctx->pad[0];
    uint64_t f1 = ((uint64_t)((h1 >> 6) | (h2 << 20))) + (uint64_t)ctx->pad[1];
    uint64_t f2 = ((uint64_t)((h2 >> 12) | (h3 << 14))) + (uint64_t)ctx->pad[2];
    uint64_t f3 = ((uint64_t)((h3 >> 18) | (h4 << 8))) + (uint64_t)ctx->pad[3];

    f1 += (f0 >> 32); f2 += (f1 >> 32); f3 += (f2 >> 32);

    tag[0]  = (uint8_t)f0;       tag[1]  = (uint8_t)(f0 >> 8);
    tag[2]  = (uint8_t)(f0 >> 16); tag[3] = (uint8_t)(f0 >> 24);
    tag[4]  = (uint8_t)f1;       tag[5]  = (uint8_t)(f1 >> 8);
    tag[6]  = (uint8_t)(f1 >> 16); tag[7] = (uint8_t)(f1 >> 24);
    tag[8]  = (uint8_t)f2;       tag[9]  = (uint8_t)(f2 >> 8);
    tag[10] = (uint8_t)(f2 >> 16); tag[11] = (uint8_t)(f2 >> 24);
    tag[12] = (uint8_t)f3;       tag[13] = (uint8_t)(f3 >> 8);
    tag[14] = (uint8_t)(f3 >> 16); tag[15] = (uint8_t)(f3 >> 24);

    SecureWipe(ctx, sizeof(*ctx));
}

// =============================================================================
// CHACHA20-POLY1305 AEAD
// =============================================================================

// Encrypt: generates nonce, encrypts, produces tag
static BOOL AeadEncrypt(const uint8_t key[CHACHA_KEY_SIZE],
                        const uint8_t nonce[CHACHA_NONCE_SIZE],
                        const uint8_t *aad, size_t aadLen,
                        uint8_t *plaintext, size_t ptLen,
                        uint8_t tag[POLY1305_TAG_SIZE]) {
    // Generate Poly1305 one-time key from ChaCha20 block 0
    uint8_t polyKey[64];
    CHACHA_CTX cc;
    ChaCha20_Init(&cc, key, nonce, 0);
    uint32_t block[16];
    ChaCha20_Block(cc.state, block);
    memcpy(polyKey, block, 64);
    SecureWipe(block, sizeof(block));

    // Encrypt with counter=1
    ChaCha20_Init(&cc, key, nonce, 1);
    ChaCha20_Encrypt(&cc, plaintext, ptLen);

    // Build Poly1305 MAC: AAD || pad || CT || pad || len(AAD) || len(CT)
    POLY1305_CTX pc;
    Poly1305_Init(&pc, polyKey);
    SecureWipe(polyKey, sizeof(polyKey));

    if (aad && aadLen > 0) {
        Poly1305_Update(&pc, aad, aadLen);
        uint8_t pad[16] = {0};
        size_t rem = aadLen % 16;
        if (rem) Poly1305_Update(&pc, pad, 16 - rem);
    }
    Poly1305_Update(&pc, plaintext, ptLen);
    {
        uint8_t pad[16] = {0};
        size_t rem = ptLen % 16;
        if (rem) Poly1305_Update(&pc, pad, 16 - rem);
    }

    // Lengths as little-endian 64-bit
    uint8_t lens[16];
    uint64_t aadLen64 = (uint64_t)aadLen;
    uint64_t ptLen64  = (uint64_t)ptLen;
    memcpy(lens, &aadLen64, 8);
    memcpy(lens + 8, &ptLen64, 8);
    Poly1305_Update(&pc, lens, 16);

    Poly1305_Final(&pc, tag);
    SecureWipe(&cc, sizeof(cc));
    return TRUE;
}

// Decrypt: verifies tag (constant-time), then decrypts
static BOOL AeadDecrypt(const uint8_t key[CHACHA_KEY_SIZE],
                        const uint8_t nonce[CHACHA_NONCE_SIZE],
                        const uint8_t *aad, size_t aadLen,
                        uint8_t *ciphertext, size_t ctLen,
                        const uint8_t expectedTag[POLY1305_TAG_SIZE]) {
    // Generate Poly1305 one-time key
    uint8_t polyKey[64];
    CHACHA_CTX cc;
    ChaCha20_Init(&cc, key, nonce, 0);
    uint32_t block[16];
    ChaCha20_Block(cc.state, block);
    memcpy(polyKey, block, 64);
    SecureWipe(block, sizeof(block));

    // Compute MAC over AAD || pad || CT || pad || len(AAD) || len(CT)
    POLY1305_CTX pc;
    Poly1305_Init(&pc, polyKey);
    SecureWipe(polyKey, sizeof(polyKey));

    if (aad && aadLen > 0) {
        Poly1305_Update(&pc, aad, aadLen);
        uint8_t pad[16] = {0};
        size_t rem = aadLen % 16;
        if (rem) Poly1305_Update(&pc, pad, 16 - rem);
    }
    Poly1305_Update(&pc, ciphertext, ctLen);
    {
        uint8_t pad[16] = {0};
        size_t rem = ctLen % 16;
        if (rem) Poly1305_Update(&pc, pad, 16 - rem);
    }

    uint8_t lens[16];
    uint64_t aadLen64 = (uint64_t)aadLen;
    uint64_t ctLen64  = (uint64_t)ctLen;
    memcpy(lens, &aadLen64, 8);
    memcpy(lens + 8, &ctLen64, 8);
    Poly1305_Update(&pc, lens, 16);

    uint8_t computedTag[POLY1305_TAG_SIZE];
    Poly1305_Final(&pc, computedTag);

    // Constant-time tag comparison
    uint8_t diff = 0;
    for (int i = 0; i < POLY1305_TAG_SIZE; i++)
        diff |= computedTag[i] ^ expectedTag[i];
    SecureWipe(computedTag, sizeof(computedTag));

    if (diff != 0) {
        SecureWipe(&cc, sizeof(cc));
        return FALSE;
    }

    // Tag OK → decrypt
    ChaCha20_Init(&cc, key, nonce, 1);
    ChaCha20_Encrypt(&cc, ciphertext, ctLen);
    SecureWipe(&cc, sizeof(cc));
    return TRUE;
}

// =============================================================================
// HWID KEY DERIVATION
// =============================================================================

static void DeriveKeyFromHWID(uint8_t outKey[CHACHA_KEY_SIZE]) {
    // Collect machine-specific entropy: volume serial + computer name hash
    uint8_t seed[64] = {0};

#ifdef _WIN32
    // Volume serial from C:
    DWORD serial = 0;
    typedef BOOL (WINAPI *GetVolumeInformationW_t)(LPCWSTR, LPWSTR, DWORD, LPDWORD, LPDWORD, LPDWORD, LPWSTR, DWORD);
    // Resolve dynamically to avoid import table entry
    HMODULE hK32 = GetModuleHandleW(L"kernel32.dll");
    if (hK32) {
        GetVolumeInformationW_t pGVI = (GetVolumeInformationW_t)GetProcAddress(hK32, "GetVolumeInformationW");
        if (pGVI) pGVI(L"C:\\", NULL, 0, &serial, NULL, NULL, NULL, 0);
    }
    memcpy(seed, &serial, 4);

    // Computer name
    wchar_t compName[MAX_COMPUTERNAME_LENGTH + 1] = {0};
    DWORD compSize = MAX_COMPUTERNAME_LENGTH + 1;
    GetComputerNameW(compName, &compSize);
    // Simple hash of computer name into seed bytes 4..35
    uint32_t nameHash = 0x811C9DC5;
    for (DWORD i = 0; i < compSize; i++) {
        nameHash ^= (uint8_t)(compName[i] & 0xFF);
        nameHash *= 0x01000193;
        nameHash ^= (uint8_t)(compName[i] >> 8);
        nameHash *= 0x01000193;
    }
    memcpy(seed + 4, &nameHash, 4);
#endif

    // Stretch seed into 32-byte key via repeated ChaCha20
    uint8_t nonce[CHACHA_NONCE_SIZE] = {0x48, 0x57, 0x49, 0x44, 0x4B, 0x45, 0x59, 0x30, 0x30, 0x31, 0x00, 0x00};
    CHACHA_CTX kdf;
    // Use first 32 bytes of seed as key
    ChaCha20_Init(&kdf, seed, nonce, 0);
    memset(outKey, 0, CHACHA_KEY_SIZE);
    ChaCha20_Encrypt(&kdf, outKey, CHACHA_KEY_SIZE);
    SecureWipe(&kdf, sizeof(kdf));
    SecureWipe(seed, sizeof(seed));
}

// =============================================================================
// COMPILE-TIME XOR STRING ENCRYPTION (CXorString)
// Distinct ciphertext each build via __TIME__ / __COUNTER__ seeding
// =============================================================================

namespace CXor {
    // Compile-time seed derived from build timestamp
    constexpr char ctSeed() {
        return (__TIME__[0] ^ __TIME__[1] ^ __TIME__[3] ^
                __TIME__[4] ^ __TIME__[6] ^ __TIME__[7]) | 0x01; // never zero
    }

    template <size_t N, char K, typename CharT>
    struct EncStr {
        CharT data[N];

        constexpr EncStr(const CharT *src) : data{} {
            for (size_t i = 0; i < N; ++i)
                data[i] = src[i] ^ (CharT)(K + (char)(i & 0x0F));
        }

        __forceinline CharT* decrypt() {
            volatile CharT *p = data;
            for (size_t i = 0; i < N; ++i)
                p[i] ^= (CharT)(K + (char)(i & 0x0F));
            return (CharT *)p;
        }
    };
}

// Per-build key changes because ctSeed() uses __TIME__
// std::remove_const/remove_reference strip the `const T&` returned by decltype(str[0])
// so the template parameter is a bare value type (char / wchar_t).
#include <type_traits>
#define OBFUSCATE(str)   (CXor::EncStr<sizeof(str)/sizeof(str[0]), CXor::ctSeed(), std::remove_const_t<std::remove_reference_t<decltype(str[0])>>>(str).decrypt())
#define STOBFS_A(str)    OBFUSCATE(str)
#define STOBFS_W(str)    OBFUSCATE(str)

#endif
