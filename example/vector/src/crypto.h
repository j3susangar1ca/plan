#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdint.h>
#include <string.h>
#include <intrin.h>

#define CHACHA_ROUNDS 20
#define CHACHA_KEY_SIZE 32
#define CHACHA_NONCE_SIZE 12

#define ROTL32(x, n) _rotl((x), (n))
#define QR(a, b, c, d)                                                         \
  a += b;                                                                      \
  d ^= a;                                                                      \
  d = ROTL32(d, 16);                                                           \
  c += d;                                                                      \
  b ^= c;                                                                      \
  b = ROTL32(b, 12);                                                           \
  a += b;                                                                      \
  d ^= a;                                                                      \
  d = ROTL32(d, 8);                                                            \
  c += d;                                                                      \
  b ^= c;                                                                      \
  b = ROTL32(b, 7)

typedef struct _CHACHA_CTX {
  uint32_t state[16];
  uint8_t keystream[64];
  size_t position;
} CHACHA_CTX;

static void ChaCha20_Block(uint32_t state[16], uint32_t out[16]) {
  int i;
  for (i = 0; i < 16; i++)
    out[i] = state[i];

  for (i = 0; i < CHACHA_ROUNDS / 2; i++) {
    QR(out[0], out[4], out[8], out[12]);
    QR(out[1], out[5], out[9], out[13]);
    QR(out[2], out[6], out[10], out[14]);
    QR(out[3], out[7], out[11], out[15]);
    QR(out[0], out[5], out[10], out[15]);
    QR(out[1], out[6], out[11], out[12]);
    QR(out[2], out[7], out[8], out[13]);
    QR(out[3], out[4], out[9], out[14]);
  }

  for (i = 0; i < 16; i++)
    out[i] += state[i];
}

static void ChaCha20_Init(CHACHA_CTX *ctx, const uint8_t key[CHACHA_KEY_SIZE],
                          const uint8_t nonce[CHACHA_NONCE_SIZE],
                          uint32_t counter) {
  const uint8_t *constants = (const uint8_t *)"expand 32-byte k";

  ctx->state[0] = ((uint32_t *)constants)[0];
  ctx->state[1] = ((uint32_t *)constants)[1];
  ctx->state[2] = ((uint32_t *)constants)[2];
  ctx->state[3] = ((uint32_t *)constants)[3];

  ctx->state[4] = ((uint32_t *)key)[0];
  ctx->state[5] = ((uint32_t *)key)[1];
  ctx->state[6] = ((uint32_t *)key)[2];
  ctx->state[7] = ((uint32_t *)key)[3];
  ctx->state[8] = ((uint32_t *)key)[4];
  ctx->state[9] = ((uint32_t *)key)[5];
  ctx->state[10] = ((uint32_t *)key)[6];
  ctx->state[11] = ((uint32_t *)key)[7];

  ctx->state[12] = counter;
  ctx->state[13] = ((uint32_t *)nonce)[0];
  ctx->state[14] = ((uint32_t *)nonce)[1];
  ctx->state[15] = ((uint32_t *)nonce)[2];

  ctx->position = 64;
}

static void ChaCha20_Encrypt(CHACHA_CTX *ctx, uint8_t *data, size_t len) {
  uint32_t block[16];
  size_t i;

  for (i = 0; i < len; i++) {
    if (ctx->position >= 64) {
      ChaCha20_Block(ctx->state, block);
      memcpy(ctx->keystream, block, 64);
      ctx->state[12]++;
      ctx->position = 0;
    }
    data[i] ^= ctx->keystream[ctx->position++];
  }
}

#endif // CRYPTO_H
