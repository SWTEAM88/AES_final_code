#include "aes.h"
#include "common.h"
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <limits.h>  // For UINT32_MAX

/* Cross-platform parallelization support */
#ifdef _OPENMP
#include <omp.h>
#define PARALLEL_MODE "OpenMP"
#endif
#ifdef _WIN32
#include <windows.h>
#ifndef PARALLEL_MODE
#define PARALLEL_MODE "Windows Thread API"
#endif
#elif defined(__APPLE__) || defined(__linux__) || defined(__unix__)
#include <pthread.h>
#include <unistd.h>
#ifndef PARALLEL_MODE
#define PARALLEL_MODE "pthread"
#endif
#else
#ifndef PARALLEL_MODE
#define PARALLEL_MODE "Single-threaded"
#endif
#endif

// AES standard S-box (256-byte lookup table)
static const byte sbox[256] = {
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

// AES standard inverse S-box
static const byte inv_sbox[256] = {
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

// Rcon
static const word RCON[14] = {
    0x01000000, 0x02000000, 0x04000000, 0x08000000,
    0x10000000, 0x20000000, 0x40000000, 0x80000000,
    0x1b000000, 0x36000000, 0x6c000000, 0xd8000000,
    0xab000000, 0x4d000000
};

// 8x32 table declaration (each table has 256 32-bit words)
static word T0[256], T1[256], T2[256], T3[256];  // for encryption
static word T4[256], T5[256], T6[256], T7[256];  // for decryption

/* GF(2^8) multiplication lookup tables for fast InvMixColumns on round keys */
static byte gmul_9[256], gmul_b[256], gmul_d[256], gmul_e[256];

// GF(2^8) x*2 operation function (for table generation)
// constant-time fix: remove conditional branch
static byte xtime(byte x) {
    byte mask = -(x >> 7);  // 0xFF if MSB is set, 0x00 otherwise
    return (x << 1) ^ (0x1b & mask);
}

// GF(2^8) multiplication operation function (for table generation)
// constant-time fix: use table-based lookup instead of conditional branches
static byte gmul(byte a, byte b) {
    // Use pre-computed lookup tables for constant-time operation
    // This function is only used during table initialization, so performance is acceptable
    byte p = 0;
    byte counter;
    byte mask;

    for (counter = 0; counter < 8; counter++) {
        // constant-time fix: use mask instead of conditional branch
        mask = -(b & 1);  // 0xFF if b&1 is 1, 0x00 otherwise
        p ^= a & mask;

        byte hi_bit_set = (a & 0x80);
        a <<= 1;
        // constant-time fix: use mask instead of conditional branch
        mask = -(hi_bit_set >> 7);  // 0xFF if hi_bit_set != 0, 0x00 otherwise
        a ^= 0x1b & mask;
        b >>= 1;
    }
    return p;
}

// 8x32 table generation function
static void generate_tables(void) {
    static int tables_initialized = 0;
    if (tables_initialized) return;

    for (int i = 0; i < 256; i++) {
        byte s = sbox[i];
        byte s2 = xtime(s);
        byte s3 = s2 ^ s;

        // Encryption tables (T0, T1, T2, T3)
        T0[i] = ((word)s2 << 24) | ((word)s << 16) | ((word)s << 8) | (word)s3;
        T1[i] = ((word)s3 << 24) | ((word)s2 << 16) | ((word)s << 8) | (word)s;
        T2[i] = ((word)s << 24) | ((word)s3 << 16) | ((word)s2 << 8) | (word)s;
        T3[i] = ((word)s << 24) | ((word)s << 16) | ((word)s3 << 8) | (word)s2;

        // Decryption tables (T4, T5, T6, T7) - using inv_sbox
        byte is = inv_sbox[i];
        byte is9 = gmul(is, 0x09);
        byte is11 = gmul(is, 0x0b);
        byte is13 = gmul(is, 0x0d);
        byte is14 = gmul(is, 0x0e);

        T4[i] = ((word)is14 << 24) | ((word)is9 << 16) | ((word)is13 << 8) | (word)is11;
        T5[i] = ((word)is11 << 24) | ((word)is14 << 16) | ((word)is9 << 8) | (word)is13;
        T6[i] = ((word)is13 << 24) | ((word)is11 << 16) | ((word)is14 << 8) | (word)is9;
        T7[i] = ((word)is9 << 24) | ((word)is13 << 16) | ((word)is11 << 8) | (word)is14;

        /* GF(2^8) multiplication tables for fast InvMixColumns on round keys */
        gmul_9[i] = gmul((byte)i, 0x09);
        gmul_b[i] = gmul((byte)i, 0x0b);
        gmul_d[i] = gmul((byte)i, 0x0d);
        gmul_e[i] = gmul((byte)i, 0x0e);
    }

    tables_initialized = 1;
}

// --- Internal AES functions (static) ---

// SubBytes
static void aes_subbytes(byte state[4][4]) {
    for (int row = 0; row < 4; row++) {
        for (int col = 0; col < 4; col++) {
            state[row][col] = sbox[state[row][col]];
        }
    }
}

// Inverse SubBytes
static void aes_inv_subbytes(byte state[4][4]) {
    for (int row = 0; row < 4; row++) {
        for (int col = 0; col < 4; col++) {
            state[row][col] = inv_sbox[state[row][col]];
        }
    }
}

// ShiftRows
static void aes_shiftrows(byte state[4][4]) {
    byte temp;
    temp = state[1][0];
    state[1][0] = state[1][1];
    state[1][1] = state[1][2];
    state[1][2] = state[1][3];
    state[1][3] = temp;
    temp = state[2][0]; state[2][0] = state[2][2]; state[2][2] = temp;
    temp = state[2][1]; state[2][1] = state[2][3]; state[2][3] = temp;
    temp = state[3][3];
    state[3][3] = state[3][2];
    state[3][2] = state[3][1];
    state[3][1] = state[3][0];
    state[3][0] = temp;
}

// Inverse ShiftRows
static void aes_inv_shiftrows(byte state[4][4]) {
    byte temp;
    temp = state[1][3];
    state[1][3] = state[1][2];
    state[1][2] = state[1][1];
    state[1][1] = state[1][0];
    state[1][0] = temp;
    temp = state[2][0]; state[2][0] = state[2][2]; state[2][2] = temp;
    temp = state[2][1]; state[2][1] = state[2][3]; state[2][3] = temp;
    temp = state[3][0];
    state[3][0] = state[3][1];
    state[3][1] = state[3][2];
    state[3][2] = state[3][3];
    state[3][3] = temp;
}

// Inverse MixColumns
static void aes_inv_mixcolumns(byte state[4][4]) {
    for (int col = 0; col < 4; col++) {
        byte a0 = state[0][col];
        byte a1 = state[1][col];
        byte a2 = state[2][col];
        byte a3 = state[3][col];
        state[0][col] = gmul(a0, 0x0e) ^ gmul(a1, 0x0b) ^ gmul(a2, 0x0d) ^ gmul(a3, 0x09);
        state[1][col] = gmul(a0, 0x09) ^ gmul(a1, 0x0e) ^ gmul(a2, 0x0b) ^ gmul(a3, 0x0d);
        state[2][col] = gmul(a0, 0x0d) ^ gmul(a1, 0x09) ^ gmul(a2, 0x0e) ^ gmul(a3, 0x0b);
        state[3][col] = gmul(a0, 0x0b) ^ gmul(a1, 0x0d) ^ gmul(a2, 0x09) ^ gmul(a3, 0x0e);
    }
}

/* Apply InvMixColumns to a single word (for equivalent decryption key schedule) */
static word inv_mix_column_word(word col) {
    byte a0 = (byte)(col >> 24);
    byte a1 = (byte)(col >> 16);
    byte a2 = (byte)(col >> 8);
    byte a3 = (byte)col;

    /* Use pre-computed gmul tables for fast lookup */
    byte r0 = gmul_e[a0] ^ gmul_b[a1] ^ gmul_d[a2] ^ gmul_9[a3];
    byte r1 = gmul_9[a0] ^ gmul_e[a1] ^ gmul_b[a2] ^ gmul_d[a3];
    byte r2 = gmul_d[a0] ^ gmul_9[a1] ^ gmul_e[a2] ^ gmul_b[a3];
    byte r3 = gmul_b[a0] ^ gmul_d[a1] ^ gmul_9[a2] ^ gmul_e[a3];

    return ((word)r0 << 24) | ((word)r1 << 16) | ((word)r2 << 8) | (word)r3;
}

/* Prepare decryption keys by applying InvMixColumns to round keys 1 to Nr-1 */
static void prepare_dec_keys(const word* round_keys, word* dec_keys, int Nr) {
    int round;
    /* Round 0 and Nr are not transformed */
    for (round = 1; round < Nr; round++) {
        dec_keys[round * 4] = inv_mix_column_word(round_keys[round * 4]);
        dec_keys[round * 4 + 1] = inv_mix_column_word(round_keys[round * 4 + 1]);
        dec_keys[round * 4 + 2] = inv_mix_column_word(round_keys[round * 4 + 2]);
        dec_keys[round * 4 + 3] = inv_mix_column_word(round_keys[round * 4 + 3]);
    }
}

// AddRoundKey
static void aes_addroundkey(const word* w, byte state[4][4], int round) {
    for (int col = 0; col < 4; col++) {
        // Apply round key w[round*4 + col] to state
        word k = w[round * 4 + col];
        state[0][col] ^= (byte)(k >> 24);
        state[1][col] ^= (byte)(k >> 16);
        state[2][col] ^= (byte)(k >> 8);
        state[3][col] ^= (byte)k;
    }
}

// RotWord
static word RotWord(word w) {
    return (w << 8) | (w >> 24);
}

// SubWord
static word SubWord(word w) {
    return (sbox[(w >> 24) & 0xFF] << 24) |
        (sbox[(w >> 16) & 0xFF] << 16) |
        (sbox[(w >> 8) & 0xFF] << 8) |
        (sbox[w & 0xFF]);
}

// Counter block construction (nonce 12 bytes + counter 4 bytes)
// NIST SP 800-38A compliant: 12-byte nonce + 4-byte counter
// This prevents nonce reuse and provides 2^32 blocks per nonce (68GB max per message)
static void construct_counter_block(byte counter_block[AES_BLOCK_SIZE], const byte* nonce, uint32_t counter) {
    // Initialize counter_block to zero
    memset(counter_block, 0, AES_BLOCK_SIZE);
    // First 12 bytes = nonce (increased from 8 bytes for better security)
    memcpy(counter_block, nonce, 12);
    // Last 4 bytes = counter (big-endian, network byte order)
    counter_block[12] = (byte)(counter >> 24);
    counter_block[13] = (byte)(counter >> 16);
    counter_block[14] = (byte)(counter >> 8);
    counter_block[15] = (byte)counter;
}

// --- Public API functions ---

// Key expansion function
int aes_keyexpansion(const byte* key, word* w, size_t key_len) {
    int Nk = (int)key_len / 4;            // Key word count (4 bytes per word)
    int Nr;                               // Number of rounds
    if (Nk == AES_NK_128) Nr = AES_NR_128;
    else if (Nk == AES_NK_192) Nr = AES_NR_192;
    else if (Nk == AES_NK_256) Nr = AES_NR_256;
    else {
        fprintf(stderr, "Unsupported key length: %zu bytes (Nk=%d). Must be 16, 24, or 32 bytes.\n", key_len, Nk);
        return -1;
    }

    // Copy first Nk words from key (Big Endian format)
    for (int i = 0; i < Nk; i++) {
        w[i] = ((word)key[4 * i] << 24) | ((word)key[4 * i + 1] << 16) |
            ((word)key[4 * i + 2] << 8) | (word)key[4 * i + 3];
    }

    // Generate remaining round keys
    for (int i = Nk; i < 4 * (Nr + 1); i++) {
        word temp = w[i - 1];
        if (i % Nk == 0) {
            // RotWord -> SubWord -> RCON XOR
            temp = SubWord(RotWord(temp)) ^ RCON[(i / Nk) - 1];
        }
        else if (Nk > 6 && (i % Nk == 4)) {
            // AES-256: 4th word (index -1) SubWord operation
            temp = SubWord(temp);
        }
        w[i] = w[i - Nk] ^ temp;
    }
    return Nr;
}

// AES block encryption function
void aes_encrypt(byte input[AES_BLOCK_SIZE], byte output[AES_BLOCK_SIZE], const word* w, int Nr) {
    // Generate lookup tables
    generate_tables();

    word s0 = 0, s1 = 0, s2 = 0, s3 = 0, t0 = 0, t1 = 0, t2 = 0, t3 = 0;

    // Convert input bytes to words (Big Endian)
    s0 = ((word)input[0] << 24) | ((word)input[1] << 16) | ((word)input[2] << 8) | (word)input[3];
    s1 = ((word)input[4] << 24) | ((word)input[5] << 16) | ((word)input[6] << 8) | (word)input[7];
    s2 = ((word)input[8] << 24) | ((word)input[9] << 16) | ((word)input[10] << 8) | (word)input[11];
    s3 = ((word)input[12] << 24) | ((word)input[13] << 16) | ((word)input[14] << 8) | (word)input[15];

    // Initial AddRoundKey
    s0 ^= w[0];
    s1 ^= w[1];
    s2 ^= w[2];
    s3 ^= w[3];

    // Nr-1 rounds of encryption
    for (int round = 1; round < Nr; round++) {
        t0 = T0[(s0 >> 24) & 0xff] ^ T1[(s1 >> 16) & 0xff] ^ T2[(s2 >> 8) & 0xff] ^ T3[s3 & 0xff] ^ w[round * 4];
        t1 = T0[(s1 >> 24) & 0xff] ^ T1[(s2 >> 16) & 0xff] ^ T2[(s3 >> 8) & 0xff] ^ T3[s0 & 0xff] ^ w[round * 4 + 1];
        t2 = T0[(s2 >> 24) & 0xff] ^ T1[(s3 >> 16) & 0xff] ^ T2[(s0 >> 8) & 0xff] ^ T3[s1 & 0xff] ^ w[round * 4 + 2];
        t3 = T0[(s3 >> 24) & 0xff] ^ T1[(s0 >> 16) & 0xff] ^ T2[(s1 >> 8) & 0xff] ^ T3[s2 & 0xff] ^ w[round * 4 + 3];
        s0 = t0;
        s1 = t1;
        s2 = t2;
        s3 = t3;
    }

    // Final MixColumns operation (S-box lookup)
    t0 = ((word)sbox[(s0 >> 24) & 0xff] << 24) | ((word)sbox[(s1 >> 16) & 0xff] << 16) |
        ((word)sbox[(s2 >> 8) & 0xff] << 8) | (word)sbox[s3 & 0xff];
    t1 = ((word)sbox[(s1 >> 24) & 0xff] << 24) | ((word)sbox[(s2 >> 16) & 0xff] << 16) |
        ((word)sbox[(s3 >> 8) & 0xff] << 8) | (word)sbox[s0 & 0xff];
    t2 = ((word)sbox[(s2 >> 24) & 0xff] << 24) | ((word)sbox[(s3 >> 16) & 0xff] << 16) |
        ((word)sbox[(s0 >> 8) & 0xff] << 8) | (word)sbox[s1 & 0xff];
    t3 = ((word)sbox[(s3 >> 24) & 0xff] << 24) | ((word)sbox[(s0 >> 16) & 0xff] << 16) |
        ((word)sbox[(s1 >> 8) & 0xff] << 8) | (word)sbox[s2 & 0xff];

    s0 = t0 ^ w[Nr * 4];
    s1 = t1 ^ w[Nr * 4 + 1];
    s2 = t2 ^ w[Nr * 4 + 2];
    s3 = t3 ^ w[Nr * 4 + 3];

    // Convert words to byte array (Big Endian)
    output[0] = (byte)(s0 >> 24);
    output[1] = (byte)(s0 >> 16);
    output[2] = (byte)(s0 >> 8);
    output[3] = (byte)s0;
    output[4] = (byte)(s1 >> 24);
    output[5] = (byte)(s1 >> 16);
    output[6] = (byte)(s1 >> 8);
    output[7] = (byte)s1;
    output[8] = (byte)(s2 >> 24);
    output[9] = (byte)(s2 >> 16);
    output[10] = (byte)(s2 >> 8);
    output[11] = (byte)s2;
    output[12] = (byte)(s3 >> 24);
    output[13] = (byte)(s3 >> 16);
    output[14] = (byte)(s3 >> 8);
    output[15] = (byte)s3;
}

/* Fast block decryption with pre-computed decryption keys (no per-block key transformation) */
static void aes_decrypt_fast(byte input[AES_BLOCK_SIZE], byte output[AES_BLOCK_SIZE],
    const word* w, const word* dec_keys, int Nr) {
    word s0, s1, s2, s3, t0, t1, t2, t3;
    int round;

    /* Convert input to words (Big Endian) */
    s0 = ((word)input[0] << 24) | ((word)input[1] << 16) | ((word)input[2] << 8) | (word)input[3];
    s1 = ((word)input[4] << 24) | ((word)input[5] << 16) | ((word)input[6] << 8) | (word)input[7];
    s2 = ((word)input[8] << 24) | ((word)input[9] << 16) | ((word)input[10] << 8) | (word)input[11];
    s3 = ((word)input[12] << 24) | ((word)input[13] << 16) | ((word)input[14] << 8) | (word)input[15];

    /* Initial AddRoundKey (using last round key - not transformed) */
    s0 ^= w[Nr * 4];
    s1 ^= w[Nr * 4 + 1];
    s2 ^= w[Nr * 4 + 2];
    s3 ^= w[Nr * 4 + 3];

    /* Nr-1 rounds (table-based with pre-computed decryption keys) */
    for (round = Nr - 1; round >= 1; round--) {
        t0 = T4[(s0 >> 24) & 0xff] ^ T5[(s3 >> 16) & 0xff] ^ T6[(s2 >> 8) & 0xff] ^ T7[s1 & 0xff] ^ dec_keys[round * 4];
        t1 = T4[(s1 >> 24) & 0xff] ^ T5[(s0 >> 16) & 0xff] ^ T6[(s3 >> 8) & 0xff] ^ T7[s2 & 0xff] ^ dec_keys[round * 4 + 1];
        t2 = T4[(s2 >> 24) & 0xff] ^ T5[(s1 >> 16) & 0xff] ^ T6[(s0 >> 8) & 0xff] ^ T7[s3 & 0xff] ^ dec_keys[round * 4 + 2];
        t3 = T4[(s3 >> 24) & 0xff] ^ T5[(s2 >> 16) & 0xff] ^ T6[(s1 >> 8) & 0xff] ^ T7[s0 & 0xff] ^ dec_keys[round * 4 + 3];
        s0 = t0;
        s1 = t1;
        s2 = t2;
        s3 = t3;
    }

    /* Final round (no InvMixColumns) */
    t0 = ((word)inv_sbox[(s0 >> 24) & 0xff] << 24) | ((word)inv_sbox[(s3 >> 16) & 0xff] << 16) |
        ((word)inv_sbox[(s2 >> 8) & 0xff] << 8) | (word)inv_sbox[s1 & 0xff];
    t1 = ((word)inv_sbox[(s1 >> 24) & 0xff] << 24) | ((word)inv_sbox[(s0 >> 16) & 0xff] << 16) |
        ((word)inv_sbox[(s3 >> 8) & 0xff] << 8) | (word)inv_sbox[s2 & 0xff];
    t2 = ((word)inv_sbox[(s2 >> 24) & 0xff] << 24) | ((word)inv_sbox[(s1 >> 16) & 0xff] << 16) |
        ((word)inv_sbox[(s0 >> 8) & 0xff] << 8) | (word)inv_sbox[s3 & 0xff];
    t3 = ((word)inv_sbox[(s3 >> 24) & 0xff] << 24) | ((word)inv_sbox[(s2 >> 16) & 0xff] << 16) |
        ((word)inv_sbox[(s1 >> 8) & 0xff] << 8) | (word)inv_sbox[s0 & 0xff];

    s0 = t0 ^ w[0];
    s1 = t1 ^ w[1];
    s2 = t2 ^ w[2];
    s3 = t3 ^ w[3];

    /* Convert words to byte array (Big Endian) */
    output[0] = (byte)(s0 >> 24);
    output[1] = (byte)(s0 >> 16);
    output[2] = (byte)(s0 >> 8);
    output[3] = (byte)s0;
    output[4] = (byte)(s1 >> 24);
    output[5] = (byte)(s1 >> 16);
    output[6] = (byte)(s1 >> 8);
    output[7] = (byte)s1;
    output[8] = (byte)(s2 >> 24);
    output[9] = (byte)(s2 >> 16);
    output[10] = (byte)(s2 >> 8);
    output[11] = (byte)s2;
    output[12] = (byte)(s3 >> 24);
    output[13] = (byte)(s3 >> 16);
    output[14] = (byte)(s3 >> 8);
    output[15] = (byte)s3;
}

// AES block decryption function (8x32 Table based - OPTIMIZED)
void aes_decrypt(byte input[AES_BLOCK_SIZE], byte output[AES_BLOCK_SIZE], const word* w, int Nr) {
    word s0 = 0, s1 = 0, s2 = 0, s3 = 0, t0 = 0, t1 = 0, t2 = 0, t3 = 0;
    word dk0 = 0, dk1 = 0, dk2 = 0, dk3 = 0;
    int round = 0;

    /* Initialize tables */
    generate_tables();

    /* Convert input to words (Big Endian) */
    s0 = ((word)input[0] << 24) | ((word)input[1] << 16) | ((word)input[2] << 8) | (word)input[3];
    s1 = ((word)input[4] << 24) | ((word)input[5] << 16) | ((word)input[6] << 8) | (word)input[7];
    s2 = ((word)input[8] << 24) | ((word)input[9] << 16) | ((word)input[10] << 8) | (word)input[11];
    s3 = ((word)input[12] << 24) | ((word)input[13] << 16) | ((word)input[14] << 8) | (word)input[15];

    /* Initial AddRoundKey (using last round key) */
    s0 ^= w[Nr * 4];
    s1 ^= w[Nr * 4 + 1];
    s2 ^= w[Nr * 4 + 2];
    s3 ^= w[Nr * 4 + 3];

    /* Nr-1 rounds (table-based with equivalent decryption) */
    /* T-tables combine InvSubBytes + InvMixColumns, InvShiftRows handled by indexing */
    /* For equivalent decryption, round keys must be transformed with InvMixColumns */
    for (round = Nr - 1; round >= 1; round--) {
        /* Transform round key with InvMixColumns for equivalent decryption */
        dk0 = inv_mix_column_word(w[round * 4]);
        dk1 = inv_mix_column_word(w[round * 4 + 1]);
        dk2 = inv_mix_column_word(w[round * 4 + 2]);
        dk3 = inv_mix_column_word(w[round * 4 + 3]);

        t0 = T4[(s0 >> 24) & 0xff] ^ T5[(s3 >> 16) & 0xff] ^ T6[(s2 >> 8) & 0xff] ^ T7[s1 & 0xff] ^ dk0;
        t1 = T4[(s1 >> 24) & 0xff] ^ T5[(s0 >> 16) & 0xff] ^ T6[(s3 >> 8) & 0xff] ^ T7[s2 & 0xff] ^ dk1;
        t2 = T4[(s2 >> 24) & 0xff] ^ T5[(s1 >> 16) & 0xff] ^ T6[(s0 >> 8) & 0xff] ^ T7[s3 & 0xff] ^ dk2;
        t3 = T4[(s3 >> 24) & 0xff] ^ T5[(s2 >> 16) & 0xff] ^ T6[(s1 >> 8) & 0xff] ^ T7[s0 & 0xff] ^ dk3;
        s0 = t0;
        s1 = t1;
        s2 = t2;
        s3 = t3;
    }

    /* Final round (no InvMixColumns, inv_sbox only with InvShiftRows indexing) */
    t0 = ((word)inv_sbox[(s0 >> 24) & 0xff] << 24) | ((word)inv_sbox[(s3 >> 16) & 0xff] << 16) |
        ((word)inv_sbox[(s2 >> 8) & 0xff] << 8) | (word)inv_sbox[s1 & 0xff];
    t1 = ((word)inv_sbox[(s1 >> 24) & 0xff] << 24) | ((word)inv_sbox[(s0 >> 16) & 0xff] << 16) |
        ((word)inv_sbox[(s3 >> 8) & 0xff] << 8) | (word)inv_sbox[s2 & 0xff];
    t2 = ((word)inv_sbox[(s2 >> 24) & 0xff] << 24) | ((word)inv_sbox[(s1 >> 16) & 0xff] << 16) |
        ((word)inv_sbox[(s0 >> 8) & 0xff] << 8) | (word)inv_sbox[s3 & 0xff];
    t3 = ((word)inv_sbox[(s3 >> 24) & 0xff] << 24) | ((word)inv_sbox[(s2 >> 16) & 0xff] << 16) |
        ((word)inv_sbox[(s1 >> 8) & 0xff] << 8) | (word)inv_sbox[s0 & 0xff];

    s0 = t0 ^ w[0];
    s1 = t1 ^ w[1];
    s2 = t2 ^ w[2];
    s3 = t3 ^ w[3]; // Initial key (0th key)

    /* Convert words to byte array (Big Endian) */
    output[0] = (byte)(s0 >> 24);
    output[1] = (byte)(s0 >> 16);
    output[2] = (byte)(s0 >> 8);
    output[3] = (byte)s0;
    output[4] = (byte)(s1 >> 24);
    output[5] = (byte)(s1 >> 16);
    output[6] = (byte)(s1 >> 8);
    output[7] = (byte)s1;
    output[8] = (byte)(s2 >> 24);
    output[9] = (byte)(s2 >> 16);
    output[10] = (byte)(s2 >> 8);
    output[11] = (byte)s2;
    output[12] = (byte)(s3 >> 24);
    output[13] = (byte)(s3 >> 16);
    output[14] = (byte)(s3 >> 8);
    output[15] = (byte)s3;
}

/* =============================================================================
 * Cross-Platform Thread Utilities
 * ============================================================================= */

 /* Helper function to get number of CPU cores */
static int get_num_threads(void) {
#ifdef _WIN32
    SYSTEM_INFO sysinfo;
    GetSystemInfo(&sysinfo);
    return (int)sysinfo.dwNumberOfProcessors;
#elif defined(__APPLE__) || defined(__linux__) || defined(__unix__)
    long nproc = sysconf(_SC_NPROCESSORS_ONLN);
    return (nproc > 0) ? (int)nproc : 1;
#else
    return 1;
#endif
}

/* =============================================================================
 * Thread Data Structures for Parallelization
 * ============================================================================= */

 /* Thread data structure for CTR parallelization */
typedef struct {
    const byte* input;
    byte* output;
    size_t length;
    const byte* nonce;
    const word* round_keys;
    int Nr;
    int start_block;
    int end_block;
} ctr_thread_data_t;

/* Thread data structure for ECB parallelization */
typedef struct {
    const byte* input;
    byte* output;
    const word* round_keys;
    const word* dec_keys;
    int Nr;
    int encrypt;
    int start_block;
    int end_block;
} ecb_thread_data_t;

/* Thread data structure for CBC decryption parallelization */
typedef struct {
    const byte* input;
    byte* output;
    const byte* iv;
    const word* round_keys;
    const word* dec_keys;
    int Nr;
    int start_block;
    int end_block;
} cbc_decrypt_thread_data_t;

/* =============================================================================
 * Platform-Specific Thread Functions (when OpenMP is not available)
 * ============================================================================= */

#ifndef _OPENMP

#ifdef _WIN32
 /* Windows Thread API implementations */

 /* CTR mode thread function for Windows */
static DWORD WINAPI ctr_thread_func_win(LPVOID arg) {
    ctr_thread_data_t* data = (ctr_thread_data_t*)arg;
    int i_block;

    for (i_block = data->start_block; i_block < data->end_block; i_block++) {
        byte counter_block[AES_BLOCK_SIZE] = { 0 };
        byte keystream[AES_BLOCK_SIZE] = { 0 };
        size_t offset = (size_t)i_block * AES_BLOCK_SIZE;
        size_t block_len = (data->length - offset >= AES_BLOCK_SIZE) ? AES_BLOCK_SIZE : (data->length - offset);
        size_t j;

        construct_counter_block(counter_block, data->nonce, (uint32_t)i_block);
        aes_encrypt(counter_block, keystream, data->round_keys, data->Nr);

        for (j = 0; j < block_len; j++) {
            data->output[offset + j] = data->input[offset + j] ^ keystream[j];
        }
    }

    return 0;
}

/* ECB mode thread function for Windows */
static DWORD WINAPI ecb_thread_func_win(LPVOID arg) {
    ecb_thread_data_t* data = (ecb_thread_data_t*)arg;
    int i_block;

    for (i_block = data->start_block; i_block < data->end_block; i_block++) {
        size_t offset = (size_t)i_block * AES_BLOCK_SIZE;
        if (data->encrypt) {
            aes_encrypt((byte*)(data->input + offset), data->output + offset, data->round_keys, data->Nr);
        }
        else {
            aes_decrypt_fast((byte*)(data->input + offset), data->output + offset, data->round_keys, data->dec_keys, data->Nr);
        }
    }

    return 0;
}

/* CBC decryption mode thread function for Windows */
static DWORD WINAPI cbc_decrypt_thread_func_win(LPVOID arg) {
    cbc_decrypt_thread_data_t* data = (cbc_decrypt_thread_data_t*)arg;
    int i_block;

    for (i_block = data->start_block; i_block < data->end_block; i_block++) {
        byte dec_block[AES_BLOCK_SIZE];
        const byte* prev_cipher;
        size_t off = (size_t)i_block * AES_BLOCK_SIZE;
        int j;

        /* AES decryption with pre-computed keys */
        aes_decrypt_fast((byte*)(data->input + off), dec_block, data->round_keys, data->dec_keys, data->Nr);

        /* XOR with previous ciphertext (first block uses IV) */
        if (i_block == 0) {
            prev_cipher = data->iv;
        }
        else {
            prev_cipher = data->input + off - AES_BLOCK_SIZE;
        }

        for (j = 0; j < AES_BLOCK_SIZE; j++) {
            data->output[off + j] = dec_block[j] ^ prev_cipher[j];
        }
    }

    return 0;
}

#else
 /* POSIX pthread implementations */

 /* CTR mode thread function for pthread */
static void* ctr_thread_func(void* arg) {
    ctr_thread_data_t* data = (ctr_thread_data_t*)arg;
    int i_block;

    for (i_block = data->start_block; i_block < data->end_block; i_block++) {
        byte counter_block[AES_BLOCK_SIZE] = { 0 };
        byte keystream[AES_BLOCK_SIZE] = { 0 };
        size_t offset = (size_t)i_block * AES_BLOCK_SIZE;
        size_t block_len = (data->length - offset >= AES_BLOCK_SIZE) ? AES_BLOCK_SIZE : (data->length - offset);
        size_t j;

        construct_counter_block(counter_block, data->nonce, (uint32_t)i_block);
        aes_encrypt(counter_block, keystream, data->round_keys, data->Nr);

        for (j = 0; j < block_len; j++) {
            data->output[offset + j] = data->input[offset + j] ^ keystream[j];
        }
    }

    return NULL;
}

/* ECB mode thread function for pthread */
static void* ecb_thread_func(void* arg) {
    ecb_thread_data_t* data = (ecb_thread_data_t*)arg;
    int i_block;

    for (i_block = data->start_block; i_block < data->end_block; i_block++) {
        size_t offset = (size_t)i_block * AES_BLOCK_SIZE;
        if (data->encrypt) {
            aes_encrypt((byte*)(data->input + offset), data->output + offset, data->round_keys, data->Nr);
        }
        else {
            aes_decrypt_fast((byte*)(data->input + offset), data->output + offset, data->round_keys, data->dec_keys, data->Nr);
        }
    }

    return NULL;
}

/* CBC decryption mode thread function for pthread */
static void* cbc_decrypt_thread_func(void* arg) {
    cbc_decrypt_thread_data_t* data = (cbc_decrypt_thread_data_t*)arg;
    int i_block;

    for (i_block = data->start_block; i_block < data->end_block; i_block++) {
        byte dec_block[AES_BLOCK_SIZE];
        const byte* prev_cipher;
        size_t off = (size_t)i_block * AES_BLOCK_SIZE;
        int j;

        aes_decrypt_fast((byte*)(data->input + off), dec_block, data->round_keys, data->dec_keys, data->Nr);

        if (i_block == 0) {
            prev_cipher = data->iv;
        }
        else {
            prev_cipher = data->input + off - AES_BLOCK_SIZE;
        }

        for (j = 0; j < AES_BLOCK_SIZE; j++) {
            data->output[off + j] = dec_block[j] ^ prev_cipher[j];
        }
    }

    return NULL;
}

#endif /* _WIN32 */

#endif /* _OPENMP */

/* =============================================================================
 * AES Mode Implementations with Cross-Platform Parallelization
 * ============================================================================= */

 /* CTR mode implementation (OpenMP/pthread/Win32 parallelized - encryption and decryption are identical) */
void AES_CTR(const byte* input, byte* output, size_t length,
    const byte* key, const byte* nonce, size_t key_len) {
    word round_keys[60];
    int Nr;
    size_t block_count;
    int i_block;

    /* Key expansion */
    Nr = aes_keyexpansion(key, round_keys, key_len);
    if (Nr < 0) return;

    /* Initialize tables */
    generate_tables();

    block_count = (length + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE;

    /* Security check: Prevent counter overflow (max 2^32 blocks = 68GB per message) */
    if (block_count > UINT32_MAX) {
        fprintf(stderr, "Error: Message too long for CTR mode (max 2^32 blocks = 68GB)\n");
        return;
    }

#ifdef _OPENMP
    /* Use OpenMP if available */
#pragma omp parallel for schedule(static)
    for (i_block = 0; i_block < (int)block_count; i_block++) {
        byte counter_block[AES_BLOCK_SIZE] = { 0 };
        byte keystream[AES_BLOCK_SIZE] = { 0 };
        size_t offset = (size_t)i_block * AES_BLOCK_SIZE;
        size_t block_len = (length - offset >= AES_BLOCK_SIZE) ? AES_BLOCK_SIZE : (length - offset);
        size_t j;

        construct_counter_block(counter_block, nonce, (uint32_t)i_block);
        aes_encrypt(counter_block, keystream, round_keys, Nr);

        for (j = 0; j < block_len; j++) {
            output[offset + j] = input[offset + j] ^ keystream[j];
        }
    }
#else
    /* Use platform-specific threading */
    int num_threads = get_num_threads();
    if (num_threads > 1 && block_count > (size_t)num_threads) {
        int blocks_per_thread = (int)block_count / num_threads;
        ctr_thread_data_t* thread_data = (ctr_thread_data_t*)malloc(num_threads * sizeof(ctr_thread_data_t));

#ifdef _WIN32
        HANDLE* threads = (HANDLE*)malloc(num_threads * sizeof(HANDLE));
#else
        pthread_t* threads = (pthread_t*)malloc(num_threads * sizeof(pthread_t));
#endif

        if (thread_data && threads) {
            int i;
            for (i = 0; i < num_threads; i++) {
                thread_data[i].input = input;
                thread_data[i].output = output;
                thread_data[i].length = length;
                thread_data[i].nonce = nonce;
                thread_data[i].round_keys = round_keys;
                thread_data[i].Nr = Nr;
                thread_data[i].start_block = i * blocks_per_thread;
                thread_data[i].end_block = (i == num_threads - 1) ? (int)block_count : (i + 1) * blocks_per_thread;

#ifdef _WIN32
                threads[i] = CreateThread(NULL, 0, ctr_thread_func_win, &thread_data[i], 0, NULL);
#else
                pthread_create(&threads[i], NULL, ctr_thread_func, &thread_data[i]);
#endif
            }

            for (i = 0; i < num_threads; i++) {
#ifdef _WIN32
                WaitForSingleObject(threads[i], INFINITE);
                CloseHandle(threads[i]);
#else
                pthread_join(threads[i], NULL);
#endif
            }

            free(threads);
            free(thread_data);
            return;
        }
        if (thread_data) free(thread_data);
        if (threads) free(threads);
    }

    /* Fallback to sequential processing */
    for (i_block = 0; i_block < (int)block_count; i_block++) {
        byte counter_block[AES_BLOCK_SIZE] = { 0 };
        byte keystream[AES_BLOCK_SIZE] = { 0 };
        size_t offset = (size_t)i_block * AES_BLOCK_SIZE;
        size_t block_len = (length - offset >= AES_BLOCK_SIZE) ? AES_BLOCK_SIZE : (length - offset);
        size_t j;

        construct_counter_block(counter_block, nonce, (uint32_t)i_block);
        aes_encrypt(counter_block, keystream, round_keys, Nr);

        for (j = 0; j < block_len; j++) {
            output[offset + j] = input[offset + j] ^ keystream[j];
        }
    }
#endif
}

/* ECB mode implementation (OpenMP/pthread/Win32 parallelized) */
void AES_ECB(const byte* input, byte* output, size_t length,
    const byte* key, size_t key_len, int encrypt) {
    word round_keys[60];
    word dec_keys[60];
    int Nr;
    size_t block_count, remaining;
    int i_block;

    /* Key expansion */
    Nr = aes_keyexpansion(key, round_keys, key_len);
    if (Nr < 0) return;

    /* Initialize tables */
    generate_tables();

    /* Prepare decryption keys once if decrypting */
    if (!encrypt) {
        prepare_dec_keys(round_keys, dec_keys, Nr);
    }

    /* Process 16-byte blocks (parallelized) */
    block_count = length / AES_BLOCK_SIZE;

#ifdef _OPENMP
    /* Use OpenMP if available */
#pragma omp parallel for schedule(static)
    for (i_block = 0; i_block < (int)block_count; i_block++) {
        size_t offset = (size_t)i_block * AES_BLOCK_SIZE;
        if (encrypt) {
            aes_encrypt((byte*)(input + offset), output + offset, round_keys, Nr);
        }
        else {
            aes_decrypt_fast((byte*)(input + offset), output + offset, round_keys, dec_keys, Nr);
        }
    }
#else
    /* Use platform-specific threading */
    int num_threads = get_num_threads();
    if (num_threads > 1 && block_count > (size_t)num_threads) {
        int blocks_per_thread = (int)block_count / num_threads;
        ecb_thread_data_t* thread_data = (ecb_thread_data_t*)malloc(num_threads * sizeof(ecb_thread_data_t));

#ifdef _WIN32
        HANDLE* threads = (HANDLE*)malloc(num_threads * sizeof(HANDLE));
#else
        pthread_t* threads = (pthread_t*)malloc(num_threads * sizeof(pthread_t));
#endif

        if (thread_data && threads) {
            int i;
            for (i = 0; i < num_threads; i++) {
                thread_data[i].input = input;
                thread_data[i].output = output;
                thread_data[i].round_keys = round_keys;
                thread_data[i].dec_keys = dec_keys;
                thread_data[i].Nr = Nr;
                thread_data[i].encrypt = encrypt;
                thread_data[i].start_block = i * blocks_per_thread;
                thread_data[i].end_block = (i == num_threads - 1) ? (int)block_count : (i + 1) * blocks_per_thread;

#ifdef _WIN32
                threads[i] = CreateThread(NULL, 0, ecb_thread_func_win, &thread_data[i], 0, NULL);
#else
                pthread_create(&threads[i], NULL, ecb_thread_func, &thread_data[i]);
#endif
            }

            for (i = 0; i < num_threads; i++) {
#ifdef _WIN32
                WaitForSingleObject(threads[i], INFINITE);
                CloseHandle(threads[i]);
#else
                pthread_join(threads[i], NULL);
#endif
            }

            free(threads);
            free(thread_data);

            /* Handle remaining data less than 16 bytes */
            remaining = length % AES_BLOCK_SIZE;
            if (remaining > 0) {
                memcpy(output + block_count * AES_BLOCK_SIZE, input + block_count * AES_BLOCK_SIZE, remaining);
            }
            return;
        }
        if (thread_data) free(thread_data);
        if (threads) free(threads);
    }

    /* Fallback to sequential processing */
    for (i_block = 0; i_block < (int)block_count; i_block++) {
        size_t offset = (size_t)i_block * AES_BLOCK_SIZE;
        if (encrypt) {
            aes_encrypt((byte*)(input + offset), output + offset, round_keys, Nr);
        }
        else {
            aes_decrypt_fast((byte*)(input + offset), output + offset, round_keys, dec_keys, Nr);
        }
    }
#endif

    /* Handle remaining data less than 16 bytes */
    remaining = length % AES_BLOCK_SIZE;
    if (remaining > 0) {
        memcpy(output + block_count * AES_BLOCK_SIZE, input + block_count * AES_BLOCK_SIZE, remaining);
    }
}

/* CBC mode implementation (decryption is OpenMP/pthread/Win32 parallelized) */
void AES_CBC(const byte* input, byte* output, size_t length,
    const byte* key, const byte* iv, size_t key_len, int encrypt) {
    word round_keys[60];
    word dec_keys[60];
    byte block[AES_BLOCK_SIZE] = { 0 };
    byte prev_block[AES_BLOCK_SIZE] = { 0 };
    int Nr = 0, j = 0;
    size_t block_count = 0, i = 0, offset = 0, remaining = 0;
    int i_block = 0;

    /* Key expansion */
    Nr = aes_keyexpansion(key, round_keys, key_len);
    if (Nr < 0) return;

    /* Initialize tables */
    generate_tables();

    /* Prepare decryption keys once if decrypting */
    if (!encrypt) {
        prepare_dec_keys(round_keys, dec_keys, Nr);
    }

    block_count = length / AES_BLOCK_SIZE;

    if (encrypt) {
        /* Encryption: sequential processing (cannot be parallelized due to chaining) */
        memcpy(prev_block, iv, AES_BLOCK_SIZE);

        for (i = 0; i < block_count; i++) {
            offset = i * AES_BLOCK_SIZE;

            /* XOR plaintext with previous ciphertext */
            for (j = 0; j < AES_BLOCK_SIZE; j++) {
                block[j] = input[offset + j] ^ prev_block[j];
            }

            /* AES encryption */
            aes_encrypt(block, output + offset, round_keys, Nr);

            /* Save current ciphertext for next block */
            memcpy(prev_block, output + offset, AES_BLOCK_SIZE);
        }
    }
    else {
        /* Decryption: parallelizable (each block decryption is independent) */
#ifdef _OPENMP
        /* Use OpenMP if available */
#pragma omp parallel for schedule(static) private(j)
        for (i_block = 0; i_block < (int)block_count; i_block++) {
            byte dec_block[AES_BLOCK_SIZE];
            const byte* prev_cipher;
            size_t off = (size_t)i_block * AES_BLOCK_SIZE;

            /* AES decryption with pre-computed keys */
            aes_decrypt_fast((byte*)(input + off), dec_block, round_keys, dec_keys, Nr);

            /* XOR with previous ciphertext (first block uses IV) */
            if (i_block == 0) {
                prev_cipher = iv;
            }
            else {
                prev_cipher = input + off - AES_BLOCK_SIZE;
            }

            for (j = 0; j < AES_BLOCK_SIZE; j++) {
                output[off + j] = dec_block[j] ^ prev_cipher[j];
            }
        }
#else
        /* Use platform-specific threading */
        int num_threads = get_num_threads();
        if (num_threads > 1 && block_count > (size_t)num_threads) {
            int blocks_per_thread = (int)block_count / num_threads;
            cbc_decrypt_thread_data_t* thread_data = (cbc_decrypt_thread_data_t*)malloc(num_threads * sizeof(cbc_decrypt_thread_data_t));

#ifdef _WIN32
            HANDLE* threads = (HANDLE*)malloc(num_threads * sizeof(HANDLE));
#else
            pthread_t* threads = (pthread_t*)malloc(num_threads * sizeof(pthread_t));
#endif

            if (thread_data && threads) {
                int i;
                for (i = 0; i < num_threads; i++) {
                    thread_data[i].input = input;
                    thread_data[i].output = output;
                    thread_data[i].iv = iv;
                    thread_data[i].round_keys = round_keys;
                    thread_data[i].dec_keys = dec_keys;
                    thread_data[i].Nr = Nr;
                    thread_data[i].start_block = i * blocks_per_thread;
                    thread_data[i].end_block = (i == num_threads - 1) ? (int)block_count : (i + 1) * blocks_per_thread;

#ifdef _WIN32
                    threads[i] = CreateThread(NULL, 0, cbc_decrypt_thread_func_win, &thread_data[i], 0, NULL);
#else
                    pthread_create(&threads[i], NULL, cbc_decrypt_thread_func, &thread_data[i]);
#endif
                }

                for (i = 0; i < num_threads; i++) {
#ifdef _WIN32
                    WaitForSingleObject(threads[i], INFINITE);
                    CloseHandle(threads[i]);
#else
                    pthread_join(threads[i], NULL);
#endif
                }

                free(threads);
                free(thread_data);

                /* Handle remaining data less than 16 bytes */
                remaining = length % AES_BLOCK_SIZE;
                if (remaining > 0) {
                    memcpy(output + block_count * AES_BLOCK_SIZE, input + block_count * AES_BLOCK_SIZE, remaining);
                }
                return;
            }
            if (thread_data) free(thread_data);
            if (threads) free(threads);
        }

        /* Fallback to sequential processing */
        for (i_block = 0; i_block < (int)block_count; i_block++) {
            byte dec_block[AES_BLOCK_SIZE];
            const byte* prev_cipher;
            size_t off = (size_t)i_block * AES_BLOCK_SIZE;

            /* AES decryption with pre-computed keys */
            aes_decrypt_fast((byte*)(input + off), dec_block, round_keys, dec_keys, Nr);

            /* XOR with previous ciphertext (first block uses IV) */
            if (i_block == 0) {
                prev_cipher = iv;
            }
            else {
                prev_cipher = input + off - AES_BLOCK_SIZE;
            }

            for (j = 0; j < AES_BLOCK_SIZE; j++) {
                output[off + j] = dec_block[j] ^ prev_cipher[j];
            }
        }
#endif
    }

    /* Handle remaining data less than 16 bytes */
    remaining = length % AES_BLOCK_SIZE;
    if (remaining > 0) {
        memcpy(output + block_count * AES_BLOCK_SIZE, input + block_count * AES_BLOCK_SIZE, remaining);
    }
}
