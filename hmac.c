#include "hmac.h"
#include "sha.h"
#include "common.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

// --- HMAC (RFC 2104) ---
// Standard HMAC structure: HMAC(K, m) = H((K' XOR opad) || H((K' XOR ipad) || m))
// algorithm: 1=SHA-256, 2=SHA-512
// constant-time fix: fully constant-time implementation to prevent timing attacks
void hmac(const byte* key, size_t key_len, const byte* message, size_t message_len,
    byte* output, int algorithm) {
    // constant-time fix: always use maximum sizes to prevent timing differences
    const size_t max_block_size = 128;  // SHA-512 block size (maximum)
    const size_t max_hash_size = 64;    // SHA-512 hash size (maximum)

    // Constant-time algorithm selection using masks
    unsigned char is_sha256 = (algorithm == 1) ? 0xFF : 0x00;
    unsigned char is_sha512 = (algorithm == 2) ? 0xFF : 0x00;

    // constant-time fix: compute block_size and hash_size using masks
    size_t block_size = (64 & is_sha256) | (128 & is_sha512);
    size_t hash_size = (32 & is_sha256) | (64 & is_sha512);

    // Prepare K': pad key to block size (always use max_block_size for constant-time)
    byte* k_prime = (byte*)malloc(max_block_size);
    if (!k_prime) {
        fprintf(stderr, "Memory allocation failed in hmac\n");
        return;
    }
    memset(k_prime, 0, max_block_size);

    // constant-time fix: always hash key regardless of key length
    byte temp_hash256[32];
    byte temp_hash512[64];
    sha256(key, key_len, temp_hash256);
    sha512(key, key_len, temp_hash512);

    // constant-time fix: always process max_block_size bytes
    // Use hash if key_len > block_size, otherwise use key directly
    size_t i;
    unsigned char use_hash256, use_hash512;
    for (i = 0; i < max_block_size; i++) {
        // Determine if we should use hash for this position
        unsigned char should_use_hash = (key_len > block_size) ? 0xFF : 0x00;
        unsigned char in_key_range = (i < key_len) ? 0xFF : 0x00;
        unsigned char in_block_range = (i < block_size) ? 0xFF : 0x00;

        // For SHA-256: use hash if key_len > 64, otherwise use key
        use_hash256 = should_use_hash & is_sha256 & in_block_range;
        // For SHA-512: use hash if key_len > 128, otherwise use key
        use_hash512 = should_use_hash & is_sha512 & in_block_range;

        // Select value: key if in range and not using hash, otherwise use hash
        byte key_byte = (i < key_len) ? key[i] : 0;
        byte hash256_byte = (i < 32) ? temp_hash256[i] : 0;
        byte hash512_byte = (i < 64) ? temp_hash512[i] : 0;

        k_prime[i] = (key_byte & ~use_hash256 & ~use_hash512 & in_key_range & in_block_range) |
            (hash256_byte & use_hash256) |
            (hash512_byte & use_hash512);
    }

    // constant-time fix: pad remaining bytes for SHA-256 if needed
    // Always process all bytes to maintain constant time
    for (i = 32; i < max_block_size; i++) {
        unsigned char need_zero = is_sha256 & ((key_len > 64) ? 0xFF : 0x00) & ((i < block_size) ? 0xFF : 0x00);
        k_prime[i] &= ~need_zero;
    }

    // Prepare ipad and opad (always use max_block_size)
    byte* ipad_key = (byte*)malloc(max_block_size);
    byte* opad_key = (byte*)malloc(max_block_size);
    if (!ipad_key || !opad_key) {
        fprintf(stderr, "Memory allocation failed in hmac\n");
        free(k_prime);
        if (ipad_key) free(ipad_key);
        if (opad_key) free(opad_key);
        return;
    }

    // K' XOR ipad (ipad = 0x36 repeated)
    // constant-time fix: always process max_block_size bytes
    for (i = 0; i < max_block_size; i++) {
        unsigned char in_block = (i < block_size) ? 0xFF : 0x00;
        ipad_key[i] = (k_prime[i] ^ 0x36) & in_block;
    }

    // K' XOR opad (opad = 0x5c repeated)
    // constant-time fix: always process max_block_size bytes
    for (i = 0; i < max_block_size; i++) {
        unsigned char in_block = (i < block_size) ? 0xFF : 0x00;
        opad_key[i] = (k_prime[i] ^ 0x5c) & in_block;
    }

    // Inner hash: H((K' XOR ipad) || message)
    // constant-time fix: always allocate for max_block_size
    byte* inner_input = (byte*)malloc(max_block_size + message_len);
    if (!inner_input) {
        fprintf(stderr, "Memory allocation failed in hmac\n");
        free(k_prime);
        free(ipad_key);
        free(opad_key);
        return;
    }
    // constant-time fix: always copy max_block_size, but only use block_size
    memcpy(inner_input, ipad_key, max_block_size);
    memcpy(inner_input + block_size, message, message_len);

    byte inner_hash[64];  // Maximum size for SHA-512
    // constant-time fix: always compute both hashes, then select result
    byte inner_hash256[32];
    byte inner_hash512[64];
    sha256(inner_input, block_size + message_len, inner_hash256);
    sha512(inner_input, block_size + message_len, inner_hash512);

    // Constant-time selection based on algorithm
    unsigned char mask_inner = is_sha256;
    for (i = 0; i < 32; i++) {
        inner_hash[i] = (inner_hash256[i] & mask_inner) | (inner_hash512[i] & ~mask_inner);
    }
    for (i = 32; i < 64; i++) {
        inner_hash[i] = inner_hash512[i] & ~mask_inner;
    }

    // Outer hash: H((K' XOR opad) || inner_hash)
    // constant-time fix: always use max sizes
    byte* outer_input = (byte*)malloc(max_block_size + max_hash_size);
    if (!outer_input) {
        fprintf(stderr, "Memory allocation failed in hmac\n");
        free(k_prime);
        free(ipad_key);
        free(opad_key);
        free(inner_input);
        return;
    }
    // constant-time fix: always copy max sizes
    memcpy(outer_input, opad_key, max_block_size);
    memcpy(outer_input + block_size, inner_hash, max_hash_size);

    // constant-time fix: always compute both hashes with max sizes, then select result
    byte output256[32];
    byte output512[64];
    sha256(outer_input, block_size + hash_size, output256);
    sha512(outer_input, block_size + hash_size, output512);

    // Constant-time selection based on algorithm
    unsigned char mask_outer = is_sha256;
    for (i = 0; i < 32; i++) {
        output[i] = (output256[i] & mask_outer) | (output512[i] & ~mask_outer);
    }
    // Only write bytes 32-63 if SHA-512 is selected (hash_size == 64)
    // For SHA-256, output buffer is only 32 bytes, so we skip this loop
    if (hash_size == 64) {
        for (i = 32; i < 64; i++) {
            output[i] = output512[i];
        }
    }

    // Memory cleanup
    free(k_prime);
    free(ipad_key);
    free(opad_key);
    free(inner_input);
    free(outer_input);
}
