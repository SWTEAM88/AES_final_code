#ifndef SHA_H
#define SHA_H

#include "common.h"

// SHA-256 context structure
typedef struct {
    byte data[64];
    uint32_t datalen;
    uint64_t bitlen;
    uint32_t state[8];
} SHA256_CTX;

// SHA-512 context structure
typedef struct {
    byte data[128];
    uint32_t datalen;
    uint64_t bitlen[2];  // 128-bit bit length
    uint64_t state[8];
} SHA512_CTX;

// SHA-256 function declarations
void sha256_init(SHA256_CTX* ctx);
void sha256_update(SHA256_CTX* ctx, const byte data[], size_t len);
void sha256_final(SHA256_CTX* ctx, byte hash[]);
void sha256(const byte data[], size_t len, byte hash[]);

// SHA-512 function declarations
void sha512_init(SHA512_CTX* ctx);
void sha512_update(SHA512_CTX* ctx, const byte data[], size_t len);
void sha512_final(SHA512_CTX* ctx, byte hash[]);
void sha512(const byte data[], size_t len, byte hash[]);

#endif // SHA_H
