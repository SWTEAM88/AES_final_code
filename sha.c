#include "sha.h"
#include "common.h"
#include <string.h>
#include <stdint.h>

// --- SHA-256 Implementation ---

// SHA-256 constants (64 32-bit words)
static const uint32_t sha256_k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// SHA-256 bit rotation macros
#define SHA_ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))
#define SHA_CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define SHA_MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SHA_EP0(x) (SHA_ROTRIGHT(x,2) ^ SHA_ROTRIGHT(x,13) ^ SHA_ROTRIGHT(x,22))
#define SHA_EP1(x) (SHA_ROTRIGHT(x,6) ^ SHA_ROTRIGHT(x,11) ^ SHA_ROTRIGHT(x,25))
#define SHA_SIG0(x) (SHA_ROTRIGHT(x,7) ^ SHA_ROTRIGHT(x,18) ^ ((x) >> 3))
#define SHA_SIG1(x) (SHA_ROTRIGHT(x,17) ^ SHA_ROTRIGHT(x,19) ^ ((x) >> 10))

// SHA-256 transform function
static void sha256_transform(SHA256_CTX* ctx, const byte data[])
{
    uint32_t a = 0, b = 0, c = 0, d = 0, e = 0, f = 0, g = 0, h = 0, i = 0, j = 0, t1 = 0, t2 = 0;
    uint32_t m[64] = { 0 };

    // Convert input bytes to 32-bit words (Big Endian)
    // Fix overflow: use explicit casts to ensure proper type promotion
    for (i = 0, j = 0; i < 16; ++i, j += 4) {
        uint32_t temp = ((uint32_t)data[j] << 24);
        temp |= ((uint32_t)data[j + 1] << 16);
        temp |= ((uint32_t)data[j + 2] << 8);
        temp |= (uint32_t)data[j + 3];
        m[i] = temp;
    }
    // Fix overflow: use explicit casts to ensure proper type promotion
    for (; i < 64; ++i) {
        uint32_t temp = SHA_SIG1(m[i - 2]);
        temp = (uint32_t)((uint64_t)temp + (uint64_t)SHA_SIG0(m[i - 15]));
        temp = (uint32_t)((uint64_t)temp + (uint64_t)m[i - 7]);
        temp = (uint32_t)((uint64_t)temp + (uint64_t)m[i - 16]);
        m[i] = temp;
    }

    // Copy current state values
    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    // 64 rounds of SHA-256 transformation
    for (i = 0; i < 64; ++i) {
        t1 = h + SHA_EP1(e) + SHA_CH(e, f, g) + sha256_k[i] + m[i];
        t2 = SHA_EP0(a) + SHA_MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    // Update state values
    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

// SHA-256 initialization
void sha256_init(SHA256_CTX* ctx)
{
    ctx->datalen = 0;
    ctx->bitlen = 0;
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
}

// SHA-256 data update function
void sha256_update(SHA256_CTX* ctx, const byte data[], size_t len)
{
    uint32_t i;

    for (i = 0; i < len; ++i) {
        ctx->data[ctx->datalen] = data[i];
        ctx->datalen++;
        if (ctx->datalen == 64) {
            sha256_transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

// SHA-256 final hash output
void sha256_final(SHA256_CTX* ctx, byte hash[])
{
    uint32_t i = ctx->datalen;

    // Add padding
    if (ctx->datalen < 56) {
        ctx->data[i++] = 0x80;
        while (i < 56)
            ctx->data[i++] = 0x00;
    }
    else {
        ctx->data[i++] = 0x80;
        while (i < 64)
            ctx->data[i++] = 0x00;
        sha256_transform(ctx, ctx->data);
        memset(ctx->data, 0, 56);
    }

    ctx->bitlen += ctx->datalen * 8;
    ctx->data[63] = ctx->bitlen;
    ctx->data[62] = ctx->bitlen >> 8;
    ctx->data[61] = ctx->bitlen >> 16;
    ctx->data[60] = ctx->bitlen >> 24;
    ctx->data[59] = ctx->bitlen >> 32;
    ctx->data[58] = ctx->bitlen >> 40;
    ctx->data[57] = ctx->bitlen >> 48;
    ctx->data[56] = ctx->bitlen >> 56;
    sha256_transform(ctx, ctx->data);

    for (i = 0; i < 4; ++i) {
        hash[i] = (ctx->state[0] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 4] = (ctx->state[1] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 8] = (ctx->state[2] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0x000000ff;
    }
}

// One-shot SHA-256 hash output
void sha256(const byte data[], size_t len, byte hash[])
{
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, hash);
}

// --- SHA-512 Implementation ---

// SHA-512 constants (80 64-bit words)
static const uint64_t sha512_k[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

// SHA-512 bit rotation macros
#define SHA512_ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (64-(b))))
#define SHA512_CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define SHA512_MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SHA512_EP0(x) (SHA512_ROTRIGHT(x,28) ^ SHA512_ROTRIGHT(x,34) ^ SHA512_ROTRIGHT(x,39))
#define SHA512_EP1(x) (SHA512_ROTRIGHT(x,14) ^ SHA512_ROTRIGHT(x,18) ^ SHA512_ROTRIGHT(x,41))
#define SHA512_SIG0(x) (SHA512_ROTRIGHT(x,1) ^ SHA512_ROTRIGHT(x,8) ^ ((x) >> 7))
#define SHA512_SIG1(x) (SHA512_ROTRIGHT(x,19) ^ SHA512_ROTRIGHT(x,61) ^ ((x) >> 6))

// SHA-512 transform function
static void sha512_transform(SHA512_CTX* ctx, const byte data[])
{
    uint64_t a = 0, b = 0, c = 0, d = 0, e = 0, f = 0, g = 0, h = 0, i = 0, j = 0, t1 = 0, t2 = 0;
    uint64_t m[80] = { 0 };

    // Convert input bytes to 64-bit words (Big Endian)
    // Fix overflow: use explicit casts to ensure proper type promotion
    for (i = 0, j = 0; i < 16; ++i, j += 8) {
        uint64_t temp = ((uint64_t)data[j] << 56);
        temp |= ((uint64_t)data[j + 1] << 48);
        temp |= ((uint64_t)data[j + 2] << 40);
        temp |= ((uint64_t)data[j + 3] << 32);
        temp |= ((uint64_t)data[j + 4] << 24);
        temp |= ((uint64_t)data[j + 5] << 16);
        temp |= ((uint64_t)data[j + 6] << 8);
        temp |= (uint64_t)data[j + 7];
        m[i] = temp;
    }
    // Fix overflow: use explicit casts to ensure proper type promotion
    for (; i < 80; ++i) {
        uint64_t temp = SHA512_SIG1(m[i - 2]);
        temp += SHA512_SIG0(m[i - 15]);
        temp += m[i - 7];
        temp += m[i - 16];
        m[i] = temp;
    }

    // Copy current state values
    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    // 80 rounds of transformation
    for (i = 0; i < 80; ++i) {
        t1 = h + SHA512_EP1(e) + SHA512_CH(e, f, g) + sha512_k[i] + m[i];
        t2 = SHA512_EP0(a) + SHA512_MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    // Update state values
    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

// SHA-512 initialization
void sha512_init(SHA512_CTX* ctx)
{
    ctx->datalen = 0;
    ctx->bitlen[0] = 0;
    ctx->bitlen[1] = 0;
    ctx->state[0] = 0x6a09e667f3bcc908ULL;
    ctx->state[1] = 0xbb67ae8584caa73bULL;
    ctx->state[2] = 0x3c6ef372fe94f82bULL;
    ctx->state[3] = 0xa54ff53a5f1d36f1ULL;
    ctx->state[4] = 0x510e527fade682d1ULL;
    ctx->state[5] = 0x9b05688c2b3e6c1fULL;
    ctx->state[6] = 0x1f83d9abfb41bd6bULL;
    ctx->state[7] = 0x5be0cd19137e2179ULL;
}

// SHA-512 data update function
void sha512_update(SHA512_CTX* ctx, const byte data[], size_t len)
{
    uint32_t i;

    for (i = 0; i < len; ++i) {
        ctx->data[ctx->datalen] = data[i];
        ctx->datalen++;
        if (ctx->datalen == 128) {
            sha512_transform(ctx, ctx->data);
            // 128 bytes = 1024 bits added
            uint64_t carry = ctx->bitlen[0];
            ctx->bitlen[0] += 1024;
            if (ctx->bitlen[0] < carry)
                ctx->bitlen[1]++;
            ctx->datalen = 0;
        }
    }
}

// SHA-512 final hash output
void sha512_final(SHA512_CTX* ctx, byte hash[])
{
    uint32_t i = ctx->datalen;

    // Add padding
    if (ctx->datalen < 112) {
        ctx->data[i++] = 0x80;
        while (i < 112)
            ctx->data[i++] = 0x00;
    }
    else {
        ctx->data[i++] = 0x80;
        while (i < 128)
            ctx->data[i++] = 0x00;
        sha512_transform(ctx, ctx->data);
        memset(ctx->data, 0, 112);
    }

    // Add bit length (128 bytes, little endian order)
    uint64_t bitlen_low = ctx->bitlen[0] + (ctx->datalen * 8);
    uint64_t bitlen_high = ctx->bitlen[1];
    if (bitlen_low < (ctx->datalen * 8))
        bitlen_high++;

    // Add bit length (128 bytes, little endian order)
    for (i = 0; i < 8; i++) {
        ctx->data[127 - i] = (byte)(bitlen_low & 0xff);
        bitlen_low >>= 8;
    }
    for (i = 0; i < 8; i++) {
        ctx->data[119 - i] = (byte)(bitlen_high & 0xff);
        bitlen_high >>= 8;
    }
    sha512_transform(ctx, ctx->data);

    // Copy final state values to hash output
    for (i = 0; i < 8; ++i) {
        hash[i] = (ctx->state[0] >> (56 - i * 8)) & 0x00000000000000ffULL;
        hash[i + 8] = (ctx->state[1] >> (56 - i * 8)) & 0x00000000000000ffULL;
        hash[i + 16] = (ctx->state[2] >> (56 - i * 8)) & 0x00000000000000ffULL;
        hash[i + 24] = (ctx->state[3] >> (56 - i * 8)) & 0x00000000000000ffULL;
        hash[i + 32] = (ctx->state[4] >> (56 - i * 8)) & 0x00000000000000ffULL;
        hash[i + 40] = (ctx->state[5] >> (56 - i * 8)) & 0x00000000000000ffULL;
        hash[i + 48] = (ctx->state[6] >> (56 - i * 8)) & 0x00000000000000ffULL;
        hash[i + 56] = (ctx->state[7] >> (56 - i * 8)) & 0x00000000000000ffULL;
    }
}

// One-shot SHA-512 hash output
void sha512(const byte data[], size_t len, byte hash[])
{
    SHA512_CTX ctx;
    sha512_init(&ctx);
    sha512_update(&ctx, data, len);
    sha512_final(&ctx, hash);
}
