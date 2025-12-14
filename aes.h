#ifndef AES_H
#define AES_H

#include "common.h"

// AES block size
#define AES_BLOCK_SIZE 16

// AES  
#define AES_NB 4 
#define AES_NK_128 4
#define AES_NK_192 6
#define AES_NK_256 8 

#define AES_NR_128 10
#define AES_NR_192 12
#define AES_NR_256 14 

// AES function declarations
int aes_keyexpansion(const byte* key, word* w, size_t key_len);
void aes_encrypt(byte input[16], byte output[16], const word* w, int Nr);
void aes_decrypt(byte input[16], byte output[16], const word* w, int Nr);

// AES mode functions
// encrypt: 1=encryption, 0=decryption
void AES_ECB(const byte* input, byte* output, size_t length,
    const byte* key, size_t key_len, int encrypt);

void AES_CBC(const byte* input, byte* output, size_t length,
    const byte* key, const byte* iv, size_t key_len, int encrypt);

void AES_CTR(const byte* input, byte* output, size_t length,
    const byte* key, const byte* nonce, size_t key_len);

#endif // AES_H
