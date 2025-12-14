#ifndef HMAC_H
#define HMAC_H

#include "common.h"

// HMAC �⑥닔 (RFC 2104)
// algorithm: 1=SHA-256, 2=SHA-512
void hmac(const byte* key, size_t key_len, const byte* message, size_t message_len,
    byte* output, int algorithm);

#endif // HMAC_H
