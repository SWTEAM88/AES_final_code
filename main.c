#include <stdio.h>    
#include <stdlib.h>   
#include <string.h>   
#include <ctype.h>    
#include <stdint.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#endif

// Required header files
#include "common.h"
#include "aes.h"
#include "sha.h"
#include "hmac.h"
#include "utils.h"
#include "network.h"
#include "performance.h"

// --- Function declarations ---
void setup_console();
void test_ecb(size_t key_len, int operation, int sha_algorithm);
void test_cbc(size_t key_len, int operation, int sha_algorithm);
void test_ctr(size_t key_len, int operation, int sha_algorithm);
void sender_mode(int mode_selection, size_t key_len, int sha_algorithm, const byte* psk, int use_network);
void receiver_mode(int use_network);
int setup_psk(byte* psk, size_t key_len, const byte* salt, size_t salt_len);
void derive_keys_from_psk(const byte* base_psk, byte* k_enc, byte* k_mac, size_t key_len);


void setup_console() {
    // Console setup (if needed for specific platforms)
}

// Network functions are now in network.c
// Utility functions (print_hex, read_dynamic_line, hex_string_to_bytes) are now in utils.c

/* =============================================================================
 * =============================================================================
 * AES Encryption/Decryption Test Functions Section
 * =============================================================================
 * This section contains test functions for AES block cipher modes (ECB, CBC, CTR).
 * Each function performs encryption/decryption operations and includes integrity
 * verification using HMAC.
 * =============================================================================
 * ============================================================================= */

// ECB test function
void test_ecb(size_t key_len, int operation, int sha_algorithm) {
    printf("\n========== AES-ECB Mode Test (AES-%zu) ==========\n\n", key_len * 8);
    byte* base_key = malloc(key_len);
    if (!base_key) { fprintf(stderr, "Memory allocation failed\n"); return; }

    // Generate secure key
    if (generate_secure_key(base_key, key_len) != 0) {
        fprintf(stderr, "Failed to generate secure key\n");
        free(base_key);
        return;
    }
    printf("Generated Base Key:\n"); print_hex(base_key, key_len); printf("\n");

    if (operation == 1) { // Encryption
        char* plaintext_input = read_dynamic_line("Enter plaintext: ");
        if (!plaintext_input) { free(base_key); return; }

        // Derive base_psk (32 bytes) from base_key using SHA-256
        byte base_psk[32];
        sha256(base_key, key_len, base_psk);

        // Derive k_enc and k_mac from base_psk
        byte* k_enc = (byte*)malloc(key_len);
        byte* k_mac = (byte*)malloc(key_len);
        if (!k_enc || !k_mac) {
            fprintf(stderr, "Memory allocation failed\n");
            free(plaintext_input); free(base_key);
            if (k_enc) free(k_enc);
            if (k_mac) free(k_mac);
            return;
        }
        derive_keys_from_psk(base_psk, k_enc, k_mac, key_len);

        size_t len = strlen(plaintext_input);
        size_t padded_len = ((len + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
        byte* padded_pt = malloc(padded_len);
        memcpy(padded_pt, plaintext_input, len);
        // Add PKCS padding: pad length bytes with pad value
        byte pad_value = (byte)(padded_len - len);
        for (size_t i = len; i < padded_len; i++) {
            padded_pt[i] = pad_value;
        }

        byte* ciphertext = malloc(padded_len);

        printf("Plaintext: %s\n", plaintext_input);
        AES_ECB(padded_pt, ciphertext, padded_len, k_enc, key_len, 1);

        printf("Ciphertext (HEX):\n"); print_hex(ciphertext, padded_len);

        // Calculate and output HMAC (HMAC of ciphertext)
        size_t hash_len = (sha_algorithm == 1) ? 32 : 64;
        byte hash[64];
        hmac(k_mac, key_len, ciphertext, padded_len, hash, sha_algorithm);
        if (sha_algorithm == 1) {
            printf("HMAC-SHA-256 of Ciphertext (HEX):\n");
            print_hex(hash, 32);
        }
        else if (sha_algorithm == 2) {
            printf("HMAC-SHA-512 of Ciphertext (HEX):\n");
            print_hex(hash, 64);
        }

        free(plaintext_input); free(padded_pt); free(ciphertext); free(k_enc); free(k_mac);
    }
    else { // Decryption
        // Decryption: get key from user
        char* key_hex = read_dynamic_line("Enter base key (HEX): ");
        if (!key_hex) { free(base_key); return; }

        size_t key_hex_len;
        byte* key_bytes = hex_string_to_bytes(key_hex, &key_hex_len);
        if (!key_bytes || key_hex_len != key_len) {
            fprintf(stderr, "Invalid key length. Expected %zu bytes.\n", key_len);
            free(base_key); free(key_hex);
            if (key_bytes) free(key_bytes);
            return;
        }
        memcpy(base_key, key_bytes, key_len);
        free(key_hex); free(key_bytes);
        printf("Using Base Key:\n"); print_hex(base_key, key_len); printf("\n");

        // Derive base_psk (32 bytes) from base_key using SHA-256
        byte base_psk[32];
        sha256(base_key, key_len, base_psk);

        // Derive k_enc and k_mac from base_psk
        byte* k_enc = (byte*)malloc(key_len);
        byte* k_mac = (byte*)malloc(key_len);
        if (!k_enc || !k_mac) {
            fprintf(stderr, "Memory allocation failed\n");
            free(base_key);
            if (k_enc) free(k_enc);
            if (k_mac) free(k_mac);
            return;
        }
        derive_keys_from_psk(base_psk, k_enc, k_mac, key_len);

        char* hex_input = read_dynamic_line("Enter ciphertext (HEX): ");
        if (!hex_input) { free(base_key); free(k_enc); free(k_mac); return; }

        size_t cipher_len;
        byte* ciphertext = hex_string_to_bytes(hex_input, &cipher_len);
        if (!ciphertext) { free(base_key); free(hex_input); free(k_enc); free(k_mac); return; }

        // Get HMAC from user
        size_t expected_hash_len = (sha_algorithm == 1) ? 64 : 128;  // hex string length
        char* hmac_hex = read_dynamic_line("Enter HMAC (HEX): ");
        if (!hmac_hex) {
            free(base_key); free(hex_input); free(ciphertext); free(k_enc); free(k_mac);
            return;
        }
        size_t hmac_hex_len = strlen(hmac_hex);
        if (hmac_hex_len != expected_hash_len) {
            fprintf(stderr, "Invalid HMAC length. Expected %zu hex characters.\n", expected_hash_len);
            free(base_key); free(hex_input); free(ciphertext); free(hmac_hex); free(k_enc); free(k_mac);
            return;
        }
        size_t hmac_bytes_len;
        byte* expected_hmac = hex_string_to_bytes(hmac_hex, &hmac_bytes_len);
        if (!expected_hmac) {
            free(base_key); free(hex_input); free(ciphertext); free(hmac_hex); free(k_enc); free(k_mac);
            return;
        }

        // Verify HMAC before decryption (Encrypt-then-MAC)
        size_t hash_len = (sha_algorithm == 1) ? 32 : 64;
        byte computed_hmac[64];
        hmac(k_mac, key_len, ciphertext, cipher_len, computed_hmac, sha_algorithm);
        int integrity_ok = (constant_time_memcmp(computed_hmac, expected_hmac, hash_len) == 0);

        if (!integrity_ok) {
            printf("\n=== Integrity Verification ===\n");
            printf("Expected HMAC: ");
            for (size_t i = 0; i < hash_len; i++) printf("%02X", expected_hmac[i]);
            printf("\n");
            printf("Computed HMAC: ");
            for (size_t i = 0; i < hash_len; i++) printf("%02X", computed_hmac[i]);
            printf("\n");
            printf("Result: Failed - Integrity verification failed! Decryption aborted.\n");
            printf("==============================\n");
            free(base_key); free(hex_input); free(ciphertext); free(hmac_hex); free(expected_hmac);
            free(k_enc); free(k_mac);
            return;
        }

        // HMAC verification succeeded, proceed with decryption
        byte* decrypted = malloc(cipher_len + 1);
        AES_ECB(ciphertext, decrypted, cipher_len, k_enc, key_len, 0);

        // constant-time fix: use constant-time PKCS#7 padding validation
        size_t actual_len = cipher_len;
        constant_time_pkcs7_unpad(decrypted, cipher_len, &actual_len);
        decrypted[actual_len] = '\0';

        printf("Decrypted text: %s\n", decrypted);
        printf("\n=== Integrity Verification ===\n");
        printf("Expected HMAC: ");
        for (size_t i = 0; i < hash_len; i++) printf("%02X", expected_hmac[i]);
        printf("\n");
        printf("Computed HMAC: ");
        for (size_t i = 0; i < hash_len; i++) printf("%02X", computed_hmac[i]);
        printf("\n");
        printf("Result: Success - Integrity verified!\n");
        printf("==============================\n");

        free(hex_input); free(ciphertext); free(decrypted); free(hmac_hex); free(expected_hmac);
        free(k_enc); free(k_mac);
    }
    free(base_key);
}

// CBC test function
void test_cbc(size_t key_len, int operation, int sha_algorithm) {
    printf("\n========== AES-CBC Mode Test (AES-%zu) ==========\n\n", key_len * 8);
    byte* base_key = malloc(key_len);
    byte iv[16];
    if (!base_key) { fprintf(stderr, "Memory allocation failed\n"); return; }

    // Generate secure key
    if (generate_secure_key(base_key, key_len) != 0) {
        fprintf(stderr, "Failed to generate secure key\n");
        free(base_key);
        return;
    }
    // Generate secure IV
    if (generate_secure_key(iv, 16) != 0) {
        fprintf(stderr, "Failed to generate secure IV\n");
        free(base_key);
        return;
    }
    printf("Generated Base Key:\n"); print_hex(base_key, key_len);
    printf("Generated IV:\n"); print_hex(iv, 16); printf("\n");

    if (operation == 1) { // Encryption
        char* plaintext_input = read_dynamic_line("Enter plaintext: ");
        if (!plaintext_input) { free(base_key); return; }

        // Derive base_psk (32 bytes) from base_key using SHA-256
        byte base_psk[32];
        sha256(base_key, key_len, base_psk);

        // Derive k_enc and k_mac from base_psk
        byte* k_enc = (byte*)malloc(key_len);
        byte* k_mac = (byte*)malloc(key_len);
        if (!k_enc || !k_mac) {
            fprintf(stderr, "Memory allocation failed\n");
            free(plaintext_input); free(base_key);
            if (k_enc) free(k_enc);
            if (k_mac) free(k_mac);
            return;
        }
        derive_keys_from_psk(base_psk, k_enc, k_mac, key_len);

        size_t len = strlen(plaintext_input);
        size_t padded_len = ((len + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
        byte* padded_pt = malloc(padded_len);
        memcpy(padded_pt, plaintext_input, len);
        // Add PKCS padding: pad length bytes with pad value
        byte pad_value = (byte)(padded_len - len);
        for (size_t i = len; i < padded_len; i++) {
            padded_pt[i] = pad_value;
        }
        byte* ciphertext = malloc(padded_len);

        printf("Plaintext: %s\n", plaintext_input);
        AES_CBC(padded_pt, ciphertext, padded_len, k_enc, iv, key_len, 1); // Encryption function call

        printf("Ciphertext (HEX):\n"); print_hex(ciphertext, padded_len);

        // Calculate and output HMAC (HMAC of ciphertext)
        size_t hash_len = (sha_algorithm == 1) ? 32 : 64;
        byte hash[64];
        hmac(k_mac, key_len, ciphertext, padded_len, hash, sha_algorithm);
        if (sha_algorithm == 1) {
            printf("HMAC-SHA-256 of Ciphertext (HEX):\n");
            print_hex(hash, 32);
        }
        else if (sha_algorithm == 2) {
            printf("HMAC-SHA-512 of Ciphertext (HEX):\n");
            print_hex(hash, 64);
        }

        free(plaintext_input); free(padded_pt); free(ciphertext); free(k_enc); free(k_mac);
    }
    else { // Decryption
        // Decryption: get key and IV from user
        char* key_hex = read_dynamic_line("Enter base key (HEX): ");
        if (!key_hex) { free(base_key); return; }

        size_t key_hex_len;
        byte* key_bytes = hex_string_to_bytes(key_hex, &key_hex_len);
        if (!key_bytes || key_hex_len != key_len) {
            fprintf(stderr, "Invalid key length. Expected %zu bytes.\n", key_len);
            free(base_key); free(key_hex);
            if (key_bytes) free(key_bytes);
            return;
        }
        memcpy(base_key, key_bytes, key_len);
        free(key_hex); free(key_bytes);
        printf("Using Base Key:\n"); print_hex(base_key, key_len); printf("\n");

        // Derive base_psk (32 bytes) from base_key using SHA-256
        byte base_psk[32];
        sha256(base_key, key_len, base_psk);

        // Derive k_enc and k_mac from base_psk
        byte* k_enc = (byte*)malloc(key_len);
        byte* k_mac = (byte*)malloc(key_len);
        if (!k_enc || !k_mac) {
            fprintf(stderr, "Memory allocation failed\n");
            free(base_key);
            if (k_enc) free(k_enc);
            if (k_mac) free(k_mac);
            return;
        }
        derive_keys_from_psk(base_psk, k_enc, k_mac, key_len);

        char* iv_hex = read_dynamic_line("Enter IV (HEX): ");
        if (!iv_hex) { free(base_key); free(k_enc); free(k_mac); return; }

        size_t iv_hex_len;
        byte* iv_bytes = hex_string_to_bytes(iv_hex, &iv_hex_len);
        if (!iv_bytes || iv_hex_len != 16) {
            fprintf(stderr, "Invalid IV length. Expected 16 bytes.\n");
            free(base_key); free(iv_hex); free(k_enc); free(k_mac);
            if (iv_bytes) free(iv_bytes);
            return;
        }
        memcpy(iv, iv_bytes, 16);
        free(iv_hex); free(iv_bytes);
        printf("Using IV:\n"); print_hex(iv, 16); printf("\n");

        char* hex_input = read_dynamic_line("Enter ciphertext (HEX): ");
        if (!hex_input) { free(base_key); free(k_enc); free(k_mac); return; }

        size_t cipher_len;
        byte* ciphertext = hex_string_to_bytes(hex_input, &cipher_len);
        if (!ciphertext) { free(base_key); free(hex_input); free(k_enc); free(k_mac); return; }

        // Get HMAC from user
        size_t expected_hash_len = (sha_algorithm == 1) ? 64 : 128;  // hex string length
        char* hmac_hex = read_dynamic_line("Enter HMAC (HEX): ");
        if (!hmac_hex) {
            free(base_key); free(hex_input); free(ciphertext); free(k_enc); free(k_mac);
            return;
        }
        size_t hmac_hex_len = strlen(hmac_hex);
        if (hmac_hex_len != expected_hash_len) {
            fprintf(stderr, "Invalid HMAC length. Expected %zu hex characters.\n", expected_hash_len);
            free(base_key); free(hex_input); free(ciphertext); free(hmac_hex); free(k_enc); free(k_mac);
            return;
        }
        size_t hmac_bytes_len;
        byte* expected_hmac = hex_string_to_bytes(hmac_hex, &hmac_bytes_len);
        if (!expected_hmac) {
            free(base_key); free(hex_input); free(ciphertext); free(hmac_hex); free(k_enc); free(k_mac);
            return;
        }

        // Verify HMAC before decryption (Encrypt-then-MAC)
        size_t hash_len = (sha_algorithm == 1) ? 32 : 64;
        byte computed_hmac[64];
        hmac(k_mac, key_len, ciphertext, cipher_len, computed_hmac, sha_algorithm);
        int integrity_ok = (constant_time_memcmp(computed_hmac, expected_hmac, hash_len) == 0);

        if (!integrity_ok) {
            printf("\n=== Integrity Verification ===\n");
            printf("Expected HMAC: ");
            for (size_t i = 0; i < hash_len; i++) printf("%02X", expected_hmac[i]);
            printf("\n");
            printf("Computed HMAC: ");
            for (size_t i = 0; i < hash_len; i++) printf("%02X", computed_hmac[i]);
            printf("\n");
            printf("Result: Failed - Integrity verification failed! Decryption aborted.\n");
            printf("==============================\n");
            free(base_key); free(hex_input); free(ciphertext); free(hmac_hex); free(expected_hmac);
            free(k_enc); free(k_mac);
            return;
        }

        // HMAC verification succeeded, proceed with decryption
        byte* decrypted = malloc(cipher_len + 1);
        AES_CBC(ciphertext, decrypted, cipher_len, k_enc, iv, key_len, 0);

        // constant-time fix: use constant-time PKCS#7 padding validation
        size_t actual_len = cipher_len;
        constant_time_pkcs7_unpad(decrypted, cipher_len, &actual_len);
        decrypted[actual_len] = '\0';

        printf("Decrypted text: %s\n", decrypted);
        printf("\n=== Integrity Verification ===\n");
        printf("Expected HMAC: ");
        for (size_t i = 0; i < hash_len; i++) printf("%02X", expected_hmac[i]);
        printf("\n");
        printf("Computed HMAC: ");
        for (size_t i = 0; i < hash_len; i++) printf("%02X", computed_hmac[i]);
        printf("\n");
        printf("Result: Success - Integrity verified!\n");
        printf("==============================\n");

        free(hex_input); free(ciphertext); free(decrypted); free(hmac_hex); free(expected_hmac);
        free(k_enc); free(k_mac);
    }
    free(base_key);
}

// CTR test function
void test_ctr(size_t key_len, int operation, int sha_algorithm) {
    printf("\n========== AES-CTR Mode Test (AES-%zu) ==========\n\n", key_len * 8);
    byte* base_key = malloc(key_len);
    byte nonce[12];  // Increased from 8 to 12 bytes for better security (NIST SP 800-38A compliant)
    if (!base_key) { fprintf(stderr, "Memory allocation failed\n"); return; }

    // Generate secure key
    if (generate_secure_key(base_key, key_len) != 0) {
        fprintf(stderr, "Failed to generate secure key\n");
        free(base_key);
        return;
    }
    // Generate secure nonce (12 bytes for better security)
    if (generate_secure_key(nonce, 12) != 0) {
        fprintf(stderr, "Failed to generate secure nonce\n");
        free(base_key);
        return;
    }
    printf("Generated Base Key:\n"); print_hex(base_key, key_len);
    printf("Generated Nonce (12 bytes):\n"); print_hex(nonce, 12); printf("\n");

    if (operation == 1) { // Encryption
        char* plaintext_input = read_dynamic_line("Enter plaintext: ");
        if (!plaintext_input) { free(base_key); return; }

        // Derive base_psk (32 bytes) from base_key using SHA-256
        byte base_psk[32];
        sha256(base_key, key_len, base_psk);

        // Derive k_enc and k_mac from base_psk
        byte* k_enc = (byte*)malloc(key_len);
        byte* k_mac = (byte*)malloc(key_len);
        if (!k_enc || !k_mac) {
            fprintf(stderr, "Memory allocation failed\n");
            free(plaintext_input); free(base_key);
            if (k_enc) free(k_enc);
            if (k_mac) free(k_mac);
            return;
        }
        derive_keys_from_psk(base_psk, k_enc, k_mac, key_len);

        size_t len = strlen(plaintext_input);
        byte* ciphertext = malloc(len);

        printf("Plaintext: %s\n", plaintext_input);
        AES_CTR((byte*)plaintext_input, ciphertext, len, k_enc, nonce, key_len); // Encryption function call

        printf("Ciphertext (HEX):\n"); print_hex(ciphertext, len);

        // Calculate and output HMAC (HMAC of ciphertext)
        size_t hash_len = (sha_algorithm == 1) ? 32 : 64;
        byte hash[64];
        hmac(k_mac, key_len, ciphertext, len, hash, sha_algorithm);
        if (sha_algorithm == 1) {
            printf("HMAC-SHA-256 of Ciphertext (HEX):\n");
            print_hex(hash, 32);
        }
        else if (sha_algorithm == 2) {
            printf("HMAC-SHA-512 of Ciphertext (HEX):\n");
            print_hex(hash, 64);
        }

        free(plaintext_input); free(ciphertext); free(k_enc); free(k_mac);
    }
    else { // Decryption
        // Decryption: get key and Nonce from user
        char* key_hex = read_dynamic_line("Enter base key (HEX): ");
        if (!key_hex) { free(base_key); return; }

        size_t key_hex_len;
        byte* key_bytes = hex_string_to_bytes(key_hex, &key_hex_len);
        if (!key_bytes || key_hex_len != key_len) {
            fprintf(stderr, "Invalid key length. Expected %zu bytes.\n", key_len);
            free(base_key); free(key_hex);
            if (key_bytes) free(key_bytes);
            return;
        }
        memcpy(base_key, key_bytes, key_len);
        free(key_hex); free(key_bytes);
        printf("Using Base Key:\n"); print_hex(base_key, key_len); printf("\n");

        // Derive base_psk (32 bytes) from base_key using SHA-256
        byte base_psk[32];
        sha256(base_key, key_len, base_psk);

        // Derive k_enc and k_mac from base_psk
        byte* k_enc = (byte*)malloc(key_len);
        byte* k_mac = (byte*)malloc(key_len);
        if (!k_enc || !k_mac) {
            fprintf(stderr, "Memory allocation failed\n");
            free(base_key);
            if (k_enc) free(k_enc);
            if (k_mac) free(k_mac);
            return;
        }
        derive_keys_from_psk(base_psk, k_enc, k_mac, key_len);

        char* nonce_hex = read_dynamic_line("Enter nonce (HEX): ");
        if (!nonce_hex) { free(base_key); free(k_enc); free(k_mac); return; }

        size_t nonce_hex_len;
        byte* nonce_bytes = hex_string_to_bytes(nonce_hex, &nonce_hex_len);
        if (!nonce_bytes || nonce_hex_len != 12) {
            fprintf(stderr, "Invalid nonce length. Expected 12 bytes.\n");
            free(base_key); free(nonce_hex); free(k_enc); free(k_mac);
            if (nonce_bytes) free(nonce_bytes);
            return;
        }
        memcpy(nonce, nonce_bytes, 12);
        free(nonce_hex); free(nonce_bytes);
        printf("Using Nonce (12 bytes):\n"); print_hex(nonce, 12); printf("\n");

        char* hex_input = read_dynamic_line("Enter ciphertext (HEX): ");
        if (!hex_input) { free(base_key); free(k_enc); free(k_mac); return; }

        size_t cipher_len;
        byte* ciphertext = hex_string_to_bytes(hex_input, &cipher_len);
        if (!ciphertext) { free(base_key); free(hex_input); free(k_enc); free(k_mac); return; }

        // Get HMAC from user
        size_t expected_hash_len = (sha_algorithm == 1) ? 64 : 128;  // hex string length
        char* hmac_hex = read_dynamic_line("Enter HMAC (HEX): ");
        if (!hmac_hex) {
            free(base_key); free(hex_input); free(ciphertext); free(k_enc); free(k_mac);
            return;
        }
        size_t hmac_hex_len = strlen(hmac_hex);
        if (hmac_hex_len != expected_hash_len) {
            fprintf(stderr, "Invalid HMAC length. Expected %zu hex characters.\n", expected_hash_len);
            free(base_key); free(hex_input); free(ciphertext); free(hmac_hex); free(k_enc); free(k_mac);
            return;
        }
        size_t hmac_bytes_len;
        byte* expected_hmac = hex_string_to_bytes(hmac_hex, &hmac_bytes_len);
        if (!expected_hmac) {
            free(base_key); free(hex_input); free(ciphertext); free(hmac_hex); free(k_enc); free(k_mac);
            return;
        }

        // Verify HMAC before decryption (Encrypt-then-MAC)
        size_t hash_len = (sha_algorithm == 1) ? 32 : 64;
        byte computed_hmac[64];
        hmac(k_mac, key_len, ciphertext, cipher_len, computed_hmac, sha_algorithm);
        int integrity_ok = (constant_time_memcmp(computed_hmac, expected_hmac, hash_len) == 0);

        if (!integrity_ok) {
            printf("\n=== Integrity Verification ===\n");
            printf("Expected HMAC: ");
            for (size_t i = 0; i < hash_len; i++) printf("%02X", expected_hmac[i]);
            printf("\n");
            printf("Computed HMAC: ");
            for (size_t i = 0; i < hash_len; i++) printf("%02X", computed_hmac[i]);
            printf("\n");
            printf("Result: Failed - Integrity verification failed! Decryption aborted.\n");
            printf("==============================\n");
            free(base_key); free(hex_input); free(ciphertext); free(hmac_hex); free(expected_hmac);
            free(k_enc); free(k_mac);
            return;
        }

        // HMAC verification succeeded, proceed with decryption
        byte* decrypted = malloc(cipher_len + 1);
        AES_CTR(ciphertext, decrypted, cipher_len, k_enc, nonce, key_len);
        decrypted[cipher_len] = '\0';

        printf("Decrypted text: %s\n", decrypted);
        printf("\n=== Integrity Verification ===\n");
        printf("Expected HMAC: ");
        for (size_t i = 0; i < hash_len; i++) printf("%02X", expected_hmac[i]);
        printf("\n");
        printf("Computed HMAC: ");
        for (size_t i = 0; i < hash_len; i++) printf("%02X", computed_hmac[i]);
        printf("\n");
        printf("Result: Success - Integrity verified!\n");
        printf("==============================\n");

        free(hex_input); free(ciphertext); free(decrypted); free(hmac_hex); free(expected_hmac);
        free(k_enc); free(k_mac);
    }
    free(base_key);
}
/* =============================================================================
 * =============================================================================
 * SHA Hash Function Usage Section
 * =============================================================================
 * This section contains functions that use SHA-256 hash function.
 * SHA-256 is used for PSK generation and key derivation.
 * =============================================================================
 * ============================================================================= */

// Extract value from packet function
static char* extract_value_from_packet(const char* packet, const char* key) {
    char search_key[256];
    snprintf(search_key, sizeof(search_key), "%s:", key);
    const char* start = strstr(packet, search_key);
    if (!start) return NULL;
    start += strlen(search_key);
    while (*start == ' ') start++;
    const char* end = strchr(start, '\n');
    if (!end) end = start + strlen(start);
    size_t len = end - start;
    char* value = (char*)malloc(len + 1);
    if (!value) return NULL;
    memcpy(value, start, len);
    value[len] = '\0';
    while (len > 0 && (value[len - 1] == ' ' || value[len - 1] == '\n')) {
        value[--len] = '\0';
    }
    return value;
}

// PSK setup function: get password input and generate 32-byte base_psk using SHA-256(password || salt)
int setup_psk(byte* psk, size_t key_len, const byte* salt, size_t salt_len) {
    printf("\n========== PSK (Pre-Shared Key) Setup ==========\n");
    printf("Enter password (will be hashed with salt to generate PSK): ");
    char* password = read_dynamic_line("");
    if (!password) {
        fprintf(stderr, "Failed to read password\n");
        return -1;
    }

    // Concatenate password and salt
    size_t password_len = strlen(password);
    byte* password_salt = (byte*)malloc(password_len + salt_len);
    if (!password_salt) {
        fprintf(stderr, "Memory allocation failed\n");
        memset(password, 0, password_len);
        free(password);
        return -1;
    }
    memcpy(password_salt, password, password_len);
    memcpy(password_salt + password_len, salt, salt_len);

    // Generate 32-byte base_psk using SHA-256(password || salt)
    sha256(password_salt, password_len + salt_len, psk);

    printf("Salt (HEX): ");
    print_hex(salt, salt_len);
    printf("\n");
    printf("Base PSK (SHA-256 of password || salt) generated: ");
    print_hex(psk, 32);
    printf("\n");

    // Clear sensitive data from memory for security
    memset(password, 0, password_len);
    memset(password_salt, 0, password_len + salt_len);
    free(password);
    free(password_salt);
    return 0;
}

/* =============================================================================
 * =============================================================================
 * HMAC Integrity Verification Section
 * =============================================================================
 * This section contains message integrity verification functions using HMAC.
 * HMAC-SHA256/512 is used to verify the integrity of ciphertext.
 * =============================================================================
 * ============================================================================= */

// Derive encryption key (K_enc) and integrity verification key (K_mac) from base_psk
void derive_keys_from_psk(const byte* base_psk, byte* k_enc, byte* k_mac, size_t key_len) {
    byte temp_enc[32];
    byte temp_mac[32];

    // K_enc = first key_len bytes of SHA-256(base_psk || "enc")
    byte enc_input[32 + 3];  // base_psk(32) + "enc"(3)
    memcpy(enc_input, base_psk, 32);
    memcpy(enc_input + 32, "enc", 3);
    sha256(enc_input, 35, temp_enc);
    memcpy(k_enc, temp_enc, key_len);

    // K_mac = first key_len bytes of SHA-256(base_psk || "mac")
    byte mac_input[32 + 3];  // base_psk(32) + "mac"(3)
    memcpy(mac_input, base_psk, 32);
    memcpy(mac_input + 32, "mac", 3);
    sha256(mac_input, 35, temp_mac);
    memcpy(k_mac, temp_mac, key_len);
}

/* =============================================================================
 * =============================================================================
 * Network Communication Section
 * =============================================================================
 * This section contains functions for encrypted data transmission/reception over network.
 * sender_mode: Constructs encrypted data into packets and sends over network
 * receiver_mode: Receives packets from network and performs decryption and integrity verification
 * =============================================================================
 * ============================================================================= */

// Sender mode: plaintext encryption SHA packet output (using PSK)
void sender_mode(int mode_selection, size_t key_len, int sha_algorithm, const byte* psk, int use_network) {
    printf("\n========== Sender Mode ==========\n\n");

    // Generate random salt (16 bytes)
    const size_t salt_len = 16;
    byte* salt = (byte*)malloc(salt_len);
    if (!salt) {
        fprintf(stderr, "Memory allocation failed\n");
        return;
    }
    if (generate_secure_key(salt, salt_len) != 0) {
        fprintf(stderr, "Failed to generate salt\n");
        free(salt);
        return;
    }

    // Generate base_psk using password and salt
    byte* base_psk = (byte*)malloc(32);
    if (!base_psk) {
        fprintf(stderr, "Memory allocation failed\n");
        free(salt);
        return;
    }

    // Get password input
    printf("Enter password: ");
    char* password = read_dynamic_line("");
    if (!password) {
        free(salt);
        free(base_psk);
        return;
    }

    // Concatenate password and salt, then hash
    size_t password_len = strlen(password);
    byte* password_salt = (byte*)malloc(password_len + salt_len);
    if (!password_salt) {
        fprintf(stderr, "Memory allocation failed\n");
        memset(password, 0, password_len);
        free(password);
        free(salt);
        free(base_psk);
        return;
    }
    memcpy(password_salt, password, password_len);
    memcpy(password_salt + password_len, salt, salt_len);
    sha256(password_salt, password_len + salt_len, base_psk);

    // Clear password from memory
    memset(password, 0, password_len);
    memset(password_salt, 0, password_len + salt_len);
    free(password);
    free(password_salt);

    printf("Salt (HEX): ");
    print_hex(salt, salt_len);
    printf("\n");
    printf("Base PSK (SHA-256 of password || salt) generated: ");
    print_hex(base_psk, 32);
    printf("\n");

    // Derive K_enc and K_mac from base_psk
    byte* k_enc = (byte*)malloc(key_len);
    byte* k_mac = (byte*)malloc(key_len);
    if (!k_enc || !k_mac) {
        fprintf(stderr, "Memory allocation failed\n");
        free(salt);
        free(base_psk);
        if (k_enc) free(k_enc);
        if (k_mac) free(k_mac);
        return;
    }
    derive_keys_from_psk(base_psk, k_enc, k_mac, key_len);
    free(base_psk);

    const byte* key = k_enc;  // Use K_enc as encryption key
    char* plaintext_input = read_dynamic_line("Enter plaintext: ");
    if (!plaintext_input) { return; }
    size_t len = strlen(plaintext_input);
    byte* ciphertext = NULL;
    size_t cipher_len = 0;
    byte iv[16] = { 0 };
    byte nonce[12] = { 0 };  // Increased from 8 to 12 bytes for better security (NIST SP 800-38A compliant)
    byte hash[64] = { 0 };
    size_t hash_len = (sha_algorithm == 1) ? 32 : 64;

    if (mode_selection == 1) {
        size_t padded_len = ((len + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
        byte* padded_pt = malloc(padded_len);
        memcpy(padded_pt, plaintext_input, len);
        byte pad_value = (byte)(padded_len - len);
        for (size_t i = len; i < padded_len; i++) padded_pt[i] = pad_value;
        ciphertext = malloc(padded_len);
        AES_ECB(padded_pt, ciphertext, padded_len, key, key_len, 1);
        cipher_len = padded_len;
        free(padded_pt);
    }
    else if (mode_selection == 2) {
        if (generate_secure_key(iv, 16) != 0) {
            fprintf(stderr, "Failed to generate IV\n");
            free(plaintext_input);
            return;
        }
        size_t padded_len = ((len + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
        byte* padded_pt = malloc(padded_len);
        memcpy(padded_pt, plaintext_input, len);
        byte pad_value = (byte)(padded_len - len);
        for (size_t i = len; i < padded_len; i++) padded_pt[i] = pad_value;
        ciphertext = malloc(padded_len);
        AES_CBC(padded_pt, ciphertext, padded_len, key, iv, key_len, 1);
        cipher_len = padded_len;
        free(padded_pt);
    }
    else if (mode_selection == 3) {
        if (generate_secure_key(nonce, 12) != 0) {
            fprintf(stderr, "Failed to generate nonce\n");
            free(plaintext_input);
            return;
        }
        ciphertext = malloc(len);
        AES_CTR((byte*)plaintext_input, ciphertext, len, key, nonce, key_len);
        cipher_len = len;
    }

    // HMAC method: use standard HMAC structure (RFC 2104)
    hmac(k_mac, key_len, ciphertext, cipher_len, hash, sha_algorithm);

    // Create packet
    size_t packet_capacity = 4096;
    char* packet = (char*)malloc(packet_capacity);
    if (!packet) {
        fprintf(stderr, "Memory allocation failed\n");
        free(plaintext_input);
        free(ciphertext);
        return;
    }

    int packet_len = snprintf(packet, packet_capacity,
        "=== PACKET (Copy this text) ===\n"
        "MODE:%d\n"
        "KEY_LEN:%zu\n"
        "SHA_ALGORITHM:%d\n"
        "SALT:",
        mode_selection, key_len, sha_algorithm);

    // Add salt to packet
    for (size_t i = 0; i < salt_len; i++) {
        packet_len += snprintf(packet + packet_len, packet_capacity - packet_len, "%02X", salt[i]);
    }
    packet_len += snprintf(packet + packet_len, packet_capacity - packet_len, "\n");

    if (mode_selection == 2) {
        packet_len += snprintf(packet + packet_len, packet_capacity - packet_len, "IV:");
        for (size_t i = 0; i < 16; i++) {
            packet_len += snprintf(packet + packet_len, packet_capacity - packet_len, "%02X", iv[i]);
        }
        packet_len += snprintf(packet + packet_len, packet_capacity - packet_len, "\n");
    }
    else if (mode_selection == 3) {
        packet_len += snprintf(packet + packet_len, packet_capacity - packet_len, "NONCE:");
        for (size_t i = 0; i < 12; i++) {
            packet_len += snprintf(packet + packet_len, packet_capacity - packet_len, "%02X", nonce[i]);
        }
        packet_len += snprintf(packet + packet_len, packet_capacity - packet_len, "\n");
    }

    packet_len += snprintf(packet + packet_len, packet_capacity - packet_len, "CIPHERTEXT:");
    for (size_t i = 0; i < cipher_len; i++) {
        packet_len += snprintf(packet + packet_len, packet_capacity - packet_len, "%02X", ciphertext[i]);
    }
    packet_len += snprintf(packet + packet_len, packet_capacity - packet_len, "\nSHA:");
    for (size_t i = 0; i < hash_len; i++) {
        packet_len += snprintf(packet + packet_len, packet_capacity - packet_len, "%02X", hash[i]);
    }
    packet_len += snprintf(packet + packet_len, packet_capacity - packet_len, "\n=== END PACKET ===\n");

    // Send packet over network
    int port = 8888;
    printf("\nEnter port number (default: 8888): ");
    char port_str[32];
    if (fgets(port_str, sizeof(port_str), stdin) != NULL) {
        int input_port = atoi(port_str);
        if (input_port > 0 && input_port < 65536) {
            port = input_port;
        }
    }

    printf("Sending packet over network...\n");
    if (send_packet_over_network(packet, NULL, port) == 0) {
        printf("Network transmission completed!\n");
    }
    else {
        fprintf(stderr, "Network transmission failed\n");
    }

    free(plaintext_input);
    free(ciphertext);
    free(packet);
    free(salt);
    free(k_enc);
    free(k_mac);
}

// Receiver mode: packet input decryption SHA verification (using PSK, automatic processing)
void receiver_mode(int use_network) {
    printf("\n========== Receiver Mode ==========\n\n");

    char* packet = NULL;

    // Receive packet from network
    int port = 8888;
    printf("Enter port number (default: 8888): ");
    char port_str[32];
    if (fgets(port_str, sizeof(port_str), stdin) != NULL) {
        int input_port = atoi(port_str);
        if (input_port > 0 && input_port < 65536) {
            port = input_port;
        }
    }

    printf("Receiving packet from network...\n");
    if (receive_packet_over_network(&packet, port) != 0) {
        fprintf(stderr, "Network reception failed\n");
        return;
    }

    // Extract KEY_LEN from packet first to use for PSK input
    char* key_len_str = extract_value_from_packet(packet, "KEY_LEN");
    if (!key_len_str) {
        fprintf(stderr, "Error: KEY_LEN not found in packet\n");
        free(packet);
        return;
    }
    size_t key_len = (size_t)atoi(key_len_str);
    if (key_len != 16 && key_len != 24 && key_len != 32) {
        fprintf(stderr, "Error: Invalid KEY_LEN value\n");
        free(packet); free(key_len_str);
        return;
    }

    // Extract salt from packet
    char* salt_hex = extract_value_from_packet(packet, "SALT");
    if (!salt_hex) {
        fprintf(stderr, "Error: SALT not found in packet\n");
        free(packet); free(key_len_str);
        return;
    }

    size_t salt_bytes_len;
    byte* salt = hex_string_to_bytes(salt_hex, &salt_bytes_len);
    if (!salt || salt_bytes_len != 16) {
        fprintf(stderr, "Error: Invalid SALT in packet (must be 16 bytes)\n");
        free(packet); free(key_len_str); free(salt_hex);
        if (salt) free(salt);
        return;
    }

    printf("Salt received from packet (HEX): ");
    print_hex(salt, salt_bytes_len);
    printf("\n");

    // Generate base_psk using password and salt
    byte* base_psk = (byte*)malloc(32);
    if (!base_psk) {
        fprintf(stderr, "Memory allocation failed\n");
        free(packet); free(key_len_str); free(salt_hex); free(salt);
        return;
    }

    // Get password input
    printf("\n========== PSK (Pre-Shared Key) Setup ==========\n");
    printf("Enter password (will be hashed with salt to generate PSK): ");
    char* password = read_dynamic_line("");
    if (!password) {
        fprintf(stderr, "Failed to read password\n");
        free(packet); free(key_len_str); free(salt_hex); free(salt); free(base_psk);
        return;
    }

    // Concatenate password and salt, then hash
    size_t password_len = strlen(password);
    byte* password_salt = (byte*)malloc(password_len + salt_bytes_len);
    if (!password_salt) {
        fprintf(stderr, "Memory allocation failed\n");
        memset(password, 0, password_len);
        free(password);
        free(packet); free(key_len_str); free(salt_hex); free(salt); free(base_psk);
        return;
    }
    memcpy(password_salt, password, password_len);
    memcpy(password_salt + password_len, salt, salt_bytes_len);
    sha256(password_salt, password_len + salt_bytes_len, base_psk);

    // Clear password from memory
    memset(password, 0, password_len);
    memset(password_salt, 0, password_len + salt_bytes_len);
    free(password);
    free(password_salt);

    printf("Base PSK (SHA-256 of password || salt) generated: ");
    print_hex(base_psk, 32);
    printf("\n");

    // Derive K_enc and K_mac from base_psk
    byte* k_enc = (byte*)malloc(key_len);
    byte* k_mac = (byte*)malloc(key_len);
    if (!k_enc || !k_mac) {
        fprintf(stderr, "Memory allocation failed\n");
        free(packet); free(key_len_str); free(salt_hex); free(salt); free(base_psk);
        if (k_enc) free(k_enc);
        if (k_mac) free(k_mac);
        return;
    }
    derive_keys_from_psk(base_psk, k_enc, k_mac, key_len);
    free(base_psk);

    // Automatically extract remaining information from packet
    char* mode_str = extract_value_from_packet(packet, "MODE");
    if (!mode_str) {
        fprintf(stderr, "Error: MODE not found in packet\n");
        free(packet); free(key_len_str); free(salt_hex); free(salt); free(k_enc); free(k_mac);
        return;
    }
    int mode_selection = atoi(mode_str);
    if (mode_selection < 1 || mode_selection > 3) {
        fprintf(stderr, "Error: Invalid MODE value\n");
        free(packet); free(mode_str); free(key_len_str); free(salt_hex); free(salt); free(k_enc); free(k_mac);
        return;
    }

    char* sha_algorithm_str = extract_value_from_packet(packet, "SHA_ALGORITHM");
    if (!sha_algorithm_str) {
        fprintf(stderr, "Error: SHA_ALGORITHM not found in packet\n");
        free(packet); free(mode_str); free(key_len_str); free(salt_hex); free(salt); free(k_enc); free(k_mac);
        return;
    }
    int sha_algorithm = atoi(sha_algorithm_str);
    if (sha_algorithm != 1 && sha_algorithm != 2) {
        fprintf(stderr, "Error: Invalid SHA_ALGORITHM value\n");
        free(packet); free(mode_str); free(key_len_str); free(sha_algorithm_str); free(salt_hex); free(salt); free(k_enc); free(k_mac);
        return;
    }

    const byte* key = k_enc;  // Use K_enc as decryption key

    char* ciphertext_hex = extract_value_from_packet(packet, "CIPHERTEXT");
    if (!ciphertext_hex) {
        fprintf(stderr, "Error: CIPHERTEXT not found in packet\n");
        free(packet); free(mode_str); free(key_len_str); free(sha_algorithm_str); free(salt_hex); free(salt); free(k_enc); free(k_mac);
        return;
    }
    char* sha_hex = extract_value_from_packet(packet, "SHA");
    if (!sha_hex) {
        fprintf(stderr, "Error: SHA not found in packet\n");
        free(packet); free(mode_str); free(key_len_str); free(sha_algorithm_str); free(salt_hex); free(salt); free(k_enc); free(k_mac); free(ciphertext_hex);
        return;
    }

    char* iv_hex = NULL;
    char* nonce_hex = NULL;
    if (mode_selection == 2) {
        iv_hex = extract_value_from_packet(packet, "IV");
        if (!iv_hex) {
            fprintf(stderr, "Error: IV not found in packet\n");
            free(packet); free(mode_str); free(key_len_str); free(sha_algorithm_str); free(salt_hex); free(salt); free(k_enc); free(k_mac);
            free(ciphertext_hex); free(sha_hex);
            return;
        }
    }
    else if (mode_selection == 3) {
        nonce_hex = extract_value_from_packet(packet, "NONCE");
        if (!nonce_hex) {
            fprintf(stderr, "Error: NONCE not found in packet\n");
            free(packet); free(mode_str); free(key_len_str); free(sha_algorithm_str); free(salt_hex); free(salt); free(k_enc); free(k_mac);
            free(ciphertext_hex); free(sha_hex);
            return;
        }
    }

    size_t cipher_len;
    byte* ciphertext = hex_string_to_bytes(ciphertext_hex, &cipher_len);
    if (!ciphertext) {
        fprintf(stderr, "Invalid ciphertext\n");
        free(packet); free(mode_str); free(key_len_str); free(sha_algorithm_str); free(salt_hex); free(salt); free(k_enc); free(k_mac);
        free(ciphertext_hex); free(sha_hex);
        if (iv_hex) free(iv_hex);
        if (nonce_hex) free(nonce_hex);
        return;
    }

    size_t sha_hex_len = strlen(sha_hex);
    size_t expected_sha_len = (sha_algorithm == 1) ? 64 : 128;
    if (sha_hex_len != expected_sha_len) {
        fprintf(stderr, "Invalid SHA length\n");
        free(packet); free(mode_str); free(key_len_str); free(sha_algorithm_str); free(salt_hex); free(salt); free(k_enc); free(k_mac);
        free(ciphertext_hex); free(sha_hex);
        if (iv_hex) free(iv_hex);
        if (nonce_hex) free(nonce_hex);
        free(ciphertext);
        return;
    }

    byte expected_hash[64];
    size_t expected_hash_len;
    size_t sha_bytes_len;
    byte* sha_bytes = hex_string_to_bytes(sha_hex, &sha_bytes_len);
    if (!sha_bytes) {
        fprintf(stderr, "Invalid SHA format\n");
        free(packet); free(mode_str); free(key_len_str); free(sha_algorithm_str); free(salt_hex); free(salt); free(k_enc); free(k_mac);
        free(ciphertext_hex); free(sha_hex);
        if (iv_hex) free(iv_hex);
        if (nonce_hex) free(nonce_hex);
        free(ciphertext);
        return;
    }
    memcpy(expected_hash, sha_bytes, sha_bytes_len);
    expected_hash_len = sha_bytes_len;

    // constant-time fix: Encrypt-then-MAC requires MAC verification BEFORE decryption
    // Verify HMAC first to prevent decryption of tampered data
    byte computed_hash[64];
    hmac(k_mac, key_len, ciphertext, cipher_len, computed_hash, sha_algorithm);

    // constant-time fix: use constant-time memory comparison
    int integrity_ok = (constant_time_memcmp(computed_hash, expected_hash, expected_hash_len) == 0);

    // Only decrypt if MAC verification succeeds (Encrypt-then-MAC security requirement)
    if (!integrity_ok) {
        printf("\n=== Integrity Verification ===\n");
        printf("Expected SHA: ");
        for (size_t i = 0; i < expected_hash_len; i++) printf("%02X", expected_hash[i]);
        printf("\n");
        printf("Computed SHA: ");
        for (size_t i = 0; i < expected_hash_len; i++) printf("%02X", computed_hash[i]);
        printf("\n");
        printf("Result: Failed - Integrity verification failed! Decryption aborted.\n");
        printf("==============================\n");

        // Cleanup and return without decrypting
        free(packet);
        free(mode_str);
        free(key_len_str);
        free(sha_algorithm_str);
        free(ciphertext_hex);
        free(sha_hex);
        if (iv_hex) free(iv_hex);
        if (nonce_hex) free(nonce_hex);
        free(ciphertext);
        free(sha_bytes);
        free(salt_hex);
        free(salt);
        free(k_enc);
        free(k_mac);
        return;
    }

    // MAC verification succeeded, proceed with decryption
    byte* decrypted = malloc(cipher_len + 1);
    size_t actual_len = cipher_len;

    // Automatically decrypt using information extracted from packet
    if (mode_selection == 1) {
        AES_ECB(ciphertext, decrypted, cipher_len, key, key_len, 0);
        // constant-time fix: use constant-time PKCS#7 padding validation
        constant_time_pkcs7_unpad(decrypted, cipher_len, &actual_len);
    }
    else if (mode_selection == 2) {
        size_t iv_bytes_len;
        byte* iv_bytes = hex_string_to_bytes(iv_hex, &iv_bytes_len);
        if (!iv_bytes || iv_bytes_len != 16) {
            fprintf(stderr, "Invalid IV\n");
            free(packet); free(mode_str); free(key_len_str); free(sha_algorithm_str); free(salt_hex); free(salt); free(k_enc); free(k_mac);
            free(ciphertext_hex); free(sha_hex);
            free(iv_hex); free(nonce_hex);
            free(ciphertext); free(decrypted);
            if (iv_bytes) free(iv_bytes);
            return;
        }
        AES_CBC(ciphertext, decrypted, cipher_len, key, iv_bytes, key_len, 0);
        // constant-time fix: use constant-time PKCS#7 padding validation
        constant_time_pkcs7_unpad(decrypted, cipher_len, &actual_len);
        free(iv_bytes);
    }
    else if (mode_selection == 3) {
        size_t nonce_bytes_len;
        byte* nonce_bytes = hex_string_to_bytes(nonce_hex, &nonce_bytes_len);
        if (!nonce_bytes || nonce_bytes_len != 12) {
            fprintf(stderr, "Invalid NONCE (expected 12 bytes)\n");
            free(packet); free(mode_str); free(key_len_str); free(sha_algorithm_str); free(salt_hex); free(salt); free(k_enc); free(k_mac);
            free(ciphertext_hex); free(sha_hex);
            free(iv_hex); free(nonce_hex);
            free(ciphertext); free(decrypted);
            if (nonce_bytes) free(nonce_bytes);
            return;
        }
        AES_CTR(ciphertext, decrypted, cipher_len, key, nonce_bytes, key_len);
        free(nonce_bytes);
    }

    decrypted[actual_len] = '\0';
    printf("\nDecrypted data: %s\n", decrypted);

    printf("\n=== Integrity Verification ===\n");
    printf("Expected SHA: ");
    for (size_t i = 0; i < expected_hash_len; i++) printf("%02X", expected_hash[i]);
    printf("\n");
    printf("Computed SHA: ");
    for (size_t i = 0; i < expected_hash_len; i++) printf("%02X", computed_hash[i]);
    printf("\n");
    if (integrity_ok) {
        printf("Result: Success - Integrity verified!\n");
    }
    else {
        printf("Result: Failed - Integrity verification failed!\n");
    }
    printf("==============================\n");

    free(packet);
    free(mode_str);
    free(key_len_str);
    free(sha_algorithm_str);
    free(ciphertext_hex);
    free(sha_hex);
    if (iv_hex) free(iv_hex);
    if (nonce_hex) free(nonce_hex);
    free(ciphertext);
    free(decrypted);
    free(sha_bytes);
    free(salt_hex);
    free(salt);
    free(k_enc);
    free(k_mac);
}

/* =============================================================================
 * =============================================================================
 * Performance Measurement Section
 * =============================================================================
 * This section contains function calls related to performance measurement.
 * The performance_test function is implemented in performance.c and
 * measures the performance of AES encryption/decryption.
 * =============================================================================
 * ============================================================================= */

// --- Performance measurement functions ---

/* Performance results output function */

// --- MAIN function ---
int main() {
    int continue_program = 1;  // Program loop flag
    int network_initialized = 0;  // Network initialization status

    // Initialize network (if needed)
    if (init_network() == 0) {
        network_initialized = 1;
    }

    while (continue_program) {
        int main_choice = 0, mode_selection = 0, key_selection = 0;
        size_t key_len = 0;
        int use_network = 0;  // Network usage flag

        printf("=======================================================\n");
        printf("  AES Encryption/Decryption Program\n");
        printf("=======================================================\n\n");

        // Main menu selection
        while (1) {
            printf("Select mode:\n");
            printf("1. 암호화 (Encryption)\n");
            printf("2. 복호화 (Decryption)\n");
            printf("3. 통신 (Communication)\n");
            printf("4. 성능측정 (Performance Test)\n");
            printf("\nSelect (1-4): ");
#ifdef _WIN32
            if (scanf_s("%d", &main_choice) == 1 && main_choice >= 1 && main_choice <= 4) {
                while (getchar() != '\n');
                break;
            }
#else
            if (scanf("%d", &main_choice) == 1 && main_choice >= 1 && main_choice <= 4) {
                while (getchar() != '\n');
                break;
            }
#endif
            fprintf(stderr, "\n Invalid input. Please enter 1, 2, 3, or 4. \n");
            while (getchar() != '\n');
        }

        if (main_choice == 1) {
            // Encryption mode
            // Sender mode: Need to select AES mode, SHA, key length
            // 2. Mode selection
            while (1) {
                printf("\nSelect AES encryption mode:\n");
                printf("1. AES-ECB Mode\n");
                printf("2. AES-CBC Mode\n");
                printf("3. AES-CTR Mode\n");
                printf("4. All-MODES\n");
                printf("\nSelect (1-4): ");
#ifdef _WIN32
                if (scanf_s("%d", &mode_selection) == 1 && mode_selection >= 1 && mode_selection <= 4) {
                    while (getchar() != '\n');
                    break;
                }
#else
                if (scanf("%d", &mode_selection) == 1 && mode_selection >= 1 && mode_selection <= 4) {
                    while (getchar() != '\n');
                    break;
                }
#endif
                fprintf(stderr, "Invalid input. Please enter a number between 1-4.\n\n");
                while (getchar() != '\n');
            }

            // 3. SHA algorithm selection
            int sha_algorithm = 0;
            while (1) {
                printf("\nSelect SHA hash algorithm:\n");
                printf("1. SHA-256\n");
                printf("2. SHA-512\n");
                printf("\nSelect (1-2): ");
#ifdef _WIN32
                if (scanf_s("%d", &sha_algorithm) == 1 && (sha_algorithm == 1 || sha_algorithm == 2)) {
                    while (getchar() != '\n');
                    break;
                }
#else
                if (scanf("%d", &sha_algorithm) == 1 && (sha_algorithm == 1 || sha_algorithm == 2)) {
                    while (getchar() != '\n');
                    break;
                }
#endif
                fprintf(stderr, "\n Invalid input. Please enter 1 or 2. \n");
                while (getchar() != '\n');
            }

            // 4. Key length selection
            while (1) {
                printf("\nSelect AES key length (128, 192, 256): ");
#ifdef _WIN32
                if (scanf_s("%d", &key_selection) == 1) {
                    while (getchar() != '\n');
                    if (key_selection == 128) { key_len = 16; break; }
                    if (key_selection == 192) { key_len = 24; break; }
                    if (key_selection == 256) { key_len = 32; break; }
                }
#else
                if (scanf("%d", &key_selection) == 1) {
                    while (getchar() != '\n');
                    if (key_selection == 128) { key_len = 16; break; }
                    if (key_selection == 192) { key_len = 24; break; }
                    if (key_selection == 256) { key_len = 32; break; }
                }
#endif
                else {
                    while (getchar() != '\n');
                }
                fprintf(stderr, "Invalid key length. Please enter 128, 192, or 256.\n");
            }

            // 5. Execute encryption test
            if (mode_selection == 1) {
                test_ecb(key_len, 1, sha_algorithm);  // 1 = encryption
            }
            else if (mode_selection == 2) {
                test_cbc(key_len, 1, sha_algorithm);  // 1 = encryption
            }
            else if (mode_selection == 3) {
                test_ctr(key_len, 1, sha_algorithm);  // 1 = encryption
            }
            else if (mode_selection == 4) {
                printf("\n[ALL MODES] Running ECB, CBC, and CTR encryption tests...\n");
                test_ecb(key_len, 1, sha_algorithm);
                test_cbc(key_len, 1, sha_algorithm);
                test_ctr(key_len, 1, sha_algorithm);
            }
        }

        else if (main_choice == 2) {
            // Decryption mode
            // Select mode
            while (1) {
                printf("\nSelect AES decryption mode:\n");
                printf("1. AES-ECB Mode\n");
                printf("2. AES-CBC Mode\n");
                printf("3. AES-CTR Mode\n");
                printf("4. All-MODES\n");
                printf("\nSelect (1-4): ");
#ifdef _WIN32
                if (scanf_s("%d", &mode_selection) == 1 && mode_selection >= 1 && mode_selection <= 4) {
                    while (getchar() != '\n');
                    break;
                }
#else
                if (scanf("%d", &mode_selection) == 1 && mode_selection >= 1 && mode_selection <= 4) {
                    while (getchar() != '\n');
                    break;
                }
#endif
                fprintf(stderr, "Invalid input. Please enter a number between 1-4.\n\n");
                while (getchar() != '\n');
            }

            // SHA algorithm selection
            int sha_algorithm = 0;
            while (1) {
                printf("\nSelect SHA hash algorithm:\n");
                printf("1. SHA-256\n");
                printf("2. SHA-512\n");
                printf("\nSelect (1-2): ");
#ifdef _WIN32
                if (scanf_s("%d", &sha_algorithm) == 1 && (sha_algorithm == 1 || sha_algorithm == 2)) {
                    while (getchar() != '\n');
                    break;
                }
#else
                if (scanf("%d", &sha_algorithm) == 1 && (sha_algorithm == 1 || sha_algorithm == 2)) {
                    while (getchar() != '\n');
                    break;
                }
#endif
                fprintf(stderr, "\n Invalid input. Please enter 1 or 2. \n");
                while (getchar() != '\n');
            }

            // Key length selection
            while (1) {
                printf("\nSelect AES key length (128, 192, 256): ");
#ifdef _WIN32
                if (scanf_s("%d", &key_selection) == 1) {
                    while (getchar() != '\n');
                    if (key_selection == 128) { key_len = 16; break; }
                    if (key_selection == 192) { key_len = 24; break; }
                    if (key_selection == 256) { key_len = 32; break; }
                }
#else
                if (scanf("%d", &key_selection) == 1) {
                    while (getchar() != '\n');
                    if (key_selection == 128) { key_len = 16; break; }
                    if (key_selection == 192) { key_len = 24; break; }
                    if (key_selection == 256) { key_len = 32; break; }
                }
#endif
                else {
                    while (getchar() != '\n');
                }
                fprintf(stderr, "Invalid key length. Please enter 128, 192, or 256.\n");
            }

            // Execute decryption test
            if (mode_selection == 1) {
                test_ecb(key_len, 0, sha_algorithm);  // 0 = decryption
            }
            else if (mode_selection == 2) {
                test_cbc(key_len, 0, sha_algorithm);  // 0 = decryption
            }
            else if (mode_selection == 3) {
                test_ctr(key_len, 0, sha_algorithm);  // 0 = decryption
            }
            else if (mode_selection == 4) {
                printf("\n[ALL MODES] Running ECB, CBC, and CTR decryption tests...\n");
                test_ecb(key_len, 0, sha_algorithm);
                test_cbc(key_len, 0, sha_algorithm);
                test_ctr(key_len, 0, sha_algorithm);
            }
        }
        
        else if (main_choice == 3) {
            // Communication mode
            use_network = 1;
            if (!network_initialized) {
                fprintf(stderr, "Network initialization failed. Exiting program.\n");
                continue;
            }

            // Sender/Receiver selection
            int sender_receiver_choice = 0;
            while (1) {
                printf("\nSelect send/receive mode:\n");
                printf("1. Sender (Enter plaintext Generate encrypted data)\n");
                printf("2. Receiver (Receive data Decrypt and verify integrity)\n");
                printf("\nSelect (1-2): ");
#ifdef _WIN32
                if (scanf_s("%d", &sender_receiver_choice) == 1 && (sender_receiver_choice == 1 || sender_receiver_choice == 2)) {
                    while (getchar() != '\n');
                    break;
                }
#else
                if (scanf("%d", &sender_receiver_choice) == 1 && (sender_receiver_choice == 1 || sender_receiver_choice == 2)) {
                    while (getchar() != '\n');
                    break;
                }
#endif
                fprintf(stderr, "\n Invalid input. Please enter 1 or 2. \n");
                while (getchar() != '\n');
            }

            if (sender_receiver_choice == 1) {
                // Sender mode: Need to select AES mode, SHA, key length
                // Mode selection
                while (1) {
                    printf("\nSelect AES encryption mode:\n");
                    printf("1. AES-ECB Mode\n");
                    printf("2. AES-CBC Mode\n");
                    printf("3. AES-CTR Mode\n");
                    printf("\nSelect (1-3): ");
#ifdef _WIN32
                    if (scanf_s("%d", &mode_selection) == 1 && mode_selection >= 1 && mode_selection <= 3) {
                        while (getchar() != '\n');
                        break;
                    }
#else
                    if (scanf("%d", &mode_selection) == 1 && mode_selection >= 1 && mode_selection <= 3) {
                        while (getchar() != '\n');
                        break;
                    }
#endif
                    fprintf(stderr, "Invalid input. Please enter a number between 1-3.\n\n");
                    while (getchar() != '\n');
                }

                // SHA algorithm selection
                int sha_algorithm = 0;
                while (1) {
                    printf("\nSelect SHA hash algorithm:\n");
                    printf("1. SHA-256\n");
                    printf("2. SHA-512\n");
                    printf("\nSelect (1-2): ");
#ifdef _WIN32
                    if (scanf_s("%d", &sha_algorithm) == 1 && (sha_algorithm == 1 || sha_algorithm == 2)) {
                        while (getchar() != '\n');
                        break;
                    }
#else
                    if (scanf("%d", &sha_algorithm) == 1 && (sha_algorithm == 1 || sha_algorithm == 2)) {
                        while (getchar() != '\n');
                        break;
                    }
#endif
                    fprintf(stderr, "\n Invalid input. Please enter 1 or 2. \n");
                    while (getchar() != '\n');
                }

                // Key length selection
                while (1) {
                    printf("\nSelect AES key length (128, 192, 256): ");
#ifdef _WIN32
                    if (scanf_s("%d", &key_selection) == 1) {
                        while (getchar() != '\n');
                        if (key_selection == 128) { key_len = 16; break; }
                        if (key_selection == 192) { key_len = 24; break; }
                        if (key_selection == 256) { key_len = 32; break; }
                    }
#else
                    if (scanf("%d", &key_selection) == 1) {
                        while (getchar() != '\n');
                        if (key_selection == 128) { key_len = 16; break; }
                        if (key_selection == 192) { key_len = 24; break; }
                        if (key_selection == 256) { key_len = 32; break; }
                    }
#endif
                    else {
                        while (getchar() != '\n');
                    }
                    fprintf(stderr, "Invalid key length. Please enter 128, 192, or 256.\n");
                }

                // Execute sender mode
                sender_mode(mode_selection, key_len, sha_algorithm, NULL, use_network);
            }
            else {
                // Receiver mode: receive packet first, check KEY_LEN, then input PSK
                receiver_mode(use_network);
            }
        }
        else if (main_choice == 4) {
            // ========== Performance Test Mode ==========
            // Performance test mode
            // Key length selection
            while (1) {
                printf("\nSelect AES key length (128, 192, 256): ");
#ifdef _WIN32
                if (scanf_s("%d", &key_selection) == 1) {
                    while (getchar() != '\n');
                    if (key_selection == 128) { key_len = 16; break; }
                    if (key_selection == 192) { key_len = 24; break; }
                    if (key_selection == 256) { key_len = 32; break; }
                }
#else
                if (scanf("%d", &key_selection) == 1) {
                    while (getchar() != '\n');
                    if (key_selection == 128) { key_len = 16; break; }
                    if (key_selection == 192) { key_len = 24; break; }
                    if (key_selection == 256) { key_len = 32; break; }
                }
#endif
                else {
                    while (getchar() != '\n');
                }
                fprintf(stderr, "Invalid key length. Please enter 128, 192, or 256.\n");
            }
            performance_test(key_len);
        }

        printf("\n=======================================================\n");
        printf("  Task completed!\n");
        printf("=======================================================\n\n");

        // 7. Continue or Exit selection
        int continue_choice = 0;
        while (1) {
            printf("\nSelect one of the following:\n");
            printf("1. Return to start\n");
            printf("2. Exit\n");
            printf("\nSelect (1-2): ");

#ifdef _WIN32
            if (scanf_s("%d", &continue_choice) == 1 && (continue_choice == 1 || continue_choice == 2)) {
                while (getchar() != '\n'); // Clear input buffer after scanf
                break;
            }
#else
            if (scanf("%d", &continue_choice) == 1 && (continue_choice == 1 || continue_choice == 2)) {
                while (getchar() != '\n'); // Clear input buffer after scanf
                break;
            }
#endif
            fprintf(stderr, "\n Invalid input. Please enter 1 or 2.\n");
            while (getchar() != '\n'); // Clear input buffer
        }

        if (continue_choice == 2) {
            continue_program = 0;
        }
        else {
            printf("\n");
        }
    }

    // Cleanup network
    if (network_initialized) {
        cleanup_network();
    }

    printf("\n=======================================================\n");
    printf("  Program terminated\n");
    printf("=======================================================\n\n");

    return 0;
}
