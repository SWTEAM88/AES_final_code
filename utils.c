/*
 * =============================================================================
 * Cross-Platform Utility Functions Implementation
 * =============================================================================
 *
 * This module provides:
 * - Constant-time security functions
 * - Secure random key generation
 * - High-resolution timing (cross-platform)
 * - General utility functions
 *
 * [Time Measurement Note]
 * C uses platform-specific APIs for high-resolution timing:
 *   - Windows: QueryPerformanceCounter (sub-microsecond precision)
 *   - POSIX: clock_gettime(CLOCK_MONOTONIC) (nanosecond precision)
 *
 * For C++ projects, consider using std::chrono::high_resolution_clock.
 * =============================================================================
 */

 #include "utils.h"
 #include "aes.h"
 #include <string.h>
 #include <stdio.h>
 #include <stdlib.h>
 #include <ctype.h>
 
 /* Platform-specific includes */
 #ifdef _WIN32
     #pragma comment(lib, "bcrypt.lib")
     #include <bcrypt.h>
 #endif
 
 /* =============================================================================
  * Constant-Time Security Functions
  * ============================================================================= */
 
 /**
  * Constant-time memory comparison (prevents timing attacks)
  * Always compares all bytes regardless of differences
  */
 int constant_time_memcmp(const void* a, const void* b, size_t len) {
     const unsigned char* pa = (const unsigned char*)a;
     const unsigned char* pb = (const unsigned char*)b;
     unsigned char diff = 0;
     size_t i;
 
     for (i = 0; i < len; i++) {
         diff |= pa[i] ^ pb[i];
     }
 
     return (int)diff;
 }
 
 /**
  * Constant-time PKCS#7 padding validation (prevents padding oracle attacks)
  * Returns 1 if padding is valid, 0 otherwise
  */
 int constant_time_pkcs7_unpad(const byte* data, size_t data_len, size_t* actual_len) {
     if (data_len == 0 || (data_len % AES_BLOCK_SIZE) != 0) {
         return 0;
     }
 
     byte pad_len = data[data_len - 1];
     unsigned char valid = 1;
     size_t i;
 
     /* Check if pad_len is in valid range [1, AES_BLOCK_SIZE] */
     valid &= (pad_len > 0) & (pad_len <= AES_BLOCK_SIZE);
 
     /* Constant-time check: verify all padding bytes are equal to pad_len */
     for (i = 0; i < AES_BLOCK_SIZE; i++) {
         size_t idx = data_len - 1 - i;
         byte expected = pad_len;
         unsigned char in_range = (idx < data_len) & (i < pad_len);
         unsigned char mask = -(in_range & 1);
         valid &= ~(mask & (data[idx] ^ expected));
     }
 
     /* Constant-time selection of result */
     size_t pad_start = data_len - pad_len;
     unsigned char valid_mask = -(valid & 1);
     *actual_len = (pad_start & valid_mask) | (data_len & ~valid_mask);
 
     return (int)valid;
 }
 
 /* =============================================================================
  * Secure Key Generation
  * ============================================================================= */
 
 /**
  * Generate cryptographically secure random bytes
  * Uses platform-specific secure random sources
  */
 int generate_secure_key(byte* key, size_t key_len) {
 #ifdef _WIN32
     /* Windows: Use BCryptGenRandom (cryptographically secure) */
     NTSTATUS status = BCryptGenRandom(NULL, key, (ULONG)key_len, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
     if (!BCRYPT_SUCCESS(status)) {
         fprintf(stderr, "BCryptGenRandom failed with status: 0x%x\n", (unsigned int)status);
         return -1;
     }
 #else
     /* Unix/Linux/macOS: Use /dev/urandom (cryptographically secure) */
     FILE* fp = fopen("/dev/urandom", "rb");
     if (!fp) {
         perror("Failed to open /dev/urandom");
         return -1;
     }
     if (fread(key, 1, key_len, fp) != key_len) {
         fprintf(stderr, "Failed to read %zu bytes from /dev/urandom\n", key_len);
         fclose(fp);
         return -1;
     }
     fclose(fp);
 #endif
     return 0;
 }
 
 /* =============================================================================
  * General Utilities
  * ============================================================================= */
 
 /**
  * Print data as hexadecimal string
  */
 void print_hex(const byte* data, size_t len) {
     for (size_t i = 0; i < len; i++) {
         printf("%02X", data[i]);
     }
     printf("\n");
 }
 
 /**
  * Read a line of input dynamically (handles arbitrary length)
  */
 char* read_dynamic_line(const char* prompt) {
     size_t capacity = 128;
     char* buffer = (char*)malloc(capacity);
     if (buffer == NULL) return NULL;
 
     size_t len = 0;
     int c;
 
     printf("%s", prompt);
     fflush(stdout);
 
     /* Skip remaining newline character in buffer */
     c = fgetc(stdin);
     if (c == '\n') {
         c = fgetc(stdin);
     }
 
    /* Read input with backslash escape handling */
    while (c != '\n' && c != EOF) {
        if (len + 1 >= capacity) {
            capacity *= 2;
            char* new_buffer = (char*)realloc(buffer, capacity);
            if (new_buffer == NULL) {
                free(buffer);
                return NULL;
            }
            buffer = new_buffer;
        }
        
        /* Handle backslash escape: only on Unix/macOS, and only when followed by space or special char
         * On Windows, backslash is a path separator, so we preserve it
         * On Unix/macOS, backslash followed by space is treated as escape (for spaces in filenames) */
#ifndef _WIN32
        if (c == '\\') {
            int next_c = fgetc(stdin);
            if (next_c != '\n' && next_c != EOF) {
                /* On Unix/macOS: treat backslash as escape for spaces in filenames */
                buffer[len++] = (char)next_c;
            } else {
                /* Backslash at end of line, just skip it */
            }
        } else {
            buffer[len++] = (char)c;
        }
#else
        /* On Windows: preserve all backslashes (they are path separators) */
        buffer[len++] = (char)c;
#endif
        c = fgetc(stdin);
    }
    buffer[len] = '\0';

    /* Remove trailing whitespace */
    while (len > 0 && (buffer[len - 1] == ' ' || buffer[len - 1] == '\t' ||
        buffer[len - 1] == '\n' || buffer[len - 1] == '\r')) {
        buffer[--len] = '\0';
    }

    /* Remove leading and trailing quotes (for drag-and-drop on macOS) */
    if (len > 0 && (buffer[0] == '"' || buffer[0] == '\'')) {
        if (len > 1 && buffer[len - 1] == buffer[0]) {
            memmove(buffer, buffer + 1, len - 2);
            buffer[len - 2] = '\0';
            len -= 2;
        }
        else if (buffer[0] == '"' || buffer[0] == '\'') {
            memmove(buffer, buffer + 1, len - 1);
            buffer[len - 1] = '\0';
            len--;
        }
    }

    return buffer;
 }
 
 /**
  * Convert hexadecimal string to byte array
  */
 byte* hex_string_to_bytes(const char* hex_str, size_t* out_len) {
     size_t len = strlen(hex_str);
     size_t hex_chars = 0;
     for (size_t i = 0; i < len; ++i) {
         if (!isspace(hex_str[i])) hex_chars++;
     }
 
     if (hex_chars % 2 != 0) {
         fprintf(stderr, "Error: Hex string must have even length.\n");
         return NULL;
     }
 
     *out_len = hex_chars / 2;
     byte* bytes = (byte*)malloc(*out_len);
     if (bytes == NULL) {
         fprintf(stderr, "Memory allocation failed\n");
         return NULL;
     }
 
     size_t byte_idx = 0;
     for (size_t i = 0; i < len && byte_idx < *out_len; ) {
         while (i < len && isspace(hex_str[i])) i++;
         if (i >= len) break;
 #ifdef _WIN32
         sscanf_s(&hex_str[i], "%2hhx", &bytes[byte_idx++]);
 #else
         sscanf(&hex_str[i], "%2hhx", &bytes[byte_idx++]);
 #endif
         i += 2;
     }
     return bytes;
 }
 
 /* =============================================================================
  * High-Resolution Performance Timer Implementation
  * =============================================================================
  *
  * Cross-platform timing using:
  *   - Windows: QueryPerformanceCounter (typical resolution: < 1 microsecond)
  *   - POSIX: clock_gettime(CLOCK_MONOTONIC) (typical resolution: nanoseconds)
  *
  * Both use monotonic clocks that are not affected by system time changes,
  * making them ideal for performance measurement.
  * ============================================================================= */
 
 /**
  * Initialize performance timer
  */
 void perf_timer_init(perf_timer* timer) {
 #ifdef _WIN32
     QueryPerformanceFrequency(&timer->frequency);
     timer->start.QuadPart = 0;
     timer->end.QuadPart = 0;
 #else
     timer->start.tv_sec = 0;
     timer->start.tv_nsec = 0;
     timer->end.tv_sec = 0;
     timer->end.tv_nsec = 0;
 #endif
 }
 
 /**
  * Start timing measurement
  */
 void perf_timer_start(perf_timer* timer) {
 #ifdef _WIN32
     QueryPerformanceCounter(&timer->start);
 #else
     clock_gettime(CLOCK_MONOTONIC, &timer->start);
 #endif
 }
 
 /**
  * Stop timing measurement
  */
 void perf_timer_stop(perf_timer* timer) {
 #ifdef _WIN32
     QueryPerformanceCounter(&timer->end);
 #else
     clock_gettime(CLOCK_MONOTONIC, &timer->end);
 #endif
 }
 
 /**
  * Get elapsed time in milliseconds
  */
 double perf_timer_get_elapsed_ms(perf_timer* timer) {
 #ifdef _WIN32
     if (timer->frequency.QuadPart == 0) {
         QueryPerformanceFrequency(&timer->frequency);
     }
     return (double)(timer->end.QuadPart - timer->start.QuadPart) * 1000.0 
            / (double)timer->frequency.QuadPart;
 #else
     double elapsed = (double)(timer->end.tv_sec - timer->start.tv_sec) * 1000.0;
     elapsed += (double)(timer->end.tv_nsec - timer->start.tv_nsec) / 1000000.0;
     return elapsed;
 #endif
 }
 
 /**
  * Get elapsed time in microseconds
  */
 double perf_timer_get_elapsed_us(perf_timer* timer) {
 #ifdef _WIN32
     if (timer->frequency.QuadPart == 0) {
         QueryPerformanceFrequency(&timer->frequency);
     }
     return (double)(timer->end.QuadPart - timer->start.QuadPart) * 1000000.0 
            / (double)timer->frequency.QuadPart;
 #else
     double elapsed = (double)(timer->end.tv_sec - timer->start.tv_sec) * 1000000.0;
     elapsed += (double)(timer->end.tv_nsec - timer->start.tv_nsec) / 1000.0;
     return elapsed;
 #endif
 }
 
 /**
  * Get elapsed time in nanoseconds
  */
 double perf_timer_get_elapsed_ns(perf_timer* timer) {
 #ifdef _WIN32
     if (timer->frequency.QuadPart == 0) {
         QueryPerformanceFrequency(&timer->frequency);
     }
     return (double)(timer->end.QuadPart - timer->start.QuadPart) * 1000000000.0 
            / (double)timer->frequency.QuadPart;
 #else
     double elapsed = (double)(timer->end.tv_sec - timer->start.tv_sec) * 1000000000.0;
     elapsed += (double)(timer->end.tv_nsec - timer->start.tv_nsec);
     return elapsed;
 #endif
 }
 