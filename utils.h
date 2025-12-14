/*
 * =============================================================================
 * Cross-Platform Utility Functions
 * =============================================================================
 *
 * [Time Measurement]
 * This module provides high-resolution cross-platform timing functions.
 *
 * Note: C++ uses <chrono> for standard time measurement, but this is a C project.
 * For C code, we use the most accurate platform-specific APIs:
 *   - Windows: QueryPerformanceCounter (highest resolution timer on Windows)
 *   - macOS/Linux: clock_gettime(CLOCK_MONOTONIC) (POSIX standard monotonic clock)
 *
 * These are the recommended high-resolution timing APIs for each platform and
 * provide nanosecond-level precision for performance measurement.
 *
 * If you need <chrono> style timing in C++, you can wrap these functions or
 * convert this file to C++ and use std::chrono::high_resolution_clock.
 * =============================================================================
 */

 #ifndef UTILS_H
 #define UTILS_H
 
 #include "common.h"
 
 /* Cross-platform timing headers */
 #ifdef _WIN32
     #include <windows.h>
 #else
     /* POSIX standard for clock_gettime */
     #ifndef _POSIX_C_SOURCE
         #define _POSIX_C_SOURCE 199309L
     #endif
     #include <time.h>
 #endif
 
 /* =============================================================================
  * Constant-Time Security Functions
  * ============================================================================= */
 
 /**
  * Constant-time memory comparison (prevents timing attacks)
  * Returns 0 if equal, non-zero if different
  */
 int constant_time_memcmp(const void* a, const void* b, size_t len);
 
 /**
  * Constant-time PKCS#7 padding validation (prevents padding oracle attacks)
  * Returns 1 if valid, 0 otherwise
  * actual_len is set to the unpadded length if valid
  */
 int constant_time_pkcs7_unpad(const byte* data, size_t data_len, size_t* actual_len);
 
 /* =============================================================================
  * Key Generation
  * ============================================================================= */
 
 /**
  * Cryptographically secure random key generation
  * Uses BCryptGenRandom on Windows, /dev/urandom on Unix-like systems
  */
 int generate_secure_key(byte* key, size_t key_len);
 
 /* =============================================================================
  * General Utilities
  * ============================================================================= */
 
 void print_hex(const byte* data, size_t len);
 char* read_dynamic_line(const char* prompt);
 byte* hex_string_to_bytes(const char* hex_str, size_t* out_len);
 
 /* =============================================================================
  * High-Resolution Performance Timer (Cross-Platform)
  * =============================================================================
  *
  * Platform-specific implementation for maximum precision:
  *   - Windows: Uses QueryPerformanceCounter/QueryPerformanceFrequency
  *   - POSIX (macOS/Linux): Uses clock_gettime with CLOCK_MONOTONIC
  *
  * Both provide nanosecond-level resolution for accurate benchmarking.
  * ============================================================================= */
 
 #ifdef _WIN32
 typedef struct {
     LARGE_INTEGER start;
     LARGE_INTEGER end;
     LARGE_INTEGER frequency;
 } perf_timer;
 #else
 typedef struct {
     struct timespec start;
     struct timespec end;
 } perf_timer;
 #endif
 
 /**
  * Initialize the performance timer
  */
 void perf_timer_init(perf_timer* timer);
 
 /**
  * Start timing measurement
  */
 void perf_timer_start(perf_timer* timer);
 
 /**
  * Stop timing measurement
  */
 void perf_timer_stop(perf_timer* timer);
 
 /**
  * Get elapsed time in milliseconds
  */
 double perf_timer_get_elapsed_ms(perf_timer* timer);
 
 /**
  * Get elapsed time in microseconds
  */
 double perf_timer_get_elapsed_us(perf_timer* timer);
 
 /**
  * Get elapsed time in nanoseconds
  */
 double perf_timer_get_elapsed_ns(perf_timer* timer);
 
 #endif /* UTILS_H */
 