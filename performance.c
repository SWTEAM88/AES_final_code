#include "performance.h"
#include "aes.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Print performance results for a single mode */
void print_performance_results(const char* mode_name, double enc_time_ms, double dec_time_ms, size_t data_size) {
    double throughput_enc;
    double throughput_dec;

    throughput_enc = (data_size / (1024.0 * 1024.0)) / (enc_time_ms / 1000.0);
    throughput_dec = (data_size / (1024.0 * 1024.0)) / (dec_time_ms / 1000.0);

    printf("  %-12s | %12.3f ms | %12.3f ms | %10.2f MB/s | %10.2f MB/s\n",
        mode_name, enc_time_ms, dec_time_ms, throughput_enc, throughput_dec);
}

/* Performance comparison analysis output function */
void print_performance_comparison(double ecb_enc, double ecb_dec, double cbc_enc, double cbc_dec,
    double ctr_enc, double ctr_dec, size_t data_size) {
    double min_enc;
    double min_dec;
    const char* fastest_enc;
    const char* fastest_dec;

    printf("\n");
    printf("===================================================================================\n");
    printf("                         PERFORMANCE COMPARISON ANALYSIS                            \n");
    printf("===================================================================================\n");

#ifdef _WIN32
    printf("\n[Platform] Windows\n");
#elif defined(__APPLE__)
    printf("\n[Platform] macOS\n");
#elif defined(__linux__)
    printf("\n[Platform] Linux\n");
#else
    printf("\n[Platform] Unknown\n");
#endif

    printf("[Data Size] %zu bytes (%.2f KB / %.2f MB)\n\n",
        data_size, data_size / 1024.0, data_size / (1024.0 * 1024.0));

    printf("-----------------------------------------------------------------------------------\n");
    printf("  Mode         |  Encryption    |  Decryption    | Enc Throughput | Dec Throughput\n");
    printf("-----------------------------------------------------------------------------------\n");

    print_performance_results("ECB", ecb_enc, ecb_dec, data_size);
    print_performance_results("CBC", cbc_enc, cbc_dec, data_size);
    print_performance_results("CTR", ctr_enc, ctr_dec, data_size);

    printf("-----------------------------------------------------------------------------------\n");
#ifdef _OPENMP
    printf("  * Parallelization: OpenMP enabled (multi-threaded)\n");
#else
    #ifdef _WIN32
    printf("  * Parallelization: Windows Thread API (multi-threaded)\n");
    #elif defined(__APPLE__) || defined(__linux__) || defined(__unix__)
    printf("  * Parallelization: pthread enabled (multi-threaded)\n");
    #else
    printf("  * Parallelization: Single-threaded\n");
    #endif
#endif
    printf("  * ECB/CTR: Fully parallelized,  CBC: Decryption only (Encryption has dependency)\n");

    min_enc = ecb_enc;
    fastest_enc = "ECB";
    if (cbc_enc < min_enc) { min_enc = cbc_enc; fastest_enc = "CBC"; }
    if (ctr_enc < min_enc) { min_enc = ctr_enc; fastest_enc = "CTR"; }

    min_dec = ecb_dec;
    fastest_dec = "ECB";
    if (cbc_dec < min_dec) { min_dec = cbc_dec; fastest_dec = "CBC"; }
    if (ctr_dec < min_dec) { min_dec = ctr_dec; fastest_dec = "CTR"; }

    printf("\n[Result] Fastest Encryption: %s (%.3f ms) | Fastest Decryption: %s (%.3f ms)\n",
        fastest_enc, min_enc, fastest_dec, min_dec);
}

/* Read file data */
byte* read_file_data(const char* filepath, size_t* data_len) {
    FILE* fp = NULL;
#ifdef _WIN32
    fopen_s(&fp, filepath, "rb");
#else
    fp = fopen(filepath, "rb");
#endif
    if (fp == NULL) {
        perror("Failed to open file");
        fprintf(stderr, "File path: %s\n", filepath);
        return NULL;
    }

    // Get file size
    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    if (file_size < 0) {
        fclose(fp);
        fprintf(stderr, "Failed to get file size\n");
        return NULL;
    }
    fseek(fp, 0, SEEK_SET);

    // Allocate memory
    byte* data = (byte*)malloc(file_size);
    if (data == NULL) {
        fclose(fp);
        fprintf(stderr, "Memory allocation failed\n");
        return NULL;
    }

    // Read file
    size_t read_size = fread(data, 1, file_size, fp);
    fclose(fp);

    if (read_size != (size_t)file_size) {
        free(data);
        fprintf(stderr, "Failed to read file completely\n");
        return NULL;
    }

    *data_len = read_size;
    return data;
}

/* Verify correctness of encryption/decryption for all modes */
void verify_correctness(size_t key_len) {
    const size_t test_data_size = 1024;  // 1KB test data
    byte* test_data;
    byte* key;
    byte iv[AES_BLOCK_SIZE];
    byte nonce[8];
    byte* encrypted;
    byte* decrypted;
    byte* padded_data;
    size_t padded_len;
    size_t i;
    byte pad_value;
    int all_passed = 1;

    printf("\n=== Verifying Algorithms ===\n\n");

    /* Generate test data (random) */
    test_data = (byte*)malloc(test_data_size);
    if (!test_data) {
        fprintf(stderr, "Memory allocation failed for test data\n");
        exit(1);
    }
    if (generate_secure_key(test_data, test_data_size) != 0) {
        fprintf(stderr, "Failed to generate test data\n");
        free(test_data);
        exit(1);
    }

    /* Generate key */
    key = (byte*)malloc(key_len);
    if (!key) {
        fprintf(stderr, "Memory allocation failed for key\n");
        free(test_data);
        exit(1);
    }
    if (generate_secure_key(key, key_len) != 0) {
        fprintf(stderr, "Failed to generate key\n");
        free(test_data);
        free(key);
        exit(1);
    }

    /* Generate IV and nonce */
    if (generate_secure_key(iv, AES_BLOCK_SIZE) != 0 ||
        generate_secure_key(nonce, 8) != 0) {
        fprintf(stderr, "Failed to generate IV/nonce\n");
        free(test_data);
        free(key);
        exit(1);
    }

    /* Test ECB mode */
    padded_len = ((test_data_size + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
    padded_data = (byte*)malloc(padded_len);
    encrypted = (byte*)malloc(padded_len);
    decrypted = (byte*)malloc(padded_len);

    if (!padded_data || !encrypted || !decrypted) {
        fprintf(stderr, "Memory allocation failed\n");
        free(test_data);
        free(key);
        if (padded_data) free(padded_data);
        if (encrypted) free(encrypted);
        if (decrypted) free(decrypted);
        exit(1);
    }

    /* Prepare padded data for ECB */
    memcpy(padded_data, test_data, test_data_size);
    pad_value = (byte)(padded_len - test_data_size);
    for (i = test_data_size; i < padded_len; i++) {
        padded_data[i] = pad_value;
    }

    AES_ECB(padded_data, encrypted, padded_len, key, key_len, 1);
    AES_ECB(encrypted, decrypted, padded_len, key, key_len, 0);

    /* Remove padding and verify */
    size_t actual_len = padded_len;
    constant_time_pkcs7_unpad(decrypted, padded_len, &actual_len);

    if (actual_len != test_data_size || memcmp(test_data, decrypted, test_data_size) != 0) {
        fprintf(stderr, "[FAIL] ECB Mode: Data mismatch!\n");
        all_passed = 0;
    }
    else {
        printf("[Pass] ECB Mode: Integrity Confirmed\n");
    }

    /* Test CBC mode */
    memcpy(padded_data, test_data, test_data_size);
    pad_value = (byte)(padded_len - test_data_size);
    for (i = test_data_size; i < padded_len; i++) {
        padded_data[i] = pad_value;
    }

    AES_CBC(padded_data, encrypted, padded_len, key, iv, key_len, 1);
    AES_CBC(encrypted, decrypted, padded_len, key, iv, key_len, 0);

    /* Remove padding and verify */
    actual_len = padded_len;
    constant_time_pkcs7_unpad(decrypted, padded_len, &actual_len);

    if (actual_len != test_data_size || memcmp(test_data, decrypted, actual_len) != 0) {
        fprintf(stderr, "[FAIL] CBC Mode: Data mismatch!\n");
        all_passed = 0;
    }
    else {
        printf("[Pass] CBC Mode: Integrity Confirmed\n");
    }

    /* Test CTR mode (no padding needed) */
    free(padded_data);
    free(encrypted);
    free(decrypted);

    encrypted = (byte*)malloc(test_data_size);
    decrypted = (byte*)malloc(test_data_size);

    if (!encrypted || !decrypted) {
        fprintf(stderr, "Memory allocation failed\n");
        free(test_data);
        free(key);
        if (encrypted) free(encrypted);
        if (decrypted) free(decrypted);
        exit(1);
    }

    AES_CTR(test_data, encrypted, test_data_size, key, nonce, key_len);
    AES_CTR(encrypted, decrypted, test_data_size, key, nonce, key_len);

    /* Verify (CTR has no padding) */
    if (memcmp(test_data, decrypted, test_data_size) != 0) {
        fprintf(stderr, "[FAIL] CTR Mode: Data mismatch!\n");
        all_passed = 0;
    }
    else {
        printf("[Pass] CTR Mode: Integrity Confirmed\n");
    }

    /* Cleanup */
    free(test_data);
    free(key);
    free(encrypted);
    free(decrypted);

    if (!all_passed) {
        fprintf(stderr, "\nERROR: Algorithm verification failed! Program terminated.\n");
        exit(1);
    }

    printf("\n============================\n\n");
}

/* Performance test function */
void performance_test(size_t key_len) {
    char* filepath;
    byte* original_data;
    byte* key;
    byte iv[AES_BLOCK_SIZE];
    byte nonce[8];
    byte* padded_data;
    byte* encrypted_ecb;
    byte* decrypted_ecb;
    byte* encrypted_cbc;
    byte* decrypted_cbc;
    byte* encrypted_ctr;
    byte* decrypted_ctr;
    size_t data_len;
    size_t padded_len;
    size_t i;
    size_t alloc_size;
    byte pad_value;
    perf_timer timer;
    double ecb_enc_time, ecb_dec_time;
    double cbc_enc_time, cbc_dec_time;
    double ctr_enc_time, ctr_dec_time;
    int ecb_valid, cbc_valid, ctr_valid;

    printf("\n========== AES Performance Test (AES-%zu) ==========\n\n", key_len * 8);

    /* Verify correctness before running benchmark */
    verify_correctness(key_len);

    filepath = read_dynamic_line("Enter file path for performance test: ");
    if (filepath == NULL) {
        fprintf(stderr, "Failed to read file path\n");
        return;
    }

    /* Debug: print the file path that was read */
    printf("Attempting to open file: [%s]\n", filepath);
    printf("File path length: %zu characters\n", strlen(filepath));

    data_len = 0;
    original_data = read_file_data(filepath, &data_len);

    if (original_data == NULL) {
        fprintf(stderr, "Failed to read file. Please check the file path.\n");
        fprintf(stderr, "File path received: [%s]\n", filepath);
        fprintf(stderr, "Tip: On macOS, you can drag and drop the file into the terminal to get the full path.\n");
        fprintf(stderr, "Tip: Make sure the file path does not contain extra spaces or quotes.\n");
        free(filepath);
        return;
    }

    free(filepath);

    printf("File loaded successfully: %zu bytes\n\n", data_len);

    key = (byte*)malloc(key_len);
    if (key == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        free(original_data);
        return;
    }

    if (generate_secure_key(key, key_len) != 0 ||
        generate_secure_key(iv, AES_BLOCK_SIZE) != 0 ||
        generate_secure_key(nonce, 8) != 0) {
        fprintf(stderr, "Failed to generate secure key/IV/nonce\n");
        free(key);
        free(original_data);
        return;
    }

    padded_len = ((data_len / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE;
    alloc_size = data_len > 0 ? data_len : 1;

    padded_data = (byte*)malloc(padded_len);
    encrypted_ecb = (byte*)malloc(padded_len);
    decrypted_ecb = (byte*)malloc(padded_len);
    encrypted_cbc = (byte*)malloc(padded_len);
    decrypted_cbc = (byte*)malloc(padded_len);
    encrypted_ctr = (byte*)malloc(alloc_size);
    decrypted_ctr = (byte*)malloc(alloc_size);

    if (padded_data == NULL || encrypted_ecb == NULL || decrypted_ecb == NULL ||
        encrypted_cbc == NULL || decrypted_cbc == NULL || encrypted_ctr == NULL ||
        decrypted_ctr == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        free(padded_data); free(encrypted_ecb); free(decrypted_ecb);
        free(encrypted_cbc); free(decrypted_cbc); free(encrypted_ctr);
        free(decrypted_ctr);
        free(key); free(original_data);
        return;
    }

    memset(padded_data, 0, padded_len);
    if (data_len > 0) {
        memcpy(padded_data, original_data, data_len);
    }
    pad_value = (byte)(padded_len - data_len);
    for (i = data_len; i < padded_len; i++) {
        padded_data[i] = pad_value;
    }

    perf_timer_init(&timer);

    printf("Running performance tests...\n\n");

    /* Cache warmup - run each mode once to load T-Tables and code into CPU cache */
    printf("Warming up CPU cache...\n");
    AES_ECB(padded_data, encrypted_ecb, padded_len, key, key_len, 1);
    AES_CBC(padded_data, encrypted_cbc, padded_len, key, iv, key_len, 1);
    AES_CTR(original_data, encrypted_ctr, data_len, key, nonce, key_len);
    printf("Warmup complete.\n\n");

    /* Run each test 3 times and take average for more accurate results */
    #define TEST_ITERATIONS 3
    int iter;

    printf("Testing ECB mode (3 iterations)...\n");
    ecb_enc_time = 0;
    ecb_dec_time = 0;
    for (iter = 0; iter < TEST_ITERATIONS; iter++) {
        perf_timer_start(&timer);
        AES_ECB(padded_data, encrypted_ecb, padded_len, key, key_len, 1);
        perf_timer_stop(&timer);
        ecb_enc_time += perf_timer_get_elapsed_ms(&timer);

        perf_timer_start(&timer);
        AES_ECB(encrypted_ecb, decrypted_ecb, padded_len, key, key_len, 0);
        perf_timer_stop(&timer);
        ecb_dec_time += perf_timer_get_elapsed_ms(&timer);
    }
    ecb_enc_time /= TEST_ITERATIONS;
    ecb_dec_time /= TEST_ITERATIONS;

    printf("Testing CBC mode (3 iterations)...\n");
    cbc_enc_time = 0;
    cbc_dec_time = 0;
    for (iter = 0; iter < TEST_ITERATIONS; iter++) {
        perf_timer_start(&timer);
        AES_CBC(padded_data, encrypted_cbc, padded_len, key, iv, key_len, 1);
        perf_timer_stop(&timer);
        cbc_enc_time += perf_timer_get_elapsed_ms(&timer);

        perf_timer_start(&timer);
        AES_CBC(encrypted_cbc, decrypted_cbc, padded_len, key, iv, key_len, 0);
        perf_timer_stop(&timer);
        cbc_dec_time += perf_timer_get_elapsed_ms(&timer);
    }
    cbc_enc_time /= TEST_ITERATIONS;
    cbc_dec_time /= TEST_ITERATIONS;

    printf("Testing CTR mode (3 iterations)...\n");
    ctr_enc_time = 0;
    ctr_dec_time = 0;
    for (iter = 0; iter < TEST_ITERATIONS; iter++) {
        perf_timer_start(&timer);
        AES_CTR(original_data, encrypted_ctr, data_len, key, nonce, key_len);
        perf_timer_stop(&timer);
        ctr_enc_time += perf_timer_get_elapsed_ms(&timer);

        perf_timer_start(&timer);
        AES_CTR(encrypted_ctr, decrypted_ctr, data_len, key, nonce, key_len);
        perf_timer_stop(&timer);
        ctr_dec_time += perf_timer_get_elapsed_ms(&timer);
    }
    ctr_enc_time /= TEST_ITERATIONS;
    ctr_dec_time /= TEST_ITERATIONS;

    printf("\nVerifying results...\n");
    ecb_valid = (data_len > 0) ? (memcmp(padded_data, decrypted_ecb, data_len) == 0) : 1;
    cbc_valid = (data_len > 0) ? (memcmp(padded_data, decrypted_cbc, data_len) == 0) : 1;
    ctr_valid = (data_len > 0) ? (memcmp(original_data, decrypted_ctr, data_len) == 0) : 1;

    printf("  ECB:    %s\n", ecb_valid ? "PASSED" : "FAILED");
    printf("  CBC:    %s\n", cbc_valid ? "PASSED" : "FAILED");
    printf("  CTR:    %s\n", ctr_valid ? "PASSED" : "FAILED");

    print_performance_comparison(ecb_enc_time, ecb_dec_time,
        cbc_enc_time, cbc_dec_time,
        ctr_enc_time, ctr_dec_time, data_len);

    free(key);
    free(original_data);
    free(padded_data);
    free(encrypted_ecb);
    free(decrypted_ecb);
    free(encrypted_cbc);
    free(decrypted_cbc);
    free(encrypted_ctr);
    free(decrypted_ctr);
}

