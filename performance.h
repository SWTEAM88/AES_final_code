#ifndef PERFORMANCE_H
#define PERFORMANCE_H

#include "common.h"

// Algorithm correctness verification
void verify_correctness(size_t key_len);

// Performance test main function
void performance_test(size_t key_len);

// Performance result printing functions
void print_performance_results(const char* mode_name, double enc_time_ms, double dec_time_ms, size_t data_size);
void print_performance_comparison(double ecb_enc, double ecb_dec, double cbc_enc, double cbc_dec, 
                                   double ctr_enc, double ctr_dec, size_t data_size);

// File reading utility
byte* read_file_data(const char* filepath, size_t* data_len);

#endif // PERFORMANCE_H

