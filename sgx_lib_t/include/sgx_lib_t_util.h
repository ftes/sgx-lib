#ifndef SGX_LIB_T_UTIL_H
#define SGX_LIB_T_UTIL_H

#include <stdarg.h>
#include <sgx_tseal.h>

char* vsprintf(char* format, va_list args);
void check(sgx_status_t rc);
size_t get_sealed_data_size(size_t plaintext_data_size);
int seal(const void* plaintext_buffer, size_t plaintext_data_size, sgx_sealed_data_t* sealed_buffer, size_t sealed_data_size);
int unseal(void* plaintext_buffer, size_t plaintext_data_size, sgx_sealed_data_t* sealed_buffer);

#endif