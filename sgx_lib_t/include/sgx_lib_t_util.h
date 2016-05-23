#ifndef SGX_LIB_T_UTIL_H
#define SGX_LIB_T_UTIL_H

#include <stdarg.h>
#include <sgx_tseal.h>

/* AES CBC Counter size in bytes */
#define CTR_SIZE 12

// TODO do not increment entire counter (https://software.intel.com/en-us/forums/intel-software-guard-extensions-intel-sgx/topic/633345)
#define CTR_INC_BITS CTR_SIZE * 8

/* AES block size in bytes */
#define BLOCK_SIZE 16

char* vsprintf(char* format, va_list args);
void check(sgx_status_t rc);
size_t get_sealed_data_size(size_t plaintext_data_size);
int seal(const void* plaintext_buffer, size_t plaintext_data_size, sgx_sealed_data_t* sealed_buffer, size_t sealed_data_size);
int unseal(void* plaintext_buffer, size_t plaintext_data_size, sgx_sealed_data_t* sealed_buffer);

int encrypt(const void* plaintext_buffer, size_t plaintext_element_size, size_t plaintext_element_count,
            uint8_t* encrypted_buffer, sgx_aes_ctr_128bit_key_t* key);
int decrypt(const uint8_t* encrypted_buffer, uint8_t* decrypted_buffer, sgx_aes_ctr_128bit_key_t* key);

#endif