#ifndef SGX_LIB_T_UTIL_H
#define SGX_LIB_T_UTIL_H

#include <stdarg.h>
#include <sgx_tseal.h>

/* AES CTR mode counter size in bytes: 128 bit */
#define CTR_SIZE 16

/* number of bytes (most significant) to use as message nonce in counter */
#define CTR_NONCE_SIZE 8

/* number of bits (least significant) to increment */
#define CTR_INC_BITS (CTR_SIZE-CTR_NONCE_SIZE)*8


/* AES block size in bytes */
#define BLOCK_SIZE 16

char* vsprintf(char* format, va_list args);
void check(sgx_status_t rc);
uint32_t get_sealed_data_size(uint32_t plaintext_data_size);
int seal(const void* plaintext_buffer, uint32_t plaintext_data_size, sgx_sealed_data_t* sealed_buffer, size_t sealed_data_size);
int unseal(void* plaintext_buffer, uint32_t plaintext_data_size, sgx_sealed_data_t* sealed_buffer);

uint32_t get_number_of_blocks(uint32_t plaintext_data_size);
uint32_t get_encrypted_data_size(uint32_t plaintext_data_size);
int encrypt(const void* plaintext_buffer, uint32_t plaintext_data_size, void* encrypted_buffer, sgx_aes_ctr_128bit_key_t* key);
int decrypt(void* plaintext_buffer, uint32_t plaintext_data_size, const void* encrypted_buffer, sgx_aes_ctr_128bit_key_t* key);

#endif