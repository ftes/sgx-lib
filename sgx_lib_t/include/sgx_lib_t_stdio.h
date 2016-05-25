#ifndef SGX_LIB_T_STDIO_H
#define SGX_LIB_T_STDIO_H

#include <stdint.h>

#include <sgx_tcrypto.h>

#include "sgx_lib_stdio.h"

/* file functions */
void rewind(FILE* file);
int fseek(FILE* file, long offset, int origin);
long ftell(FILE* file);
size_t fwrite(const void* buffer, size_t size, size_t count, FILE* stream);
size_t fread(void* buffer, size_t size, size_t count, FILE* stream);
int fclose(FILE* stream);
FILE* fopen(const char* filename, const char* mode);

size_t fwrite_unencrypted(const void* buffer, size_t size, size_t count, FILE* stream);
size_t fread_unencrypted(void* buffer, size_t size, size_t count, FILE* stream);
size_t fwrite_encrypted(const void* buffer, size_t size, size_t count, FILE* stream);
size_t fread_encrypted(void* buffer, size_t size, size_t count, FILE* stream);

#ifdef SGX_INSECURE_IO_OPERATIONS
#define fwrite fwrite_unencrypted
#define fread fread_unencrypted
#else
#define fwrite fwrite_encrypted
#define fread fread_encrypted
  #ifdef SGX_SECURE_IO_OPERATIONS_KEY
  void set_secure_io_key(sgx_aes_ctr_128bit_key_t key);
  #define get_output_data_size get_encrypted_data_size
  #define seal_or_encrypt encrypt_with_set_key
  #define unseal_or_decrypt decrypt_with_set_key
  #define output_buffer_t sgx_lib_encrypted_data_t
  #else
  #define get_output_data_size get_sealed_data_size
  #define seal_or_encrypt seal
  #define unseal_or_decrypt unseal
  #define output_buffer_t sgx_sealed_data_t
  #endif
#endif

/* GENERATE OCALL CODE AFTER THIS LINE */
int64_t _ftelli64(FILE* file);
int fflush(FILE* file);
int fopen_s(FILE** file, const char* filename, const char* mode);
// generated using:
// TRUSTED_C=sgx_lib_t/sgx_lib_t_stdio.c TRUSTED_H=sgx_lib_t/include/sgx_lib_t_stdio.h UNTRUSTED_C=sgx_lib_u/sgx_lib_u_ocalls_stdio.c \
// > ./add_ocall.sh 'int _fseeki64([user_check] FILE* file, int64_t offset, int origin)'
int _fseeki64(FILE* file, int64_t offset, int origin);

#endif