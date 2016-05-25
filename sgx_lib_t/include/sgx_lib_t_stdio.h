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

size_t fwrite_insecure(const void* buffer, size_t size, size_t count, FILE* stream);
size_t fread_insecure(void* buffer, size_t size, size_t count, FILE* stream);
size_t fwrite_encrypted(const void* buffer, size_t size, size_t count, FILE* stream);
size_t fread_encrypted(void* buffer, size_t size, size_t count, FILE* stream);
size_t fwrite_sealed(const void* buffer, size_t size, size_t count, FILE* stream);
size_t fread_sealed(void* buffer, size_t size, size_t count, FILE* stream);

#ifdef SGX_INSECURE_IO_OPERATIONS
#define fwrite fwrite_insecure
#define fread fread_insecure
#else
  #ifdef SGX_SECURE_IO_OPERATIONS_KEY
  #define fwrite fwrite_encrypted
  #define fread fread_encrypted
  #else
  #define fwrite fwrite_sealed
  #define fread fread_sealed
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