#ifndef SGX_LIB_U_H__
#define SGX_LIB_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */

#include "stdio.h"
#include "sgx_lib_stdio.h"

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

void SGX_UBRIDGE(SGX_NOCONVENTION, print_ocall, (char* message));
void SGX_UBRIDGE(SGX_NOCONVENTION, rewind_ocall, (FILE* file));
int SGX_UBRIDGE(SGX_NOCONVENTION, fseek_ocall, (FILE* file, long int offset, int origin));
long int SGX_UBRIDGE(SGX_NOCONVENTION, ftell_ocall, (FILE* file));
size_t SGX_UBRIDGE(SGX_NOCONVENTION, fwrite_enclave_memory_ocall, (const void* buffer, size_t size, size_t count, FILE* stream));
size_t SGX_UBRIDGE(SGX_NOCONVENTION, fread_copy_into_enclave_memory_ocall, (void* buffer, size_t size, size_t count, FILE* stream));
int SGX_UBRIDGE(SGX_NOCONVENTION, fclose_ocall, (FILE* stream));
FILE* SGX_UBRIDGE(SGX_NOCONVENTION, fopen_ocall, (const char* filename, const char* mode));


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
