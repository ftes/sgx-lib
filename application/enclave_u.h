#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */

#include "stdio.h"
#include "mystdio.h"

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

FILE* SGX_UBRIDGE(SGX_NOCONVENTION, fopen_ocall, (const char* filename, const char* mode));
int SGX_UBRIDGE(SGX_NOCONVENTION, fclose_ocall, (FILE* stream));
size_t SGX_UBRIDGE(SGX_NOCONVENTION, fwrite_ocall, (const void* buffer, size_t size, size_t count, FILE* stream));
size_t SGX_UBRIDGE(SGX_NOCONVENTION, fread_ocall, (const void* buffer, size_t size, size_t count, FILE* stream));
int SGX_UBRIDGE(SGX_NOCONVENTION, fseek_ocall, (FILE* file, long int offset, int origin));
long int SGX_UBRIDGE(SGX_NOCONVENTION, ftell_ocall, (FILE* file));
void SGX_UBRIDGE(SGX_NOCONVENTION, log_ocall, (char* message));

sgx_status_t add_secret(sgx_enclave_id_t eid, int secret);
sgx_status_t print_secrets(sgx_enclave_id_t eid);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
