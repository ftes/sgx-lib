#include <stdlib.h>

#include "sgx_lib_t_stdio.h"
#include "sgx_lib_t_logging.h"
#include "sgx_lib_t.h"
#include "sgx_lib_t_util.h"

#ifdef SGX_INSECURE_IO_OPERATIONS
void printf(char* format, ...) {
  char *formatted;
  va_list argptr;
  va_start(argptr, format);
  formatted = vsprintf(format, argptr);
  va_end(argptr);
  print_ocall(formatted);
  free(formatted);
}

size_t fwrite(const void* buffer, size_t size, size_t count, FILE* stream) {
  size_t ret;
  check(fwrite_enclave_memory_ocall(&ret, buffer, size, count, stream));
  return ret;
}

size_t fread(void* buffer, size_t size, size_t count, FILE* stream) {
  size_t ret;
  check(fread_copy_into_enclave_memory_ocall(&ret, buffer, size, count, stream));
  return ret;
}
#else
// WARNING: NOT REPLAY PROTECTED!

/* Steps:
 * 1. seal data
 * 2. fwrite sealed data
 *
 * Parameters:
 * - plaintext_buffer must be in the enclave
 *
 * returns count of plaintext elements written if there was no error, 0 otherwise
 */
size_t fwrite(const void* plaintext_buffer, size_t plaintext_element_size, size_t plaintext_element_count, FILE* stream) {
  size_t written_bytes;
  size_t plaintext_data_size = plaintext_element_size * plaintext_element_count;
  size_t sealed_data_size = get_sealed_data_size(plaintext_data_size);

  // STEP 1
  // temporary buffer (sealed_data) must be inside enclave, enforced by SGX lib
  sgx_sealed_data_t* sealed_buffer = (sgx_sealed_data_t*) malloc(sealed_data_size);
  int rc = seal(plaintext_buffer, plaintext_data_size, sealed_buffer, sealed_data_size);
  if (rc != 0) {
    // sealing failed, return 0 elements written
    return 0; 
  }

  // STEP 2
  // sgx lib outputs sealed data into enclave memory, so we have to copy this outside in the fwrite ocall
  check(fwrite_enclave_memory_ocall(&written_bytes, sealed_buffer, 1, sealed_data_size, stream));
  // free temp buffer (don't need to memset, encrypted anyway)
  free(sealed_buffer);

  if (written_bytes != sealed_data_size) {
    // not all data was written
    // don't try to convert number of written sealed bytes to number of plaintext elements, rather just return 0
    log("Not all sealed data could be written");
    return 0;
  }

  return plaintext_element_count;
}

/* Steps:
 * 1. fread sealed data
 * 2. unseal data
 */
size_t fread(void* plaintext_buffer, size_t plaintext_element_size, size_t plaintext_element_count, FILE* stream) {
  size_t read_bytes;
  size_t plaintext_data_size = plaintext_element_size * plaintext_element_count;
  int rc;
  size_t sealed_data_size = get_sealed_data_size(plaintext_data_size);

  // STEP 1
  // temporary buffer (sealed_data) must be inside enclave, enforced by SGX lib, so we let the fread ocall copy it inside
  sgx_sealed_data_t* sealed_buffer = (sgx_sealed_data_t*) malloc(sealed_data_size);
  check(fread_copy_into_enclave_memory_ocall(&read_bytes, sealed_buffer, 1, sealed_data_size, stream));
  
  if (read_bytes != sealed_data_size) {
    // not all data was read
    // don't try to convert number of read sealed bytes to number of plaintext elements, rather just return 0
    log("Not all sealed data could be read");
    free(sealed_buffer);
    return 0;
  }

  // STEP 2
  rc = unseal(plaintext_buffer, plaintext_data_size, sealed_buffer);
  free(sealed_buffer);
  if (rc != 0) {
    // unsealing failed, return 0 elements read
    return 0; 
  }

  return plaintext_element_count;
}
#endif


/* file functions */
void rewind(FILE* file) {
  check(rewind_ocall(file));
}

int fseek(FILE* file, long offset, int origin) {
  int ret;
  check(fseek_ocall(&ret, file, offset, origin));
  return ret;
}

long ftell(FILE* file) {
  long ret;
  check(ftell_ocall(&ret, file));
  return ret;
}

int fclose(FILE* stream) {
  int ret;
  check(fclose_ocall(&ret, stream));
  return ret;
}

FILE* fopen(const char* filename, const char* mode) {
  FILE* ret;
  check(fopen_ocall(&ret, filename, mode));
  return ret;
}
/* end of file functions */


/* GENERATE OCALL CODE AFTER THIS LINE */
