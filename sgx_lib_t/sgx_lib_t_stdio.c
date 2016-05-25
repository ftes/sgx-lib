#include <stdlib.h>

#include "sgx_lib_t_stdio.h"
#include "sgx_lib_t.h"
#include "sgx_lib_t_util.h"
#include "sgx_lib_t_crypto.h"


size_t fwrite_unencrypted(const void* buffer, size_t size, size_t count, FILE* stream) {
  size_t ret;

  #ifdef SGX_INSECURE_IO_OPERATIONS
  print_ocall("Warning: insecure I/O operations activated (SGX_INSECURE_IO_OPERATIONS macro defined)");
  #endif

  check(fwrite_enclave_memory_ocall(&ret, buffer, size, count, stream));
  return ret;
}

size_t fread_unencrypted(void* buffer, size_t size, size_t count, FILE* stream) {
  size_t ret;

  #ifdef SGX_INSECURE_IO_OPERATIONS
  print_ocall("Warning: insecure I/O operations activated (SGX_INSECURE_IO_OPERATIONS macro defined)");
  #endif

  check(fread_copy_into_enclave_memory_ocall(&ret, buffer, size, count, stream));
  return ret;
}

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
size_t fwrite_encrypted(const void* plaintext_buffer, size_t plaintext_element_size, size_t plaintext_element_count, FILE* stream) {
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
    print_ocall("Not all sealed data could be written");
    return 0;
  }

  return plaintext_element_count;
}

/* Steps:
 * 1. fread sealed data
 * 2. unseal data
 */
size_t fread_encrypted(void* plaintext_buffer, size_t plaintext_element_size, size_t plaintext_element_count, FILE* stream) {
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
    print_ocall("Not all sealed data could be read");
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

/* GENERATE OCALL CODE AFTER THIS LINE */
int64_t _ftelli64(FILE* file) {
  int64_t ret;
  check(_ftelli64_ocall(&ret, file));
  return ret;
}

int fflush(FILE* file) {
  int ret;
  check(fflush_ocall(&ret, file));
  return ret;
}

int fopen_s(FILE** file, const char* filename, const char* mode) {
  int ret;
  check(fopen_s_ocall(&ret, file, filename, mode));
  return ret;
}

int _fseeki64(FILE* file, int64_t offest, int origin) {
  int ret;
  check(_fseeki64_ocall(&ret, file, offest, origin));
  return ret;
}

