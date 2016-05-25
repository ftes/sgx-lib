#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include "sgx_lib_t_stdio.h"
#include "sgx_lib_t.h"
#include "sgx_lib_t_util.h"
#include "sgx_lib_t_crypto.h"
#include "sgx_lib_t_debug.h"


size_t fwrite_unencrypted(const void* buffer, size_t size, size_t count, FILE* stream) {
  size_t ret;

  #ifdef SGX_INSECURE_IO_OPERATIONS
  log_msg("Warning: insecure I/O operations activated (SGX_INSECURE_IO_OPERATIONS macro defined)");
  #endif

  check(fwrite_enclave_memory_ocall(&ret, buffer, size, count, stream));
  return ret;
}

size_t fread_unencrypted(void* buffer, size_t size, size_t count, FILE* stream) {
  size_t ret;

  #ifdef SGX_INSECURE_IO_OPERATIONS
  log_msg("Warning: insecure I/O operations activated (SGX_INSECURE_IO_OPERATIONS macro defined)");
  #endif

  check(fread_copy_into_enclave_memory_ocall(&ret, buffer, size, count, stream));
  return ret;
}

// WARNING: NOT REPLAY PROTECTED!

sgx_aes_ctr_128bit_key_t secure_io_key = {0};
bool secure_io_key_initialized = false;
void set_secure_io_key(sgx_aes_ctr_128bit_key_t key) {
  secure_io_key_initialized = true;
  memcpy(secure_io_key, key, sizeof(secure_io_key));
}

int encrypt_with_set_key(const void* plaintext_buffer, uint32_t plaintext_data_size, sgx_lib_encrypted_data_t* encrypted_buffer,
                         uint32_t encrypted_buffer_size) {
  if (!secure_io_key_initialized) {
    log_msg("Secure IO key was not initialized");
    return 1;
  }
  return encrypt(plaintext_buffer, plaintext_data_size, encrypted_buffer, &secure_io_key);
}
int decrypt_with_set_key(void* plaintext_buffer, uint32_t plaintext_data_size, sgx_lib_encrypted_data_t* encrypted_buffer) {
  if (!secure_io_key_initialized) {
    log_msg("Secure IO key was not initialized");
    return 1;
  }
  return decrypt(plaintext_buffer, plaintext_data_size, encrypted_buffer, &secure_io_key);
}


/* Steps:
 * 1. seal/encrypt data
 * 2. fwrite sealed/encrypted data
 *
 * returns count of plaintext elements written if there was no error, 0 otherwise
 */
size_t fwrite_encrypted(const void* plaintext_buffer, size_t plaintext_element_size, size_t plaintext_element_count, FILE* stream) {
  size_t written_bytes;
  size_t plaintext_data_size = plaintext_element_size * plaintext_element_count;
  size_t output_data_size = get_output_data_size(plaintext_data_size);

  // STEP 1
  // temporary buffer (sealed_data) must be inside enclave, enforced by SGX lib
  output_buffer_t* output_buffer = (output_buffer_t*) malloc(output_data_size);
  int rc = seal_or_encrypt(plaintext_buffer, plaintext_data_size, output_buffer, output_data_size);

  if (rc != 0) {
    // encrypting failed, return 0 elements written
    return 0; 
  }

  // STEP 2
  // sgx lib outputs sealed data into enclave memory, so we have to copy this outside in the fwrite ocall
  check(fwrite_enclave_memory_ocall(&written_bytes, output_buffer, 1, output_data_size, stream));
  // free temp buffer (don't need to memset, encrypted anyway)
  free(output_buffer);

  if (written_bytes != output_data_size) {
    // not all data was written
    // don't try to convert number of written sealed bytes to number of plaintext elements, rather just return 0
    log_msg("Not all encrypted data could be written");
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
  size_t output_data_size = get_output_data_size(plaintext_data_size);

  // STEP 1
  // temporary buffer (sealed_data) must be inside enclave, enforced by SGX lib, so we let the fread ocall copy it inside
  output_buffer_t* output_buffer = (sgx_sealed_data_t*) malloc(output_data_size);
  check(fread_copy_into_enclave_memory_ocall(&read_bytes, output_buffer, 1, output_data_size, stream));
  
  if (read_bytes != output_data_size) {
    // not all data was read
    // don't try to convert number of read sealed bytes to number of plaintext elements, rather just return 0
    log_msg("Not all sealed data could be read");
    free(output_buffer);
    return 0;
  }

  // STEP 2
  rc = unseal_or_decrypt(plaintext_buffer, plaintext_data_size, output_buffer);
  free(output_buffer);
  if (rc != 0) {
    // decrypting failed, return 0 elements read
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

