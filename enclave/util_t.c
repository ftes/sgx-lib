#include <stdlib.h>
#include <sgx_trts.h>
#include "util_t.h"
#include "enclave_t.h"
#include "util.h"
#include "sgx_tseal.h"
#include "string.h"

void check(sgx_status_t rc) {
  if (rc != SGX_SUCCESS) {
    char* desc = get_error_description(rc);
    log(desc);
  }
}

char* vsprintf(char* format, va_list args) {
  char *formatted;
  int size;
  size = vsnprintf(NULL, 0, format, args) + 1; //+1 for trailing \0
  formatted = (char*) malloc(size * sizeof(*formatted));
  vsnprintf(formatted, size, format, args);
  return formatted;
}

/* INSECURE - leaks plaintext data */
void log(char* format, ...) {
  char *formatted;
  va_list argptr;
  va_start(argptr, format);
  formatted = vsprintf(format, argptr);
  va_end(argptr);
  log_ocall(formatted);
  free(formatted);
}

size_t get_sealed_data_size(size_t plaintext_data_size) {
  size_t sealed_data_size = sgx_calc_sealed_data_size(0, plaintext_data_size);
  if (sealed_data_size == UINT32_MAX) {
    log("Failed to allocate calc number of bytes needed to seal %d bytes of plaintext data.", plaintext_data_size);
    return -1;
  }
  return sealed_data_size;
}

/* convenience wrapper for sgx_seal_data()
 * returns: 0 if sealing succeeded, >0 otherwise
 */
int seal(const void* plaintext_buffer, size_t plaintext_data_size, sgx_sealed_data_t* sealed_buffer, size_t sealed_data_size) {
  sgx_status_t sgx_ret;
  
  /* sgx_seal_data
    * Purpose: This algorithm is used to AES-GCM encrypt the input data.  Specifically,
    *          two input data sets can be provided, one is the text to encrypt (p_text2encrypt)
    *          the second being optional additional text that should not be encrypted but will
    *          be part of the GCM MAC calculation.
    *          The sgx_sealed_data_t structure should be allocated prior to the API call and
    *          should include buffer storage for the MAC text and encrypted text.
    *          The sgx_sealed_data_t structure contains the data required to unseal the data on
    *          the same system it was sealed.
    */
  check(sgx_ret = sgx_seal_data(
    0, // [IN] length of the plaintext data stream in bytes
    NULL, // [IN] pointer to the plaintext data stream to be GCM protected
    plaintext_data_size, // [IN] length of the data stream to encrypt in bytes
    (uint8_t*) plaintext_buffer, // [IN] pointer to data stream to encrypt - must be in the enclave
    sealed_data_size, // [IN] Size of the sealed data buffer passed in
    sealed_buffer // [OUT] pointer to the sealed data structure containing protected data, must be in the enclave
    ));

  if (sgx_ret != SGX_SUCCESS) {
    log("Failed to seal data");
    return 1;
  }

  return 0;
}

/* convenience wrapper for sgx_unseal_data()
 * returns: 0 if unsealing succeeded, >0 otherwise
 */
int unseal(void* plaintext_buffer, size_t plaintext_data_size, sgx_sealed_data_t* sealed_buffer) {
  sgx_status_t sgx_ret;

  /* sgx_unseal_data
    * Purpose: Unseal the sealed data structure passed in and populate the MAC text and decrypted text
    *          buffers with the appropriate data from the sealed data structure.
    */
  check(sgx_ret = sgx_unseal_data(
    sealed_buffer, //  [IN] pointer to the sealed data structure containing protected data, must be in the enclave
    NULL, // [OUT] pointer to the plaintext data stream which was GCM protected
    0, // [IN/OUT] pointer to length of the plaintext data stream in bytes
    (uint8_t*) plaintext_buffer, // [OUT] pointer to decrypted data stream, must be in the enclave
    &plaintext_data_size // [IN/OUT] pointer to length of the decrypted data stream to encrypt in bytes
    ));

  if (sgx_ret != SGX_SUCCESS) {
    log("Failed to unseal data");
    return 1; // error code
  }

  return 0;
}

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
