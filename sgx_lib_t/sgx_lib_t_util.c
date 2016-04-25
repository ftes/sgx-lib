#include <stdlib.h>
#include <sgx_error.h>

#include "sgx_lib_t_util.h"
#include "sgx_lib_t.h"
#include "sgx_lib.h"

void check(sgx_status_t rc) {
  if (rc != SGX_SUCCESS) {
    char* desc = get_error_description(rc);
    log_ocall(desc);
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

size_t get_sealed_data_size(size_t plaintext_data_size) {
  size_t sealed_data_size = sgx_calc_sealed_data_size(0, plaintext_data_size);
  if (sealed_data_size == UINT32_MAX) {
    log_ocall("Failed to allocate calc number of bytes needed to seal plaintext data.");
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
    log_ocall("Failed to seal data");
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
    log_ocall("Failed to unseal data");
    return 1; // error code
  }

  return 0;
}