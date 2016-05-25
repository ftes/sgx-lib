#include <string.h>
#include <stdbool.h>
#include <stdlib.h>

#include <sgx_error.h>
#include <sgx_trts.h>

#include "sgx_lib_t.h"
#include "sgx_lib_t_debug.h"
#include "sgx_lib_t_util.h"

#include "sgx_lib_t_crypto.h"

uint32_t get_sealed_data_size(uint32_t plaintext_data_size) {
  size_t sealed_data_size = sgx_calc_sealed_data_size(0, plaintext_data_size);
  if (sealed_data_size == UINT32_MAX) {
    log_msg("Failed to allocate calc number of bytes needed to seal plaintext data.");
    return -1;
  }
  return sealed_data_size;
}

/* convenience wrapper for sgx_seal_data()
 * parameters:
 * plaintext_data_size: input size in bytes
 * returns: 0 if sealing succeeded, >0 otherwise
 */
int seal(const void* plaintext_buffer, uint32_t plaintext_data_size, sgx_sealed_data_t* sealed_buffer, uint32_t sealed_data_size) {
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
    log_msg("Failed to seal data");
    return 1;
  }

  return 0;
}

/* convenience wrapper for sgx_unseal_data()
 * returns: 0 if unsealing succeeded, >0 otherwise
 */
int unseal(void* plaintext_buffer, uint32_t plaintext_data_size, sgx_sealed_data_t* sealed_buffer) {
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
    log_msg("Failed to unseal data");
    return 1; // error code
  }

  return 0;
}

/* parameters:
 * [IN] plaintext_data_size in bytes
 *
 * returns: size of encrypted buffer in bytes
 */
uint32_t get_number_of_blocks(uint32_t plaintext_data_size) {
  // ceil(x/y) = (x + y - 1) - y
  return (plaintext_data_size + BLOCK_SIZE - 1) / BLOCK_SIZE;
}

/* parameters:
 * [IN] plaintext_data_size in bytes
 *
 * returns: size of encrypted buffer in bytes
 */
uint32_t get_encrypted_data_size(uint32_t plaintext_data_size) {
  return offsetof(sgx_lib_encrypted_data_t, data) + get_number_of_blocks(plaintext_data_size) * BLOCK_SIZE;
}

/* convenience wrapper for sgx_aes_ctr_encrypt()
 * - generates a random initial counter (IV) and adds this (in plaintext) to the enrypted_buffer
 *
 * output format: see encrypted_struct
 *
 * parameters:
 * [IN] key: must be 128 bits
 * [OUT] encrypted_buffer: minimum size in bytes given by get_encrypted_data_size()
 * [IN] plaintext_data_size in bytes
 * returns: 0 on success, >0 otherwise
 */
int encrypt(const void* plaintext_buffer, uint32_t plaintext_data_size, sgx_lib_encrypted_data_t *encrypted_buffer, sgx_aes_ctr_128bit_key_t* key) {
  sgx_status_t sgx_ret;
  int size = 0;
  uint8_t ctr[CTR_SIZE] = {0};

  /* NIST recommendations on CTR mode (publication 800-38A, p. 15):
   * - CTR is incremented for each message block
   * - CTR is encrypted, and then serves as pad (output block) with which plaintext (ciphertext) is XOR-ed
   * - benefit: output blocks can be derived in parallel, even before payload is available
   * - CTR must be unique over all messages encrypted under same key -> IV that is initial CTR must be unique
   * - choosing an IV:
   *   2. new nonce (IV) for each message which is b/2 bits long (MSB) -> increment the remaining b/2 LSB
   */
  sgx_read_rand(ctr, CTR_NONCE_SIZE);

  encrypted_buffer->number_of_blocks = get_number_of_blocks(plaintext_data_size);
  memcpy(encrypted_buffer->ctr, ctr, CTR_SIZE);

  // write encrypted data to output
  check(sgx_ret = sgx_aes_ctr_encrypt(key,
    (uint8_t*) plaintext_buffer, plaintext_data_size,
    ctr, CTR_INC_BITS,
    encrypted_buffer->data
  ));

  if (sgx_ret != SGX_SUCCESS) {
    log_msg("Failed to encrypt data");
    return 1;
  }

  return 0;
}

/* convenience wrapper for sgx_aes_ctr_decrypt()
 * - does opposite of encrypt()
 * - decrypts encrypted_buffer->data into temporary buffer if plaintext_buffer does not have a block-aligned size
 *
 * Performance notice: Allocate plaintext_buffer to next multiple of BLOCK_SIZE (get_number_of_blocks(data_bytes) * BLOCK_SIZE)
 * and pass this as plaintext_data_size for increased performance (avoids memcpy of resulting plaintext).
 *
 * parameters:
 * [OUT] plaintext_buffer: must have minimum size of plaintext_data_size bytes
 * [IN] plaintext_data_size in bytes
 * returns: 0 on success, >0 otherwise
 */
int decrypt(void* plaintext_buffer, uint32_t plaintext_data_size, sgx_lib_encrypted_data_t* encrypted_buffer, sgx_aes_ctr_128bit_key_t* key) {
  sgx_status_t sgx_ret;
  uint8_t ctr[CTR_SIZE];
  void* plaintext_block_aligned_buffer;
  uint32_t plaintext_block_aligned_size;
  bool temp_plaintext_buffer = false;

  // copy counter
  memcpy(ctr, encrypted_buffer->ctr, CTR_SIZE);

  // allocate temporary block-aligned plaintext buffer, if plaintext_buffer is not block-aligned
  plaintext_block_aligned_size = encrypted_buffer->number_of_blocks * BLOCK_SIZE;
  if (plaintext_data_size == plaintext_block_aligned_size) {
    plaintext_block_aligned_buffer = plaintext_buffer;
  } else {
    temp_plaintext_buffer = true;
    plaintext_block_aligned_buffer = malloc(plaintext_block_aligned_size);
  }

  // read encrypted data
  check(sgx_ret = sgx_aes_ctr_decrypt(key,
    encrypted_buffer->data, plaintext_block_aligned_size,
    ctr, CTR_INC_BITS,
    (uint8_t*) plaintext_block_aligned_buffer
  ));

  if (sgx_ret != SGX_SUCCESS) {
    log_msg("Failed to encrypt data");
    return 1;
  }

  if (temp_plaintext_buffer) {
    memcpy(plaintext_buffer, plaintext_block_aligned_buffer, plaintext_data_size);
    free(plaintext_block_aligned_buffer);
  }

  return 0;
}