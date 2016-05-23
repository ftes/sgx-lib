#include <stdlib.h>
#include <string.h>
#include <sgx_error.h>
#include <sgx_trts.h>

#include "sgx_lib_t_util.h"
#include "sgx_lib_t.h"
#include "sgx_lib.h"
#include "sgx_lib_t_debug.h"

void check(sgx_status_t rc) {
  if (rc != SGX_SUCCESS) {
    char* desc = get_error_description(rc);
    print_ocall(desc);
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
    print_ocall("Failed to allocate calc number of bytes needed to seal plaintext data.");
    return -1;
  }
  return sealed_data_size;
}

/* convenience wrapper for sgx_seal_data()
 * parameters:
 * plaintext_data_size: input size in bytes
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
    print_ocall("Failed to seal data");
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
    print_ocall("Failed to unseal data");
    return 1; // error code
  }

  return 0;
}

/* convenience wrapper for sgx_aes_ctr_encrypt()
 * - generates a random initial counter (IV) and adds this (in plaintext) to the enrypted_buffer
 * - also encrypts the number of written bytes, to properly restore the output when decrypting
 *
 * output format: number_of_encrypted_blocks | iv | enc(data_size) | enc(data)
 *
 * parameters:
 * [IN] key: must be 128 bits
 * [OUT] encrypted_buffer: allocates memory and writes result to this buffer
 * plaintext_element_size: size in bytes
 * returns: number of bytes written to encrypted_buffer on success, -1 otherwise
 */
int encrypt(const void* plaintext_buffer, size_t plaintext_element_size, size_t plaintext_element_count,
            uint8_t* encrypted_buffer, sgx_aes_ctr_128bit_key_t* key) {
  sgx_status_t sgx_ret;
  uint8_t ctr[CTR_SIZE];

  uint32_t plaintext_size = plaintext_element_size * plaintext_element_count;
  // ceil(x/y) = (x + y - 1) - y  blocks for data
  uint32_t number_of_encrypted_data_blocks = (plaintext_size + BLOCK_SIZE - 1) / BLOCK_SIZE;
  uint32_t number_of_encrypted_blocks = 1 + number_of_encrypted_data_blocks;
  size_t encrypted_buffer_size = sizeof(number_of_encrypted_blocks) + CTR_SIZE + BLOCK_SIZE * number_of_encrypted_blocks;
  encrypted_buffer = (uint8_t*) malloc(encrypted_buffer_size);

  /* NIST recommendations on CTR mode (publication 800-38A, p. 15):
   * - CTR is incremented for each message block
   * - CTR is encrypted, and then serves as pad (output block) with which plaintext (ciphertext) is XOR-ed
   * - benefit: output blocks can be derived in parallel, even before payload is available
   * - CTR must be unique over all messages encrypted under same key -> IV that is initial CTR must be unique
   * - choosing an IV:
   *   2. new nonce (IV) for each message which is b/2 bits long (MSB) -> increment the remaining b/2 LSB
   */
  
  // TODO use b/2 bis as message nonce, and encrypt remaining b/2 as counter
  // dependent on: https://software.intel.com/en-us/forums/intel-software-guard-extensions-intel-sgx/topic/633345
  sgx_read_rand(ctr, CTR_SIZE);

  int position = 0;
  int size = 0;

  // write number of encrypted blocks to output
  size = sizeof(number_of_encrypted_data_blocks);
  memcpy(&encrypted_buffer[position], &number_of_encrypted_blocks, size);
  position += size;

  // write initial counter to output
  size = CTR_SIZE;
  memcpy(&encrypted_buffer[position], ctr, CTR_SIZE);
  position += size;

  printf("Initial counter:\n%d\n\n", ctr);

  // write encrypted data size to output
  check(sgx_ret = sgx_aes_ctr_encrypt(key,
    (uint8_t*) &plaintext_size, sizeof(plaintext_size) * 1,
    ctr, CTR_INC_BITS,
    &encrypted_buffer[position]
  ));
  position += BLOCK_SIZE;

  if (sgx_ret != SGX_SUCCESS) {
    print_ocall("Failed to encrypt data");
    return -1;
  }
  
  printf("Counter after first encryption:\n%d\n\n", ctr);

  // write encrypted data to output
  check(sgx_ret = sgx_aes_ctr_encrypt(key,
    (uint8_t*) plaintext_buffer, plaintext_size,
    ctr, CTR_INC_BITS,
    &encrypted_buffer[position]
  ));
  position += number_of_encrypted_data_blocks * BLOCK_SIZE;

  if (sgx_ret != SGX_SUCCESS) {
    print_ocall("Failed to encrypt data");
    return -1;
  }

  return encrypted_buffer_size;
}

int decrypt(const uint8_t* encrypted_buffer, uint8_t* decrypted_buffer, sgx_aes_ctr_128bit_key_t* key) {
  sgx_status_t sgx_ret;
  uint8_t ctr[CTR_SIZE];
  uint32_t number_of_encrypted_blocks;
  uint32_t plaintext_size;
  
  // input format: number_of_encrypted_blocks | iv | enc(data_size) | enc(data)

  int position = 0;
  int size;

  // read number of encrypted blocks
  size = sizeof(number_of_encrypted_blocks);
  memcpy(&number_of_encrypted_blocks, encrypted_buffer + position, size);
  position += size;

  // read initial counter
  memcpy(ctr, encrypted_buffer + position, CTR_SIZE);
  position += CTR_SIZE;

  // read encrypted data size
  check(sgx_ret = sgx_aes_ctr_decrypt(key,
    encrypted_buffer + position, sizeof(plaintext_size) * 1,
    ctr, CTR_INC_BITS,
    (uint8_t*) &plaintext_size
  ));
  position += BLOCK_SIZE;

  if (sgx_ret != SGX_SUCCESS) {
    print_ocall("Failed to encrypt data");
    return -1;
  }

  // allocate memory for plaintext
  decrypted_buffer = (uint8_t*) malloc(plaintext_size);

  // read encrypted data
  check(sgx_ret = sgx_aes_ctr_decrypt(key,
    encrypted_buffer + position, (number_of_encrypted_blocks - 1) * BLOCK_SIZE,
    ctr, CTR_INC_BITS,
    decrypted_buffer
  ));
  position += (number_of_encrypted_blocks - 1) * BLOCK_SIZE;

  if (sgx_ret != SGX_SUCCESS) {
    print_ocall("Failed to encrypt data");
    return -1;
  }

  return plaintext_size;
}