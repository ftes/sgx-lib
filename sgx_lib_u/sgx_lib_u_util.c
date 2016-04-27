#include <sgx_urts.h>
#include <stdio.h>

#include "sgx_lib.h"

#include "sgx_lib_u_util.h"

sgx_status_t check(sgx_status_t rc, char* error_msg) {
  if (rc != SGX_SUCCESS) {
    char* desc = get_error_description(rc);
    fprintf(stderr, "%s (%s)\n", error_msg, desc);
  }
  return rc;
}

/* Very simple for now: debug mode, no launch token supported */
 sgx_status_t launch_enclave(const LPCWSTR enclave_dll_file, /*out*/ sgx_enclave_id_t* eid) {
  sgx_launch_token_t token = {0};
  int updated = 0;

  // Launch the enclave
  // Token is not stored for now (would speed up subsequent launches)
  return check(sgx_create_enclave(enclave_dll_file, SGX_DEBUG_FLAG, &token, &updated, eid, NULL), "Failed to launch enclave");
}

sgx_status_t destroy_enclave(sgx_enclave_id_t eid) {
  return check(sgx_destroy_enclave(eid), "Failed to destroy enclave");
}