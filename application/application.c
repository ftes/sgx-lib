#include <stdio.h>
#include <tchar.h>
#include "sgx_urts.h"
#include "util.h"
#include "enclave_u.h"

#define ENCLAVE_FILE _T("enclave.signed.dll")

int main(int argc, char* argv[])
{
  sgx_enclave_id_t   eid;
  sgx_status_t       ret   = SGX_SUCCESS;
  sgx_launch_token_t token = {0};
  int updated = 0;
  int secret;

  // Launch the enclave
  // Token is not stored for now (would speed up subsequent launches)
  ret  =  sgx_create_enclave(ENCLAVE_FILE,  SGX_DEBUG_FLAG,  &token,   &updated, &eid, NULL);
  if (ret != SGX_SUCCESS) {
    printf("App: error %#x, failed to create enclave.\n%s\n", ret, get_error_description(ret));
    return -1;
  }

  // Interact with the enclave
  printf("Secret to seal by the enclave (-1 to reuse old secret): ");
  scanf("%d%*c", &secret);
  if (secret != -1) {
    add_secret(eid, secret);
  }
  print_secrets(eid);

  // Destroy the enclave
  if(SGX_SUCCESS != sgx_destroy_enclave(eid)) {
    printf("App: error %#x, failed to destroy enclave.\n%s\n", ret, get_error_description(ret));
    return -1;
  }

  printf("Press any key to exit...");
  getchar();
  return 0;
}