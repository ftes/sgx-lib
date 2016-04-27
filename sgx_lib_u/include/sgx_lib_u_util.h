#ifndef SGX_LIB_U_UTIL_H
#define SGX_LIB_U_UTIL_H

#include <sgx_status.h>

sgx_status_t check(sgx_status_t rc, char* error_msg);

sgx_status_t launch_enclave(const LPCWSTR enclave_dll_file, sgx_enclave_id_t* eid);
sgx_status_t destroy_enclave(sgx_enclave_id_t eid);

#endif