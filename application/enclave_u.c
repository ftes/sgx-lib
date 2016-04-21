#include "enclave_u.h"

typedef struct ms_add_secret_t {
	int ms_secret;
} ms_add_secret_t;


typedef struct ms_fopen_ocall_t {
	FILE* ms_retval;
	char* ms_filename;
	char* ms_mode;
} ms_fopen_ocall_t;

typedef struct ms_fclose_ocall_t {
	int ms_retval;
	FILE* ms_stream;
} ms_fclose_ocall_t;

typedef struct ms_fwrite_ocall_t {
	size_t ms_retval;
	void* ms_buffer;
	size_t ms_size;
	size_t ms_count;
	FILE* ms_stream;
} ms_fwrite_ocall_t;

typedef struct ms_fread_ocall_t {
	size_t ms_retval;
	void* ms_buffer;
	size_t ms_size;
	size_t ms_count;
	FILE* ms_stream;
} ms_fread_ocall_t;

typedef struct ms_fseek_ocall_t {
	int ms_retval;
	FILE* ms_file;
	long int ms_offset;
	int ms_origin;
} ms_fseek_ocall_t;

typedef struct ms_ftell_ocall_t {
	long int ms_retval;
	FILE* ms_file;
} ms_ftell_ocall_t;

typedef struct ms_log_ocall_t {
	char* ms_message;
} ms_log_ocall_t;

static sgx_status_t SGX_CDECL enclave_fopen_ocall(void* pms)
{
	ms_fopen_ocall_t* ms = SGX_CAST(ms_fopen_ocall_t*, pms);
	ms->ms_retval = fopen_ocall((const char*)ms->ms_filename, (const char*)ms->ms_mode);
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_fclose_ocall(void* pms)
{
	ms_fclose_ocall_t* ms = SGX_CAST(ms_fclose_ocall_t*, pms);
	ms->ms_retval = fclose_ocall(ms->ms_stream);
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_fwrite_ocall(void* pms)
{
	ms_fwrite_ocall_t* ms = SGX_CAST(ms_fwrite_ocall_t*, pms);
	ms->ms_retval = fwrite_ocall((const void*)ms->ms_buffer, ms->ms_size, ms->ms_count, ms->ms_stream);
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_fread_ocall(void* pms)
{
	ms_fread_ocall_t* ms = SGX_CAST(ms_fread_ocall_t*, pms);
	ms->ms_retval = fread_ocall(ms->ms_buffer, ms->ms_size, ms->ms_count, ms->ms_stream);
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_fseek_ocall(void* pms)
{
	ms_fseek_ocall_t* ms = SGX_CAST(ms_fseek_ocall_t*, pms);
	ms->ms_retval = fseek_ocall(ms->ms_file, ms->ms_offset, ms->ms_origin);
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_ftell_ocall(void* pms)
{
	ms_ftell_ocall_t* ms = SGX_CAST(ms_ftell_ocall_t*, pms);
	ms->ms_retval = ftell_ocall(ms->ms_file);
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_log_ocall(void* pms)
{
	ms_log_ocall_t* ms = SGX_CAST(ms_log_ocall_t*, pms);
	log_ocall(ms->ms_message);
	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * func_addr[7];
} ocall_table_enclave = {
	7,
	{
		(void*)(uintptr_t)enclave_fopen_ocall,
		(void*)(uintptr_t)enclave_fclose_ocall,
		(void*)(uintptr_t)enclave_fwrite_ocall,
		(void*)(uintptr_t)enclave_fread_ocall,
		(void*)(uintptr_t)enclave_fseek_ocall,
		(void*)(uintptr_t)enclave_ftell_ocall,
		(void*)(uintptr_t)enclave_log_ocall,
	}
};

sgx_status_t add_secret(sgx_enclave_id_t eid, int secret)
{
	sgx_status_t status;
	ms_add_secret_t ms;
	ms.ms_secret = secret;
	status = sgx_ecall(eid, 0, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t print_secrets(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 1, &ocall_table_enclave, NULL);
	return status;
}

