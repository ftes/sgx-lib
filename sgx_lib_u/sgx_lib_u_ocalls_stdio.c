#include "sgx_lib_u.h"

void rewind_ocall(FILE* file) {
  rewind(file);
}

int fseek_ocall(FILE* file, long offset, int origin) {
  return fseek(file, offset, origin);
}

long ftell_ocall(FILE* file) {
  return ftell(file);
}

size_t fwrite_enclave_memory_ocall(const void* buffer, size_t size, size_t count, FILE* stream) {
  // buffer ([in]) is managed by SGX proxy (according to SDK guide 1.1, p. 53)
  // "the trusted proxy allocates memory outside the enclave and copies the memory pointed to by the pointer from inside the enclave to untrusted memory"
  return fwrite(buffer, size, count, stream);
}

size_t fread_copy_into_enclave_memory_ocall(void* buffer, size_t size, size_t count, FILE* stream) {
  // buffer ([out]) is allocated here in untrusted memory by SGX proxy (according to SDK guide 1.1, p. 53)
  // "the trusted proxy allocates a buffer on the untrusted stack, and passes a pointer to this buffer to the untrusted function"
  return fread(buffer, size, count, stream);
}

int fclose_ocall(FILE* stream) {
  return fclose(stream);
}

FILE* fopen_ocall(const char* filename, const char* mode) {
  return fopen(filename, mode);
}