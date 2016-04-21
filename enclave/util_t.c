#include <stdlib.h>
#include <sgx_trts.h>
#include "util_t.h"
#include "enclave_t.h"

#define MAX_LOG_MESSAGE_LENGTH 200
/* maximum length: 200 characters */

/* combines sprintf and log */
void log(char* format, ...) {
  char *formatted;

  va_list argptr;
  va_start(argptr, format);
  formatted = (char*) malloc(MAX_LOG_MESSAGE_LENGTH * sizeof(*formatted));
  vsnprintf(formatted, MAX_LOG_MESSAGE_LENGTH, format, argptr);
  va_end(argptr);

  log_ocall(formatted);
}

void check(sgx_status_t rc) {
  if (rc != SGX_SUCCESS) {
    char* desc = get_error_description(rc);
    log(desc);
  }
}

FILE* fopen(const char* filename, const char* mode) {
  FILE *file;
  check(fopen_ocall(&file, filename, mode));
  return file;
}

int fclose(FILE * stream) {
  int rc;
  check(fclose_ocall(&rc, stream));
  return rc;
}

int fseek(FILE* file, long offset, int origin) {
  int rc;
  check(fseek_ocall(&rc, file, offset, origin));
  return rc;
}

long ftell(FILE* file) {
  long ret;
  check(ftell_ocall(&ret, file));
  return ret;
}

#ifdef SGX_INSECURE_FILE_OPERATIONS
size_t fwrite(const void* buffer, size_t size, size_t count, FILE* stream) {
  size_t ret;
  log("insecure file operation used");
  check(fwrite_ocall(&ret, buffer, size, count, stream));
  return ret;
}

size_t fread(const void* buffer, size_t size, size_t count, FILE* stream) {
  size_t ret;
  log("insecure file operation used");
  check(fread_ocall(&ret, buffer, size, count, stream));
  return ret;
}
#else
size_t fwrite(const void* buffer, size_t size, size_t count, FILE* stream) {
  //TODO seal upon writing
  throw std::runtime_error("secure fwrite not implemented");
}

size_t fread(const void* buffer, size_t size, size_t count, FILE* stream) {
  //TODO unseal upon reading
  throw std::runtime_error("secure fread not implemented");
}
#endif