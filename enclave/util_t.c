#include <stdlib.h>
#include <sgx_trts.h>
#include "util_t.h"
#include "enclave_t.h"
#include "util.h"

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

#ifdef SGX_INSECURE_IO_OPERATIONS
size_t fwrite(const void* buffer, size_t size, size_t count, FILE* stream) {
  size_t ret;
  check(fwrite_ocall(&ret, buffer, size, count, stream));
  return ret;
}

size_t fread(void* buffer, size_t size, size_t count, FILE* stream) {
  size_t ret;
  check(fread_ocall(&ret, buffer, size, count, stream));
  return ret;
}

/* combines sprintf and log */
void log(char* format, ...) {
  char *formatted;
  va_list argptr;
  va_start(argptr, format);
  formatted = vsprintf(format, argptr);
  va_end(argptr);
  log_ocall(formatted);
  free(formatted);
}

void printf(char* format, ...) {
  char *formatted;
  va_list argptr;
  va_start(argptr, format);
  formatted = vsprintf(format, argptr);
  va_end(argptr);
  print_ocall(formatted);
  free(formatted);
}
#else
// missing
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
