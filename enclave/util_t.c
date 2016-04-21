#include <stdlib.h>
#include <sgx_trts.h>
#include "util_t.h"
#include "enclave_t.h"
#include "util.h"

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


#ifdef SGX_INSECURE_FILE_OPERATIONS

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


/* GENERATE OCALL CODE AFTER THIS LINE */