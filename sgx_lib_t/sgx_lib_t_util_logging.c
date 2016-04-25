#include <stdlib.h>

#include "sgx_lib_t.h"
#include "sgx_lib_t_util.h"

/* INSECURE - leaks plaintext data */
void log(char* format, ...) {
  char *formatted;
  va_list argptr;
  va_start(argptr, format);
  formatted = vsprintf(format, argptr);
  va_end(argptr);
  log_ocall(formatted);
  free(formatted);
}