#include <stdlib.h>

#include "sgx_lib_t.h"
#include "sgx_lib.h"

#include "sgx_lib_t_debug.h"

#include "sgx_lib_t_util.h"

void check(sgx_status_t rc) {
  if (rc != SGX_SUCCESS) {
    char* desc = get_error_description(rc);
    log_msg(desc);
  }
}

/* parameters:
 * [OUT] format: must be free()-d by caller
 */
char* vsprintf(char* format, va_list args) {
  char *formatted;
  int size;
  size = vsnprintf(NULL, 0, format, args) + 1; //+1 for trailing \0
  formatted = (char*) malloc(size * sizeof(*formatted));
  vsnprintf(formatted, size, format, args);
  return formatted;
}