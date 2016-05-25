#ifndef SGX_LIB_T_UTIL_H
#define SGX_LIB_T_UTIL_H

#include <stdarg.h>

#include <sgx_error.h>

char* vsprintf(char* format, va_list args);
void check(sgx_status_t rc);

#endif