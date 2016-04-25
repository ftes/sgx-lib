#ifndef SGX_LIB_T_STDIO_H
#define SGX_LIB_T_STDIO_H

#include "sgx_lib_stdio.h"

/* file functions */
void rewind(FILE* file);
int fseek(FILE* file, long offset, int origin);
long ftell(FILE* file);
size_t fwrite(const void* buffer, size_t size, size_t count, FILE* stream);
size_t fread(void* buffer, size_t size, size_t count, FILE* stream);
int fclose(FILE* stream);
FILE* fopen(const char* filename, const char* mode);


/* GENERATE OCALL CODE AFTER THIS LINE */


#endif