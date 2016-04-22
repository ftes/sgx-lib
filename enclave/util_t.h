#ifndef UTIL_H
#define UTIL_H

#include "mystdio.h"

void log(char* format, ...);
void printf(char* format, ...);

/* file functions */
void rewind(FILE* file);
int fseek(FILE* file, long offset, int origin);
long ftell(FILE* file);
size_t fwrite(const void* buffer, size_t size, size_t count, FILE* stream);
size_t fread(void* buffer, size_t size, size_t count, FILE* stream);
int fclose(FILE* stream);
FILE* fopen(const char* filename, const char* mode);


/* GENERATE OCALL CODE AFTER THIS LINE */


#endif UTIL_H