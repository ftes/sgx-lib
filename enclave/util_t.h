#ifndef UTIL_H
#define UTIL_H

#include "mystdio.h"

void log(char* format, ...);

FILE*    fopen(const char * filename, const char * mode);
size_t   fread(void * buffer, size_t size, size_t count, FILE * file);
size_t   fwrite(const void * buffer, size_t size, size_t count, FILE * file);
int      fclose(FILE * file);
int      fseek(FILE* file, long offset, int origin);
long     ftell(FILE* file);


/* GENERATE OCALL CODE AFTER THIS LINE */

#endif UTIL_H