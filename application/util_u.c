#include "enclave_u.h"

#define LOG_FILE "log.txt"
void log_ocall(char* message) {
  FILE *file = fopen(LOG_FILE, "a");
  if (file != NULL) {
    fputs(message, file);
    fputs("\n", file);
    fclose(file);
  }
}

/* Function definitions in the .edl can also link directly against implementations provided by DLLs by adding [cdecl, dllimport] (see SDK guide).
   However, the generated stub in the enclave has a different signature in case the function has a return value. The generated signature of the
   trusted fopen stub would look like this:

   fopen(int* retVal, const char* filename, const char* mode);

   So to provide trusted functions with the original signature, one has to overload the functions in the enclave. This is not possible in C, so
   C++ has to be used. Pulling in a dependency on C++ is not a good tradeoff for saving three lines per ocall in this file.
   
   Rather, the ocalls are named *_ocall, so no overloading is necessary, and the wrapper functions in this file then link the stubs against the
   actual DLL implementations.
*/

/* file functions */
void rewind_ocall(FILE* file) {
  rewind(file);
}

int fseek_ocall(FILE* file, long offset, int origin) {
  return fseek(file, offset, origin);
}

long ftell_ocall(FILE* file) {
  return ftell(file);
}

size_t fwrite_ocall(const void* buffer, size_t size, size_t count, FILE* stream) {
  return fwrite(buffer, size, count, stream);
}

size_t fread_ocall(void* buffer, size_t size, size_t count, FILE* stream) {
  return fread(buffer, size, count, stream);
}

int fclose_ocall(FILE* stream) {
  return fclose(stream);
}

FILE* fopen_ocall(const char* filename, const char* mode) {
  return fopen(filename, mode);
}


/* GENERATE OCALL CODE AFTER THIS LINE */

