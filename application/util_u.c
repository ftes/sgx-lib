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


/* GENERATE OCALL CODE AFTER THIS LINE */

