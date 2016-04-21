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

FILE* fopen_ocall(const char* filename, const char* mode) {
  return fopen(filename, mode);
}

int fclose_ocall(FILE * stream) {
  return fclose(stream);
}

size_t fwrite_ocall(const void* buffer, size_t size, size_t count, FILE* stream) {
  return fwrite(buffer, size, count, stream);
}

size_t fread_ocall(const void* buffer, size_t size, size_t count, FILE* stream) {
  return fread(buffer, size, count, stream);
}

int fseek_ocall(FILE* file, long offset, int origin) {
  return fseek(file, offset, origin);
}

long ftell_ocall(FILE* file) {
  return ftell(file);
}