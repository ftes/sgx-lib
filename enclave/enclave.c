#include "enclave_t.h"
#include "sgx_trts.h"
#include "util_t.h"
#include "stdlib.h"

#define FILE_NAME "test_file_in_application_dir.txt"
void add_secret(int secret) {
  FILE *file = fopen(FILE_NAME, "wb" /*delete existing file, binary*/);
  fwrite(&secret, sizeof(secret), 1, file);
  fclose(file);
}

void print_secrets() {
  FILE *file = fopen(FILE_NAME, "rb" /*binary*/);
  long size;
  int secret;
  size_t ret;
  fread(&secret, sizeof(secret), 1, file);
  log("Secret: %d", secret);
  fclose(file);
}