// this include is essential, otherwise the whole project won't compile (without a decent error message)
#include <stdlib.h>

#include "sgx_lib_stdio.h"
#include "sgx_lib_t_stdio.h"
#include "sgx_lib_t_logging.h"
#include "../sgx_lib_t/sgx_lib_t.h"

#define FILE_NAME "test_file_in_application_dir.txt"
void add_secret(int secret) {
  FILE *file = fopen(FILE_NAME, "wb" /*delete existing file, binary*/);
  fwrite(&secret, sizeof(secret), 1, file);
  fclose(file);
}

void print_secrets() {
  long size;
  int secret;
  size_t ret;
  FILE *file = fopen(FILE_NAME, "rb" /*binary*/);
  fread(&secret, sizeof(secret), 1, file);
  log_ocall("Secret: aaa");
  log("Secret: %d", secret);
  fclose(file);
}