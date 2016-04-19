#include "enclave_t.h"
#include "sgx_trts.h"
#include "util.h"

#define FILE_NAME "test_file_in_application_dir.txt"
void add_secret(int secret) {
  FILE *file = fopen(FILE_NAME, "rw");
  fwrite(&secret , 1 , sizeof(secret) , file);
  fclose(file);
}

void print_secrets() {
  FILE *file = fopen(FILE_NAME, "r");
  int secret;
  size_t ret;
  //fread(&secret, 1, sizeof(secret), file);
  log("%d", secret);
  fclose(file);
}