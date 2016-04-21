#include "enclave_t.h"
#include "sgx_trts.h"
#include "util_t.h"

#define FILE_NAME "test_file_in_application_dir.txt"
void add_secret(int secret) {
  FILE *file = fopen(FILE_NAME, "w" /*delete existing*/);
  fwrite(&secret, sizeof(secret), 1, file);
  fclose(file);
}

void print_secrets() {
  FILE *file = fopen(FILE_NAME, "r");
  long size;

  fseek (file , 0 , SEEK_END);
  size = ftell (file);
  rewind (pFile);
  int secret;
  size_t ret;
  fread(&secret, sizeof(secret), 1, file);
  log("%d", secret);
  fclose(file);
}