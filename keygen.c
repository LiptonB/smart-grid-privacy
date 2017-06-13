#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "paillier.h"

int main(int argc, char *argv[]) {
  seckey sec;
  char *filename;
  size_t filename_prefix_len;
  FILE *fp;

  if (argc != 2) {
    fprintf(stderr, "Usage: %s <key_filename_prefix>\n", argv[0]);
    exit(1);
  }

  filename_prefix_len = strlen(argv[1]);
  filename = malloc(filename_prefix_len + 5);
  
  seckey_init(&sec);
  keygen(&sec, 2048);

  strncpy(filename, argv[1], filename_prefix_len + 1);
  strncat(filename, ".sec", 5);
  fp = fopen(filename, "w");
  seckey_fprint(fp, &sec);
  fclose(fp);
  printf("Wrote secret key: %s\n", filename);

  strncpy(filename, argv[1], filename_prefix_len + 1);
  strncat(filename, ".pub", 5);
  fp = fopen(filename, "w");
  pubkey_fprint(fp, &sec.pub);
  fclose(fp);
  printf("Wrote public key: %s\n", filename);

  seckey_clear(&sec);
}
