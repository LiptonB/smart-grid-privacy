#include <gmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"
#include "paillier.h"

int main(int argc, char *argv[]) {
  pubkey pub;
  FILE *fp;
  unsigned char *enc = NULL;
  uint32_t msg;
  size_t msglen = 0;
  int i;

  if (argc != 3) {
    fprintf(stderr, "Usage: %s <message> <pubkey>\n", argv[0]);
    exit(1);
  }

  msg = atoi(argv[1]);

  fp = fopen(argv[2], "r");
  pubkey_init(&pub);
  pubkey_fscan(fp, &pub);
  fclose(fp);

  encrypt(&enc, &msglen, msg, &pub);
  printf_hex(enc, msglen);
  printf("\n");

  pubkey_clear(&pub);
}
