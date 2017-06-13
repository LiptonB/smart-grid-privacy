#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"
#include "paillier.h"

int main(int argc, char *argv[]) {
  pubkey pub;
  FILE *fp;
  unsigned char *share, *accum, *newaccum;
  size_t msglen, accumlen, newaccumlen;
  int i;

  if (argc < 3) {
    fprintf(stderr, "Usage: %s <pubkey> <share> ...\n", argv[0]);
    exit(1);
  }

  fp = fopen(argv[1], "r");
  pubkey_init(&pub);
  pubkey_fscan(fp, &pub);
  fclose(fp);

  accumlen = strlen(argv[2])/2;
  accum = malloc(accumlen);
  sscanf_hex(accum, argv[2], accumlen);
  for (i = 3; i < argc; i++) {
    msglen = strlen(argv[i])/2;
    share = malloc(msglen);
    sscanf_hex(share, argv[i], msglen);
    newaccum = NULL;
    newaccumlen = 0;
    paillier_add(&newaccum, &newaccumlen, accum, accumlen, share, msglen, &pub);
    // TODO: don't like this business here
    free(accum);
    free(share);
    accum = newaccum;
    accumlen = newaccumlen;
  }

  printf("Combined: ");
  printf_hex(accum, accumlen);
  printf("\n");

  pubkey_clear(&pub);
}
