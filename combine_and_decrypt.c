#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "util.h"
#include "paillier.h"

int main(int argc, char *argv[]) {
  seckey sec;
  FILE *fp;
  unsigned char *share, *accum, *newaccum;
  size_t msglen, accumlen, newaccumlen;
  int i;
  uint32_t m;

  if (argc < 3) {
    fprintf(stderr, "Usage: %s <seckey> <share> ...\n", argv[0]);
    exit(1);
  }

  fp = fopen(argv[1], "r");
  seckey_init(&sec);
  seckey_fscan(fp, &sec);
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
    paillier_add(&newaccum, &newaccumlen, accum, accumlen, share, msglen, &sec.pub);
    // TODO: don't like this business here
    free(accum);
    free(share);
    accum = newaccum;
    accumlen = newaccumlen;
  }

  m = decrypt(accum, accumlen, &sec);
  printf("Message: %d\n", m);

  seckey_clear(&sec);
  free(accum);
}
