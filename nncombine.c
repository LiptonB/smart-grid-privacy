#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "nnsplit.h"

int main(int argc, char *argv[]) {
  int nshares;
  int sharelen;
  unsigned char *share;
  uint32_t secret;
  int i, j;
  nnsplit_ctx *ctx;

  if (argc < 2) {
    fprintf(stderr, "Usage: %s <share> ...\n", argv[0]);
    exit(1);
  }

  nshares = argc-1;
  sharelen = strlen(argv[1])/2;
  share = malloc(sharelen);

  ctx = nnsplit_ctx_init(nshares, nshares);

  for (i = 0; i < nshares; i++) {
    for (j = 0; j < sharelen; j++) {
      sscanf(&argv[1+i][2*j], "%02hhx", &share[j]);
    }
    nnsplit_giveshare(ctx, share);
  }
  nnsplit_extract(ctx, &secret);

  printf("Message: %d\n", secret);

  nnsplit_ctx_free(ctx);
  free(share);
}
