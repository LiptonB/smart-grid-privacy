#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"
#include "nnsplit.h"

int main(int argc, char *argv[]) {
  FILE *fp;
  unsigned char share[sizeof(uint32_t)];
  int shares, threshold, i, j;
  gmp_randstate_t randstate;
  nnsplit_ctx *ctx;

  if (argc != 4) {
    fprintf(stderr, "Usage: %s <message> <shares> <threshold>\n", argv[0]);
    exit(1);
  }

  shares = atoi(argv[2]);
  threshold = atoi(argv[3]);

  ctx = nnsplit_ctx_init(shares, threshold);
  nnsplit_setsecret(ctx, atoi(argv[1]));

  for (i = 0; i < shares; i++) {
    nnsplit_getshare(ctx, i, share);
    printf("Share %d: ", i+1);
    printf_hex(share, sizeof(share));
    printf("\n");
  }
}
