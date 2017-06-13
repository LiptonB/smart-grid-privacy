#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "shamir.h"

int main(int argc, char *argv[]) {
  unsigned char *sharenrs;
  int sharelen = -1;
  int i,j;
  gfshare_ctx *G;
  int sharecount = (argc-1)/2;
  char *curarg;
  unsigned char *curshare;
  uint32_t message;

  if (argc < 3 || argc % 2 == 0) {
    fprintf(stderr, "Usage: %s x1 y1 x2 y2 ...\n", argv[0]);
    exit(1);
  }

  sharenrs = malloc(sharecount * sizeof(*sharenrs));

  for (i = 0; i < sharecount; i++) {
    sharenrs[i] = strtoul(argv[1+2*i], NULL, 0);
    if (sharelen == -1) {
      sharelen = strlen(argv[2+2*i]);
    } else if (sharelen != strlen(argv[2+2*i])) {
      fprintf(stderr, "Length of share %d is incorrect\n", i);
      exit(1);
    }
  }

  sharelen = (sharelen-2)/2;

  G = gfshare_ctx_init_dec(sharenrs, sharecount);
  curshare = malloc(sharelen);

  for (i = 0; i < sharecount; i++) {
    curarg = argv[2+2*i];
    for (j = 0; j < sharelen; j++) {
      sscanf(&curarg[2+2*j], "%02hhx", &curshare[j]);
    }
    gfshare_ctx_dec_giveshare(G, i, curshare);
  }

  gfshare_ctx_dec_extract(G, &message);
  printf("Message was: %d\n", message);

  free(sharenrs);
}
