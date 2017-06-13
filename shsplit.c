#include <stdio.h>
#include <stdlib.h>

#include "shamir.h"

#define SHARES 5
#define THRESHOLD 3

static void
gfsplit_fill_rand( unsigned char *buffer,
                   unsigned int count )
{
  size_t n;
  FILE *devrandom;

  devrandom = fopen("/dev/urandom", "rb");
  if (!devrandom) {
    perror("Unable to read /dev/urandom");
    abort();
  }
  n = fread(buffer, 1, count, devrandom);
  if (n < count) {
      perror("Short read from /dev/urandom");
      abort();
  }
  fclose(devrandom);
}

int main(int argc, char *argv[]) {
  unsigned char sharenrs[SHARES];
  int i,j;
  uint32_t message;
  unsigned char buffer[sizeof(message)];
  gfshare_ctx *G;

  if (argc != 2) {
    fprintf(stderr, "Usage: %s <message>\n", argv[0]);
    exit(1);
  }

  gfshare_fill_rand = gfsplit_fill_rand;

  sscanf(argv[1], "%d", &message);

  for (i = 0; i < SHARES; i++) {
    sharenrs[i] = i+1;
  }

  G = gfshare_ctx_init_enc(sharenrs, SHARES, THRESHOLD);
  if (!G) {
    perror("gfshare_ctx_init_enc");
    return 1;
  }

  gfshare_ctx_enc_setsecret(G, message);
  for (i = 0; i < SHARES; i++) {
    gfshare_ctx_enc_getshare(G, i, buffer);
    printf("0x%x 0x", i+1);
    for (j = 0; j < sizeof(buffer); j++) {
      printf("%02x", buffer[j]);
    }
    printf("\n");
  }
}
