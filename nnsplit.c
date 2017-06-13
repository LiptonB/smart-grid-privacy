#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

#include "util.h"
#include "nnsplit.h"

struct _nnsplit_ctx {
  unsigned int sharecount;
  unsigned int threshold;
  uint32_t *shares;
  unsigned int storedshares;
  unsigned int seed;
  int sharebytes;
  uint32_t shareoffset;
};

nnsplit_ctx *nnsplit_ctx_init(unsigned int sharecount, unsigned int threshold) {
  nnsplit_ctx *ctx;
  int i;

  ctx = malloc(sizeof(*ctx));
  ctx->sharecount = sharecount;
  ctx->threshold = threshold;
  ctx->storedshares = 0;
  ctx->shares = malloc(sharecount * sizeof(*ctx->shares));

  get_rand((unsigned char *)&ctx->seed, sizeof(ctx->seed));

  return ctx;
}

void nnsplit_setsecret(nnsplit_ctx *ctx, uint32_t secret) {
  int i;
  uint32_t remaining;
  int choice;
  unsigned char selected[ctx->sharecount];
  uint32_t share;

  // First select which aggregators will receive shares
  memset(selected, 0, ctx->sharecount);
  for (i = 0; i < ctx->threshold; i++) {
    do {
      choice = rand_r_uniform(&ctx->seed, ctx->sharecount);
    } while (selected[choice]);
    selected[choice] = 1;
  }

  // Now generate the shares
  remaining = secret;

  for (i = 0; i < ctx->sharecount; i++) {
    if (selected[i]) {
      if (i != choice) { // all but final share
        get_rand((unsigned char *)&share, sizeof(share));
        remaining -= share;
        ctx->shares[i] = share;
      }
    } else {
      ctx->shares[i] = 0;
    }
  }
  ctx->shares[choice] = remaining;
  ctx->storedshares = ctx->sharecount;
}

void nnsplit_getshare(
    nnsplit_ctx *ctx, unsigned int sharenr, unsigned char *share) {
  uint32_t *intptr = (uint32_t *)share;
  *intptr = ctx->shares[sharenr];
}

void nnsplit_extract(nnsplit_ctx *ctx, uint32_t *secret) {
  int i;
  
  *secret = 0;
  for (i = 0; i < ctx->sharecount; i++) {
    *secret += ctx->shares[i];
  }
}

void nnsplit_giveshare(nnsplit_ctx *ctx, unsigned char *share) {
  uint32_t *intptr = (uint32_t *)share;
  ctx->shares[ctx->storedshares] = *intptr;
  ctx->storedshares++;
}

void nnsplit_ctx_free(nnsplit_ctx *ctx) {
  free(ctx->shares);
  free(ctx);
}
