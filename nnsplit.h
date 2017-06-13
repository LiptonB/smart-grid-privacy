#ifndef _NNSPLIT_H
#define _NNSPLIT_H 1

#include <stdint.h>

typedef struct _nnsplit_ctx nnsplit_ctx;

nnsplit_ctx *nnsplit_ctx_init(unsigned int sharecount, unsigned int threshold);
void nnsplit_setsecret(nnsplit_ctx *ctx, uint32_t secret);
void nnsplit_getshare(nnsplit_ctx *ctx, unsigned int sharenr, unsigned char *share);
void nnsplit_extract(nnsplit_ctx *ctx, uint32_t *secret);
void nnsplit_giveshare(nnsplit_ctx *ctx, unsigned char *share);
void nnsplit_ctx_free(nnsplit_ctx *ctx);

#endif
