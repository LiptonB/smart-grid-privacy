/*
 * This file is Copyright Daniel Silverstone <dsilvers@digital-scurf.org> 2006,2015
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 */

#include "shamir.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#define XMALLOC malloc
#define XFREE free

// Largest 32-bit prime (2**32-5)
#define MODULUS 4294967291UL

struct _gfshare_ctx {
  unsigned int sharecount;
  unsigned int threshold;
  unsigned int size;
  unsigned char* sharenrs;
  uint32_t* buffer;
  unsigned int buffersize;
};

static void
_gfshare_fill_rand_using_random( unsigned char* buffer,
                                 unsigned int count )
{
  unsigned int i;
  for( i = 0; i < count; ++i )
    buffer[i] = (random() & 0xff00) >> 8; /* apparently the bottom 8 aren't
                                           * very random but the middles ones
                                           * are
                                           */
}
const gfshare_rand_func_t gfshare_bad_idea_but_fill_rand_using_random =
	_gfshare_fill_rand_using_random;
gfshare_rand_func_t gfshare_fill_rand = NULL;

/* ------------------------------------------------------[ Preparation ]---- */

static gfshare_ctx *
_gfshare_ctx_init_core( unsigned char *sharenrs,
                        unsigned int sharecount,
                        unsigned char threshold)
{
  gfshare_ctx *ctx;
  
  ctx = XMALLOC( sizeof(struct _gfshare_ctx) );
  if( ctx == NULL )
    return NULL; /* errno should still be set from XMALLOC() */
  
  ctx->sharecount = sharecount;
  ctx->threshold = threshold;
  ctx->size = sizeof(uint32_t);
  ctx->sharenrs = XMALLOC( sharecount );
  
  if( ctx->sharenrs == NULL ) {
    int saved_errno = errno;
    XFREE( ctx );
    errno = saved_errno;
    return NULL;
  }
  
  memcpy( ctx->sharenrs, sharenrs, sharecount );
  ctx->buffersize = threshold * ctx->size;
  ctx->buffer = XMALLOC( ctx->buffersize );
  
  if( ctx->buffer == NULL ) {
    int saved_errno = errno;
    XFREE( ctx->sharenrs );
    XFREE( ctx );
    errno = saved_errno;
    return NULL;
  }
  
  return ctx;
}

/* Initialise a gfshare context for producing shares */
gfshare_ctx *
gfshare_ctx_init_enc( unsigned char* sharenrs,
                      unsigned int sharecount,
                      unsigned char threshold)
{
  unsigned int i;

  for (i = 0; i < sharecount; i++) {
    if (sharenrs[i] == 0) {
      /* can't have x[i] = 0 - that would just be a copy of the secret, in
       * theory (in fact, due to the way we use exp/log for multiplication and
       * treat log(0) as 0, it ends up as a copy of x[i] = 1) */
      errno = EINVAL;
      return NULL;
    }
  }

  return _gfshare_ctx_init_core( sharenrs, sharecount, threshold );
}

/* Initialise a gfshare context for recombining shares */
gfshare_ctx*
gfshare_ctx_init_dec( unsigned char* sharenrs,
                      unsigned int sharecount )
{
  gfshare_ctx *ctx = _gfshare_ctx_init_core( sharenrs, sharecount, sharecount );
  
  if( ctx != NULL )
    ctx->threshold = 0;
  
  return ctx;
}

/* Free a share context's memory. */
void 
gfshare_ctx_free( gfshare_ctx* ctx )
{
  gfshare_fill_rand( (unsigned char *)ctx->buffer, ctx->buffersize );
  gfshare_fill_rand( ctx->sharenrs, ctx->sharecount );
  XFREE( ctx->sharenrs );
  XFREE( ctx->buffer );
  gfshare_fill_rand( (unsigned char*)ctx, sizeof(struct _gfshare_ctx) );
  XFREE( ctx );
}

/* --------------------------------------------------------[ Splitting ]---- */

/* Provide a secret to the encoder. (this re-scrambles the coefficients) */
void 
gfshare_ctx_enc_setsecret( gfshare_ctx* ctx,
                           uint32_t secret)
{
  memcpy( ctx->buffer + (ctx->threshold-1),
          &secret,
          ctx->size );
  gfshare_fill_rand( (unsigned char *)ctx->buffer, (ctx->threshold-1) * ctx->size );
}

/* Extract a share from the context. 
 * 'share' must be preallocated and at least 'size' bytes long.
 * 'sharenr' is the index into the 'sharenrs' array of the share you want.
 */
void
gfshare_ctx_enc_getshare( gfshare_ctx* ctx,
                          unsigned char sharenr,
                          unsigned char* share)
{
  unsigned int coefficient;
  unsigned char xval = ctx->sharenrs[sharenr];
  uint32_t *coefficient_ptr = ctx->buffer;
  uint64_t temp;
  uint32_t *share_ptr = (uint32_t *)share;
  temp = *(coefficient_ptr++);
  for( coefficient = 1; coefficient < ctx->threshold; ++coefficient ) {
    // multiply current value of share by ctx->sharenrs[sharenr]
    // add *coefficient_ptr
    // all operations mod MODULUS
    temp *= xval;
    temp += *coefficient_ptr++;
    temp %= MODULUS;
  }

  *share_ptr = temp;
}

/* ----------------------------------------------------[ Recombination ]---- */

/* Inform a recombination context of a change in share indexes */
void 
gfshare_ctx_dec_newshares( gfshare_ctx* ctx,
                           unsigned char* sharenrs)
{
  memcpy( ctx->sharenrs, sharenrs, ctx->sharecount );
}

/* Provide a share context with one of the shares.
 * The 'sharenr' is the index into the 'sharenrs' array
 */
void 
gfshare_ctx_dec_giveshare( gfshare_ctx* ctx,
                           unsigned char sharenr,
                           unsigned char* share )
{
  memcpy( ctx->buffer + sharenr, share, ctx->size );
}

// modInv: Computes the multiplicative inverse of val, modulo mod. Uses the
// extended Euclidean algorithm to compute the inverse. If the value is not
// invertible, returns -1, otherwise returns an integer in [0, mod).
uint64_t modInv(uint64_t val, uint64_t mod) {
  int64_t a0, b0, t, t0, q, r, temp;
  int64_t smod = mod;

  a0 = mod;
  b0 = val;
  t0 = 0;
  t = 1;
  q = a0 / b0;
  r = a0 - q * b0;
  while (r > 0) {
    temp = (t0 - q * t) % smod;
    t0 = t;
    t = temp;
    a0 = b0;
    b0 = r;
    q = a0 / b0;
    r = a0 - q * b0;
  }
  if (b0 == 1) {
    return (t + smod) % smod; // Make the result positive
  } else {
    return -1;
  }
}

/* Extract the secret by interpolation of the shares.
 * secretbuf must be allocated and at least 'size' bytes long
 */
void
gfshare_ctx_dec_extract( gfshare_ctx* ctx,
                         uint32_t* secretbuf )
{
  unsigned int i, j;
  uint64_t secret = 0;

  for( i = 0; i < ctx->sharecount; ++i ) {
    /* Compute L(i) as per Lagrange Interpolation */
    uint64_t Li_top = 1, Li_bottom = 1;

    if( ctx->sharenrs[i] == 0 ) continue; /* this share is not provided. */

    for( j = 0; j < ctx->sharecount; ++j ) {
      if( i == j ) continue;
      if( ctx->sharenrs[j] == 0 ) continue; /* skip empty share */
      Li_top *= MODULUS - ctx->sharenrs[j];
      Li_top %= MODULUS;
      Li_bottom *= (ctx->sharenrs[i] - ctx->sharenrs[j] + MODULUS) % MODULUS;
      Li_bottom %= MODULUS;
    }
    Li_bottom = modInv(Li_bottom, MODULUS); /* Li_top is now log(L(i)) */
    Li_top = Li_top * Li_bottom % MODULUS;

    secret = (secret + Li_top * ctx->buffer[i]) % MODULUS;
  }

  *secretbuf = secret;
}
