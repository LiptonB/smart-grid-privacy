#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include "shamir.h"
#include "util.h"
#include "nnsplit.h"
#include "paillier.h"

#define ITERATIONS 10
#define AGGREGATORS 10
#define SHARES 5
#define THRESHOLD 5

#define NNSPLIT 1
#define GFSHARE 2
#define PAILLIER 3

int main(int argc, char *argv[]) {
  uint32_t message;
  clock_t start, end;
  int i,j;

  int opt;
  unsigned int iterations = ITERATIONS;
  unsigned int aggregators = AGGREGATORS;
  unsigned int shares = SHARES;
  unsigned int threshold = THRESHOLD;
  char *keypath = NULL;
  signed char scheme = -1;

  nnsplit_ctx *nnctx;
  unsigned char nnshare[sizeof(message)];

  gfshare_ctx *gfctx;
  unsigned char *sharenrs;
  unsigned char gfshare[sizeof(message)];

  FILE *fp;
  pubkey pub;
  unsigned char *enc;
  size_t clen;

  while ((opt = getopt(argc, argv, "NSPi:a:n:k:p:")) != -1) {
    switch (opt) {
      case 'N': // nnsplit
        scheme = NNSPLIT;
        break;
      case 'S': // shamir
        scheme = GFSHARE;
        break;
      case 'P': // paillier
        scheme = PAILLIER;
        break;
      case 'i': // iterations
        iterations = atoi(optarg);
        break;
      case 'a': // aggregators
        aggregators = atoi(optarg);
        break;
      case 'n': // number of shares for nnsplit
        shares = atoi(optarg);
        break;
      case 'k': // threshold number of shares for shamir
        threshold = atoi(optarg);
        break;
      case 'p': // path of paillier public key
        keypath = optarg;
        break;
    }
  }

  if (scheme == -1) {
    fprintf(stderr, "One of the N, S, P flags is required\n");
    exit(1);
  }
  if (scheme == PAILLIER && keypath == NULL) {
    fprintf(stderr, "-p must be specified for Paillier encryption\n");
    exit(1);
  }

  // Seed random number generator (if needed)

  // Randomly generate 16-bit message
  message = 0;
  get_rand((unsigned char *)&message, 2);

  switch(scheme) {
    case NNSPLIT:
      // Initialize nnsplit
      nnctx = nnsplit_ctx_init(aggregators, shares);

      // Start timer
      start = clock();

      // Split or encrypt message 100 times
      for (i = 0; i < iterations; i++) {
        nnsplit_setsecret(nnctx, message);
        for (j = 0; j < shares; j++) {
          nnsplit_getshare(nnctx, j, nnshare);
        }
      }

      // Stop timer
      end = clock();

      printf("Probabilistic, %d out of %d: %d iterations, %ld us\n",
          shares, aggregators, iterations, (end-start));

      nnsplit_ctx_free(nnctx);
      break;

    case GFSHARE:
      // Initialize gfsplit
      gfshare_fill_rand = get_rand;
      sharenrs = malloc(sizeof(*sharenrs) * aggregators);
      for (i = 0; i < aggregators; i++) {
        sharenrs[i] = i+1;
      }
      gfctx = gfshare_ctx_init_enc(sharenrs, aggregators, threshold);

      // Start timer
      start = clock();

      // Split or encrypt message 100 times
      for (i = 0; i < iterations; i++) {
        gfshare_ctx_enc_setsecret(gfctx, message);
        for (j = 0; j < aggregators; j++) {
          gfshare_ctx_enc_getshare(gfctx, j, gfshare);
        }
      }

      // Stop timer
      end = clock();

      printf("Threshold, %d out of %d: %d iterations, %ld us\n",
          threshold, aggregators, iterations, (end-start));

      gfshare_ctx_free(gfctx);
      free(sharenrs);
      break;

    case PAILLIER:
      // Initialize paillier
      fp = fopen(keypath, "r");
      pubkey_init(&pub);
      pubkey_fscan(fp, &pub);
      fclose(fp);

      // Start timer
      start = clock();

      // Split or encrypt message 100 times
      for (i = 0; i < iterations; i++) {
        enc = NULL;
        clen = 0;
        encrypt(&enc, &clen, message, &pub);
        free(enc);
      }

      // Stop timer
      end = clock();

      printf("Paillier: %d iterations, %ld us\n", iterations, (end-start));

      pubkey_clear(&pub);
      break;
  }
}
