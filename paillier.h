#ifndef _PAILLIER_H
#define _PAILLIER_H 1

#include <gmp.h>
#include <stdint.h>
#include <stdio.h>


typedef struct {
  mpz_t n;
  mpz_t n2;
  mpz_t g;
} pubkey;

typedef struct {
  mpz_t l;
  mpz_t m;
  pubkey pub;
} seckey;

void keygen(seckey *sec, int keysize);
void encrypt(unsigned char **cbytes, size_t *clen,
    uint32_t mint, pubkey *key);
uint32_t decrypt(unsigned char *c, size_t clen, seckey *sec);

void paillier_add(
    unsigned char **sumbytes, size_t *sumlen,
    unsigned char *c1bytes, size_t c1len,
    unsigned char *c2bytes, size_t c2len,
    pubkey *key);

void seckey_init(seckey *sec);
void pubkey_init(pubkey *pub);
void seckey_clear(seckey *sec);
void pubkey_clear(pubkey *pub);
void seckey_fprint(FILE *fp, seckey *sec);
void pubkey_fprint(FILE *fp, pubkey *pub);
void seckey_fscan(FILE *fp, seckey *sec);
void pubkey_fscan(FILE *fp, pubkey *pub);

#endif
