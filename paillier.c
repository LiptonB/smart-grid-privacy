#include <stdio.h>
#include <gmp.h>

#include "util.h"
#include "paillier.h"

void L(mpz_t l, mpz_t x, mpz_t n) {
  mpz_sub_ui(l, x, 1);
  mpz_fdiv_q(l, l, n);
}

void keygen(seckey *sec, int keysize) {
  mpz_t p;
  mpz_t q;
  gmp_randstate_t randstate;
  unsigned long int seed;

  get_rand((unsigned char *)&seed, sizeof(seed));
  gmp_randinit_default(randstate);
  gmp_randseed_ui(randstate, seed);
  mpz_inits(p, q, NULL);

  mpz_urandomb(p, randstate, keysize/2);
  mpz_nextprime(p, p);
  mpz_urandomb(q, randstate, keysize/2);
  mpz_nextprime(q, q);

  mpz_mul(sec->pub.n, p, q);
  mpz_mul(sec->pub.n2, sec->pub.n, sec->pub.n);

  mpz_sub_ui(p, p, 1);
  mpz_sub_ui(q, q, 1);
  // p and q now hold (p-1) and (q-1)
  mpz_lcm(sec->l, p, q);

  mpz_add_ui(sec->pub.g, sec->pub.n, 1);

  mpz_invert(sec->m, sec->l, sec->pub.n);

  mpz_clears(p, q, NULL);
  gmp_randclear(randstate);
}

void encrypt(unsigned char **cbytes, size_t *clen,
    uint32_t mint, pubkey *key) {
  mpz_t term1, term2, r, c, m;
  gmp_randstate_t randstate;
  unsigned long int seed;

  get_rand((unsigned char *)&seed, sizeof(seed));
  gmp_randinit_default(randstate);
  gmp_randseed_ui(randstate, seed);
  mpz_inits(term1, term2, r, c, NULL);

  mpz_init_set_ui(m, mint);

  mpz_urandomm(r, randstate, key->n);

  mpz_powm(term1, key->g, m, key->n2);
  mpz_powm(term2, r, key->n, key->n2);
  mpz_mul(c, term1, term2);
  mpz_mod(c, c, key->n2);

  mpz_to_bytes(cbytes, clen, c);

  mpz_clears(term1, term2, r, c, m, NULL);
  gmp_randclear(randstate);
}

uint32_t decrypt(unsigned char *cbytes, size_t clen, seckey *sec) {
  mpz_t temp, m, c;
  uint32_t mint;

  mpz_inits(temp, m, c, NULL);

  bytes_to_mpz(c, cbytes, clen);

  mpz_powm(temp, c, sec->l, sec->pub.n2);
  L(temp, temp, sec->pub.n);

  mpz_mul(temp, temp, sec->m);
  mpz_mod(m, temp, sec->pub.n);

  mint = mpz_get_ui(m);

  mpz_clears(temp, m, c, NULL);

  return mint;
}

void paillier_add(
    unsigned char **sumbytes, size_t *sumlen,
    unsigned char *c1bytes, size_t c1len,
    unsigned char *c2bytes, size_t c2len,
    pubkey *key) {
  mpz_t sum, c1, c2;
  mpz_inits(sum, c1, c2, NULL);
  bytes_to_mpz(c1, c1bytes, c1len);
  bytes_to_mpz(c2, c2bytes, c2len);

  mpz_mul(sum, c1, c2);
  mpz_mod(sum, sum, key->n2);

  mpz_to_bytes(sumbytes, sumlen, sum);
  mpz_clears(sum, c1, c2, NULL);
}

void pubkey_init(pubkey *pub) {
  mpz_inits(pub->n, pub->n2, pub->g, NULL);
}

void seckey_init(seckey *sec) {
  mpz_inits(sec->l, sec->m, NULL);
  pubkey_init(&sec->pub);
}

void pubkey_clear(pubkey *pub) {
  mpz_clears(pub->n, pub->n2, pub->g, NULL);
}

void seckey_clear(seckey *sec) {
  mpz_clears(sec->l, sec->m, NULL);
  pubkey_clear(&sec->pub);
}

void pubkey_fprint(FILE *fp, pubkey *pub) {
  gmp_fprintf(fp, "%ZX\n%ZX\n%ZX\n", pub->n, pub->n2, pub->g);
}

void seckey_fprint(FILE *fp, seckey *sec) {
  pubkey_fprint(fp, &sec->pub);
  gmp_fprintf(fp, "%ZX\n%ZX\n", sec->l, sec->m);
}

void pubkey_fscan(FILE *fp, pubkey *pub) {
  gmp_fscanf(fp, "%ZX\n%ZX\n%ZX\n", pub->n, pub->n2, pub->g);
}

void seckey_fscan(FILE *fp, seckey *sec) {
  pubkey_fscan(fp, &sec->pub);
  gmp_fscanf(fp, "%ZX\n%ZX\n", sec->l, sec->m);
}
