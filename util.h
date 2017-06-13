#ifndef _UTIL_H
#define _UTIL_H 1

#include <gmp.h>


void get_rand(unsigned char *buffer, unsigned int count);
void bytes_to_mpz(mpz_t out, unsigned char *in, size_t size);
void mpz_to_bytes(unsigned char **out, size_t *size, mpz_t in);
void printf_hex(unsigned char *str, size_t len);
void sscanf_hex(unsigned char *out, char *in, size_t len);
unsigned int rand_r_uniform(unsigned int *seedp, unsigned int n);

#endif
