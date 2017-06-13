#include <stdio.h>
#include <stdlib.h>

#include "util.h"

void get_rand(unsigned char *buffer, unsigned int count) {
  size_t n;
  static FILE *devrandom = NULL;

  if (devrandom == NULL) {
    devrandom = fopen("/dev/urandom", "rb");
  }
  if (!devrandom) {
    perror("Unable to read /dev/urandom");
    exit(1);
  }
  n = fread(buffer, 1, count, devrandom);
  if (n < count) {
    perror("Short read from /dev/urandom");
    exit(1);
  }
}

void bytes_to_mpz(mpz_t out, unsigned char *in, size_t size) {
  mpz_import(out, size, -1, 1, 0, 0, in);
}

void mpz_to_bytes(unsigned char **out, size_t *size, mpz_t in) {
  size_t written;

  *out = mpz_export(*out, &written, -1, 1, 0, 0, in);

  if (size != NULL) {
    if (*size != 0) {
      for (; written < *size; written++) {
        (*out)[written] = '\0';
      }
    }
    *size = written;
  }
}

void printf_hex(unsigned char *str, size_t len) {
  int i;

  for (i = 0; i < len; i++) {
    printf("%02X", str[i]);
  }
}

void sscanf_hex(unsigned char *out, char *in, size_t len) {
  int i;

  for (i = 0; i < len; i++) {
    sscanf(&in[2*i], "%02hhx", &out[i]);
  }
}

unsigned int rand_r_uniform(unsigned int *seedp, unsigned int n) {
  int val;
  static unsigned int max;
  static unsigned int lastn = 0;

  // Memoize the last value for max computed
  if (n != lastn) {
    max = RAND_MAX/n;
    max *= n;
    lastn = n;
  }

  do {
    val = rand_r(seedp);
  } while (val >= max);

  return val % n;
}
