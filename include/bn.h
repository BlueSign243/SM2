#ifndef BN_H
#define BN_H

#include "SM3.h"
#include <stdint.h>

#define WSIZE     64
#define BN_BITS   256
#define BN_DIGS   16
#define BN_SIZE   ((size_t)(2 * BN_DIGS + 2))
#define BN_LT     -1
#define BN_EQ     0
#define BN_GT     1
#define BN_POS    0
#define BN_NEG    1
#define DIG       (WSIZE)
#define DIG_LOG   6
#define RAND_DIST 40

#define bn_new(A) bn_make(A, BN_SIZE)

#define bn_new_size(A, D) bn_make(A, D)

#define MAX(A, B) ((A) > (B) ? (A) : (B))

#define MIN(A, B) ((A) < (B) ? (A) : (B))

#define MUL_DIG(H, L, A, B)                                                                                            \
    H = ((dbl_t)(A) * (dbl_t)(B)) >> DIG;                                                                              \
    L = (A) * (B);

#define COMBA_ADD(T, R2, R1, R0, A)                                                                                    \
    (T) = (R1);                                                                                                        \
    (R0) += (A);                                                                                                       \
    (R1) += (R0) < (A);                                                                                                \
    (R2) += (R1) < (T);

#define COMBA_STEP_MUL(R2, R1, R0, A, B)                                                                               \
    dig_t _r, _r0, _r1;                                                                                                \
    MUL_DIG(_r1, _r0, A, B);                                                                                           \
    COMBA_ADD(_r, R2, R1, R0, _r0);                                                                                    \
    (R1) += _r1;                                                                                                       \
    (R2) += (R1) < _r1;

#define MASK(B) ((-(dig_t)((B) >= WSIZE)) | (((dig_t)1 << ((B) % WSIZE)) - 1))

#define DIV_DIG(Q, R, H, L, D)                                                                                         \
    Q = (((dbl_t)(H) << DIG) | (L)) / (D);                                                                             \
    R = (((dbl_t)(H) << DIG) | (L)) - (dbl_t)(Q) * (dbl_t)(D);

typedef uint64_t dig_t;
typedef __uint128_t dbl_t;
typedef unsigned long uint_t;

typedef struct {
    size_t alloc;
    size_t used;
    int sign;
    dig_t dp[BN_SIZE];
} bn_st;

typedef bn_st bn_t[1];

/* utils */
void bn_make(bn_t a, size_t digits);

void bn_trim(bn_t a);

void bn_rand(bn_t a, int sign, size_t bits);

void bn_rand_mod(bn_t a, const bn_t m);

int bn_cmp_abs(const bn_t a, const bn_t b);

int bn_cmp_dig(const bn_t a, dig_t b);

int bn_cmp(const bn_t a, const bn_t b);

int bn_bit_len(const bn_t a);

int bn_get_one_bit(const bn_t a, int bit);

int bn_is_zero(const bn_t a);

void bn_zero(bn_t a);

void bn_set_dig(bn_t a, dig_t digit);

void bn_copy(bn_t c, const bn_t a);

void bn_abs(bn_t c, const bn_t a);

void bn_neg(bn_t c, const bn_t a);

void bn_from_digest(bn_t a, const uint8_t digest[SM3_DIGEST_SIZE]);

void bn_from_hex(bn_t a, const char *hex);

char *bn_to_hex(const bn_t a);

void bn_print(bn_t a);

/* operations */

/* c = a + b */
void bn_add(bn_t c, const bn_t a, const bn_t b);

/* c = a + (dig_t)b */
void bn_add_dig(bn_t c, const bn_t a, dig_t b);

/* c = a - b */
void bn_sub(bn_t c, const bn_t a, const bn_t b);

/* c = a * b */
void bn_mul(bn_t c, const bn_t a, const bn_t b);

/* c = a / b, d = a % b */
void bn_div(bn_t c, bn_t d, const bn_t a, const bn_t b);

/* c = a mod m */
void bn_mod(bn_t c, const bn_t a, const bn_t m);

/* c = a^-1 mod b */
void bn_mod_inv(bn_t c, const bn_t a, const bn_t b);

/* c = (a + b) mod m */
void bn_mod_add(bn_t c, const bn_t a, const bn_t b, const bn_t m);

/* c = (a - b) mod m */
void bn_mod_sub(bn_t c, const bn_t a, const bn_t b, const bn_t m);

/* c = a * b mod m */
void bn_mod_mul(bn_t c, const bn_t a, const bn_t b, const bn_t m);

#endif