#include "bn.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

/* utils */
void bn_make(bn_t a, size_t digits) {
    if (digits > BN_SIZE || digits < 0)
        return;

    digits = BN_SIZE;
    if (a != NULL) {
        a->used = 1;
        a->alloc = digits;
        a->sign = BN_POS;
        memset(a->dp, 0, digits * sizeof(dig_t));
    }
}

void bn_trim(bn_t a) {
    if (a->used <= a->alloc) {
        while (a->used > 0 && a->dp[a->used - 1] == 0)
            --(a->used);

        if (a->used == 0) {
            a->used = 1;
            a->dp[0] = 0;
            a->sign = BN_POS;
        }
    }
}

void bn_rand(bn_t a, int sign, size_t bits) {
    HCRYPTPROV ctx;
    if (!CryptAcquireContext(&ctx, NULL, NULL, PROV_RSA_FULL, 0))
        abort();

    size_t word_size = (bits + WSIZE - 1) / WSIZE;
    size_t buffer_size = word_size * (WSIZE / 8);
    BYTE *buffer = (BYTE *)malloc(buffer_size);
    if (buffer == NULL)
        abort();

    if (!CryptGenRandom(ctx, buffer_size, buffer))
        abort();

    if (!CryptReleaseContext(ctx, 0))
        abort();

    for (size_t i = 0; i < word_size; i++) {
        a->dp[i] = 0;
        for (size_t j = 0; j < WSIZE / 8; j++)
            a->dp[i] |= (dig_t)buffer[i * (WSIZE / 8) + j] << (j * 8);
    }

    if (bits % WSIZE != 0) {
        dig_t mask = ((dig_t)1 << (bits % WSIZE)) - 1;
        a->dp[word_size - 1] &= mask;
    }

    a->used = word_size;
    a->sign = sign;
    bn_trim(a);
    free(buffer);
}

void bn_rand_mod(bn_t a, const bn_st *m) {
    bn_t t;
    bn_new(t);
    bn_copy(t, m);
    do {
        bn_rand(a, m->sign, bn_bit_len(t) + RAND_DIST);
        bn_mod(a, a, t);
    } while (bn_is_zero(a) || bn_cmp_abs(a, t) != BN_LT);
}

int dv_cmp(const dig_t *a, const dig_t *b, size_t size) {
    int r;

    a += (size - 1);
    b += (size - 1);

    r = BN_EQ;
    for (size_t i = 0; i < size; i++, --a, --b)
        if (*a != *b && r == BN_EQ)
            r = (*a > *b ? BN_GT : BN_LT);

    return r;
}

void dv_rshd(dig_t *c, const dig_t *a, size_t size, uint_t digits) {
    const dig_t *top;
    dig_t *bot;
    size_t i;

    top = a + digits;
    bot = c;

    for (i = 0; i < size - digits; i++, top++, bot++)
        *bot = *top;

    for (; i < size; i++, bot++)
        *bot = 0;
}

void dv_lshd(dig_t *c, const dig_t *a, size_t size, uint_t digits) {
    dig_t *top;
    const dig_t *bot;
    size_t i;

    top = c + size - 1;
    bot = a + size - 1 - digits;

    for (i = 0; i < size - digits; i++, top--, bot--)
        *top = *bot;

    for (i = 0; i < digits; i++, c++)
        *c = 0;
}

static size_t util_bits_dig(dig_t a) {
    size_t bits = 0;
    dig_t t = a;
    while (t) {
        bits++;
        t >>= 1;
    }
    return bits;
}

int bn_cmp_abs(const bn_t a, const bn_t b) {
    if (bn_is_zero(a) && bn_is_zero(b))
        return BN_EQ;

    if (a->used > b->used)
        return BN_GT;

    if (a->used < b->used)
        return BN_LT;

    return dv_cmp(a->dp, b->dp, a->used);
}

int bn_cmp_dig(const bn_t a, dig_t b) {
    if (a->sign == BN_NEG)
        return BN_LT;

    if (a->used > 1)
        return BN_GT;

    if (a->dp[0] > b)
        return BN_GT;

    if (a->dp[0] < b)
        return BN_LT;

    return BN_EQ;
}

int bn_cmp(const bn_t a, const bn_t b) {
    if (bn_is_zero(a) && bn_is_zero(b))
        return BN_EQ;

    if (a->sign == BN_POS && b->sign == BN_NEG)
        return BN_GT;

    if (a->sign == BN_NEG && b->sign == BN_POS)
        return BN_LT;

    if (a->sign == BN_NEG)
        return bn_cmp_abs(b, a);

    return bn_cmp_abs(a, b);
}

int bn_bit_len(const bn_t a) {
    int bits = util_bits_dig(a->dp[a->used - 1]);
    return bits + (a->used - 1) * WSIZE;
}

int bn_get_one_bit(const bn_t a, int bit) {
    int bit_index = bit % WSIZE;
    int word_index = bit / WSIZE;
    return (a->dp[word_index] >> bit_index) & 1;
}

int bn_is_zero(const bn_t a) {
    if (a->used == 0)
        return 1;
    return (a->used == 1) && (a->dp[0] == 0);
}

void bn_zero(bn_t a) {
    a->used = 1;
    a->sign = BN_POS;
    for (int i = 0; i < a->alloc; i++)
        a->dp[i] = 0;
}

void bn_set_dig(bn_t a, dig_t digit) {
    bn_zero(a);
    a->dp[0] = digit;
    a->used = 1;
    a->sign = BN_POS;
}

void bn_copy(bn_t c, const bn_t a) {
    if (c->dp == a->dp)
        return;

    memcpy(c->dp, a->dp, a->used * sizeof(dig_t));
    c->used = a->used;
    c->sign = a->sign;
    bn_trim(c);
}

void bn_abs(bn_t c, const bn_t a) {
    if (c->dp != a->dp)
        bn_copy(c, a);

    c->sign = BN_POS;
}

void bn_neg(bn_t c, const bn_t a) {
    if (c->dp != a->dp)
        bn_copy(c, a);

    if (!bn_is_zero(c))
        c->sign = a->sign ^ 1;
}

void bn_from_digest(bn_t a, const uint8_t digest[SM3_DIGEST_SIZE]) {
    for (int i = 0; i < SM3_DIGEST_SIZE; i += 8) {
        a->dp[3 - i / 8] |= (dig_t)digest[i] << 56;
        a->dp[3 - i / 8] |= (dig_t)digest[i + 1] << 48;
        a->dp[3 - i / 8] |= (dig_t)digest[i + 2] << 40;
        a->dp[3 - i / 8] |= (dig_t)digest[i + 3] << 32;
        a->dp[3 - i / 8] |= (dig_t)digest[i + 4] << 24;
        a->dp[3 - i / 8] |= (dig_t)digest[i + 5] << 16;
        a->dp[3 - i / 8] |= (dig_t)digest[i + 6] << 8;
        a->dp[3 - i / 8] |= (dig_t)digest[i + 7];
    }
    a->used = 4;
}

void bn_from_hex(bn_t a, const char *hex) {
    bn_new(a);
    int len = strlen(hex);
    if (len == 0)
        return;

    if (hex[0] == '-') {
        a->sign = BN_NEG;
        len--;
    } else {
        a->sign = BN_POS;
    }

    int word_index = 0;
    int shift = 0;
    dig_t current_word = 0;

    for (int i = len - 1; i >= 0; i--) {
        char c = hex[i];
        int digit;
        if (c >= '0' && c <= '9')
            digit = c - '0';
        else if (c >= 'a' && c <= 'f')
            digit = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F')
            digit = c - 'A' + 10;
        else
            continue;

        current_word |= ((dig_t)digit << shift);
        shift += 4;
        if (shift == WSIZE) {
            a->dp[word_index++] = current_word;
            current_word = 0;
            shift = 0;
        }
    }

    if (current_word != 0 && word_index < BN_SIZE) {
        a->dp[word_index] = current_word;
        word_index++;
    }
    a->used = word_index;

    bn_trim(a);
}

char *bn_to_hex(const bn_t a) {
    if (bn_is_zero(a))
        return "0";

    char *hex = malloc((a->used * WSIZE / 8 + 1) * sizeof(char));
    int j = 0;
    for (int i = a->used - 1; i >= 0; i--)
        for (int shift = WSIZE - 8; shift >= 0; shift -= 8)
            hex[j++] = (a->dp[i] >> shift) & 0xFF;
    hex[j] = '\0';
    return hex;
}

void bn_print(bn_t a) {
    if (a->sign == BN_NEG)
        printf("-");

    for (int i = a->used - 1; i >= 0; i--)
        printf("%016llX ", a->dp[i]);

    printf("\n");
}

/* support functions */
dig_t bn_add1_low(dig_t *c, const dig_t *a, dig_t digit, size_t size) {
    size_t i;
    dig_t carry, r0;

    carry = digit;
    for (i = 0; i < size && carry; i++, a++, c++) {
        r0 = (*a) + carry;
        carry = (r0 < carry);
        (*c) = r0;
    }
    for (; i < size; i++, a++, c++) {
        (*c) = (*a);
    }
    return carry;
}

dig_t bn_addn_low(dig_t *c, const dig_t *a, const dig_t *b, size_t size) {
    dig_t carry, c0, c1, r0, r1;

    carry = 0;
    for (size_t i = 0; i < size; i++, a++, b++, c++) {
        r0 = (*a) + (*b);
        c0 = (r0 < (*a));
        r1 = r0 + carry;
        c1 = (r1 < r0);
        carry = c0 | c1;
        (*c) = r1;
    }
    return carry;
}

void bn_add_imp(bn_t c, const bn_t a, const bn_t b) {
    int max, min;
    dig_t carry;

    max = a->used;
    min = b->used;

    if (min == 0) {
        bn_copy(c, a);
        return;
    }

    if (a->used == b->used) {
        carry = bn_addn_low(c->dp, a->dp, b->dp, max);
    } else {
        carry = bn_addn_low(c->dp, a->dp, b->dp, min);
        carry = bn_add1_low(c->dp + min, a->dp + min, carry, max - min);
    }
    if (carry)
        c->dp[max] = carry;
    c->used = max + carry;
    bn_trim(c);
}

dig_t bn_sub1_low(dig_t *c, const dig_t *a, dig_t digit, size_t size) {
    size_t i;
    dig_t carry, r0;

    carry = digit;
    for (i = 0; i < size && carry; i++, c++, a++) {
        r0 = (*a) - carry;
        carry = (r0 > (*a));
        (*c) = r0;
    }
    for (; i < size; i++, a++, c++) {
        (*c) = (*a);
    }
    return carry;
}

dig_t bn_subn_low(dig_t *c, const dig_t *a, const dig_t *b, size_t size) {
    dig_t carry, r0, diff;

    carry = 0;
    for (size_t i = 0; i < size; i++, a++, b++, c++) {
        diff = (*a) - (*b);
        r0 = diff - carry;
        carry = ((*a) < (*b)) || (carry && !diff);
        (*c) = r0;
    }
    return carry;
}

void bn_sub_dig(bn_t c, const bn_t a, dig_t b) {
    dig_t carry;

    if (a->used > 1 || a->dp[0] >= b) {
        carry = bn_sub1_low(c->dp, a->dp, b, a->used);
        c->used = a->used;
    } else {
        /* If a > 0 && a < b. */
        if (a->used == 1) {
            c->dp[0] = b - a->dp[0];
        } else {
            c->dp[0] = b;
        }
        c->used = 1;
    }

    bn_trim(c);
}

void bn_sub_imp(bn_t c, const bn_t a, const bn_t b) {
    int max, min;
    dig_t carry;

    max = a->used;
    min = b->used;

    if (min == 0) {
        bn_copy(c, a);
        return;
    }

    if (a->used == b->used) {
        carry = bn_subn_low(c->dp, a->dp, b->dp, min);
    } else {
        carry = bn_subn_low(c->dp, a->dp, b->dp, min);
        carry = bn_sub1_low(c->dp + min, a->dp + min, carry, max - min);
    }
    c->used = max;
    bn_trim(c);
}

dig_t bn_mul1_low(dig_t *c, const dig_t *a, dig_t digit, size_t size) {
    dig_t r0, r1, carry = 0;
    for (int i = 0; i < size; i++, a++, c++) {
        MUL_DIG(r1, r0, *a, digit);
        *c = r0 + carry;
        carry = r1 + (*c < carry);
    }
    return carry;
}

void bn_muln_low(dig_t *c, const dig_t *a, const dig_t *b, size_t size) {
    int i, j;
    const dig_t *tmpa, *tmpb;
    dig_t r0, r1, r2;

    r0 = r1 = r2 = 0;
    for (i = 0; i < size; i++, c++) {
        tmpa = a;
        tmpb = b + i;
        for (j = 0; j <= i; j++, tmpa++, tmpb--) {
            COMBA_STEP_MUL(r2, r1, r0, *tmpa, *tmpb);
        }
        *c = r0;
        r0 = r1;
        r1 = r2;
        r2 = 0;
    }
    for (i = 0; i < size; i++, c++) {
        tmpa = a + i + 1;
        tmpb = b + (size - 1);
        for (j = 0; j < size - (i + 1); j++, tmpa++, tmpb--) {
            COMBA_STEP_MUL(r2, r1, r0, *tmpa, *tmpb);
        }
        *c = r0;
        r0 = r1;
        r1 = r2;
        r2 = 0;
    }
}

void bn_muld_low(dig_t *c, const dig_t *a, size_t sa, const dig_t *b, size_t sb, uint_t l, uint_t h) {
    int i, j, ta;
    const dig_t *tmpa, *tmpb;
    dig_t r0, r1, r2;

    c += l;

    r0 = r1 = r2 = 0;
    for (i = l; i < sb; i++, c++) {
        tmpa = a;
        tmpb = b + i;
        for (j = 0; j <= i; j++, tmpa++, tmpb--) {
            COMBA_STEP_MUL(r2, r1, r0, *tmpa, *tmpb);
        }
        *c = r0;
        r0 = r1;
        r1 = r2;
        r2 = 0;
    }
    ta = 0;
    for (i = sb; i < sa; i++, c++) {
        tmpa = a + ++ta;
        tmpb = b + (sb - 1);
        for (j = 0; j < sb; j++, tmpa++, tmpb--) {
            COMBA_STEP_MUL(r2, r1, r0, *tmpa, *tmpb);
        }
        *c = r0;
        r0 = r1;
        r1 = r2;
        r2 = 0;
    }
    for (i = sa; i < h; i++, c++) {
        tmpa = a + ++ta;
        tmpb = b + (sb - 1);
        for (j = 0; j < sa - ta; j++, tmpa++, tmpb--) {
            COMBA_STEP_MUL(r2, r1, r0, *tmpa, *tmpb);
        }
        *c = r0;
        r0 = r1;
        r1 = r2;
        r2 = 0;
    }
}

dig_t bn_lshb_low(dig_t *c, const dig_t *a, size_t size, uint_t bits) {
    int i;
    dig_t r, carry, shift, mask;

    shift = DIG - bits;
    carry = 0;
    mask = MASK(bits);
    for (i = 0; i < size; i++, a++, c++) {
        /* Get the needed least significant bits. */
        r = ((*a) >> shift) & mask;
        /* Shift left the operand. */
        *c = ((*a) << bits) | carry;
        /* Update the carry. */
        carry = r;
    }
    return carry;
}

dig_t bn_rshb_low(dig_t *c, const dig_t *a, size_t size, uint_t bits) {
    int i;
    dig_t r, carry, shift, mask;

    c += size - 1;
    a += size - 1;
    /* Prepare the bit mask. */
    shift = (DIG - bits) % DIG;
    carry = 0;
    mask = MASK(bits);
    for (i = size - 1; i >= 0; i--, a--, c--) {
        /* Get the needed least significant bits. */
        r = (*a) & mask;
        /* Shift left the operand. */
        *c = ((*a) >> bits) | (carry << shift);
        /* Update the carry. */
        carry = r;
    }
    return carry;
}

void bn_divn_low(dig_t *c, dig_t *d, dig_t *a, size_t sa, dig_t *b, size_t sb) {
    int norm, i, n, t, sd;
    dig_t carry, t1[3], t2[3];

    /* Normalize x and y so that the leading digit of y is bigger than
     * 2^(RLC_DIG-1). */
    norm = util_bits_dig(b[sb - 1]) % DIG;

    if (norm < (int)(DIG - 1)) {
        norm = (DIG - 1) - norm;
        carry = bn_lshb_low(a, a, sa, norm);
        if (carry) {
            a[sa++] = carry;
        }
        carry = bn_lshb_low(b, b, sb, norm);
        if (carry) {
            b[sb++] = carry;
        }
    } else {
        norm = 0;
    }

    n = sa - 1;
    t = sb - 1;

    /* Shift y so that the most significant digit of y is aligned with the
     * most significant digit of x. */
    dv_lshd(b, b, sb + (n - t), (n - t));

    /* Find the most significant digit of the quotient. */
    while (dv_cmp(a, b, sa) != BN_LT) {
        c[n - t]++;
        bn_subn_low(a, a, b, sa);
    }

    /* Shift y back. */
    dv_rshd(b, b, sb + (n - t), (n - t));

    /* Find the remaining digits. */
    for (i = n; i >= (t + 1); i--) {
        if (i > sa) {
            continue;
        }

        if (a[i] == b[t]) {
            c[i - t - 1] = MASK(DIG);
        } else {
            DIV_DIG(c[i - t - 1], carry, a[i], a[i - 1], b[t]);
        }

        c[i - t - 1]++;
        do {
            c[i - t - 1]--;
            t1[0] = (t - 1 < 0) ? 0 : b[t - 1];
            t1[1] = b[t];

            carry = bn_mul1_low(t1, t1, c[i - t - 1], 2);
            t1[2] = carry;

            t2[0] = (i - 2 < 0) ? 0 : a[i - 2];
            t2[1] = (i - 1 < 0) ? 0 : a[i - 1];
            t2[2] = a[i];
        } while (dv_cmp(t1, t2, 3) == BN_GT);

        carry = bn_mul1_low(d, b, c[i - t - 1], sb);
        sd = sb;
        if (carry) {
            d[sd++] = carry;
        }

        carry = bn_subn_low(a + (i - t - 1), a + (i - t - 1), d, sd);
        sd += (i - t - 1);
        if (sa > sd) {
            carry = bn_sub1_low(a + sd, a + sd, carry, sa - sd);
        }

        if (carry) {
            sd = sb + (i - t - 1);
            carry = bn_addn_low(a + (i - t - 1), a + (i - t - 1), b, sb);
            carry = bn_add1_low(a + sd, a + sd, carry, sa - sd);
            c[i - t - 1]--;
        }
    }
    /* Remainder should be not be longer than the divisor. */
    bn_rshb_low(d, a, sb, norm);
}

void bn_div_imp(bn_t c, bn_t d, const bn_t a, const bn_t b) {
    bn_t q, x, y, r;
    int sign;

    /* If |a| < |b|, we're done. */
    if (bn_cmp_abs(a, b) == BN_LT) {
        if (a->sign == b->sign) {
            if (c != NULL) {
                bn_zero(c);
            }
            if (d != NULL) {
                bn_copy(d, a);
            }
        } else {
            if (c != NULL) {
                bn_set_dig(c, 1);
                bn_neg(c, c);
            }
            if (d != NULL) {
                bn_add(d, a, b);
            }
        }
        return;
    }

    /* Be conservative about space for scratch memory, many attempts to
     * optimize these had invalid reads. */
    bn_new_size(x, a->used + 1);
    bn_new_size(q, a->used + 1);
    bn_new_size(y, a->used + 1);
    bn_new_size(r, a->used + 1);
    bn_zero(q);
    bn_zero(r);
    bn_abs(x, a);
    bn_abs(y, b);

    /* Find the sign. */
    sign = (a->sign == b->sign ? BN_POS : BN_NEG);

    bn_divn_low(q->dp, r->dp, x->dp, a->used, y->dp, b->used);

    q->used = a->used - b->used + 1;
    q->sign = sign;
    bn_trim(q);

    r->used = b->used;
    r->sign = b->sign;
    bn_trim(r);

    /* We have the quotient in q and the remainder in r. */
    if (c != NULL) {
        if ((bn_is_zero(r)) || (a->sign == b->sign)) {
            bn_copy(c, q);
        } else {
            bn_sub_dig(c, q, 1);
        }
    }

    if (d != NULL) {
        if ((bn_is_zero(r)) || (a->sign == b->sign)) {
            bn_copy(d, r);
        } else {
            bn_sub(d, b, r);
        }
    }
}

void bn_gcd_ext(bn_t c, bn_t d, bn_t e, const bn_t a, const bn_t b) {
    bn_t u, v, x_1, y_1, q, r;

    if (bn_is_zero(a)) {
        bn_abs(c, b);
        bn_zero(d);
        if (e != NULL)
            bn_set_dig(e, 1);
        return;
    }

    if (bn_is_zero(b)) {
        bn_abs(c, a);
        bn_set_dig(d, 1);
        if (e != NULL)
            bn_zero(e);
        return;
    }

    bn_new(u);
    bn_new(v);
    bn_new(x_1);
    bn_new(y_1);
    bn_new(q);
    bn_new(r);

    bn_abs(u, a);
    bn_abs(v, b);

    bn_zero(x_1);
    bn_set_dig(y_1, 1);
    bn_set_dig(d, 1);
    if (e != NULL)
        bn_zero(e);

    while (!bn_is_zero(v)) {
        bn_div(q, r, u, v);

        bn_copy(u, v);
        bn_copy(v, r);

        bn_mul(c, q, x_1);
        bn_sub(r, d, c);
        bn_copy(d, x_1);
        bn_copy(x_1, r);

        if (e != NULL) {
            bn_mul(c, q, y_1);
            bn_sub(r, e, c);
            bn_copy(e, y_1);
            bn_copy(y_1, r);
        }
    }
    bn_copy(c, u);
}

/* operation functions */
void bn_add(bn_t c, const bn_t a, const bn_t b) {
    int sa, sb;

    sa = a->sign;
    sb = b->sign;

    if (sa == sb) {
        /* If the signs are equal, copy the sign and add. */
        c->sign = sa;
        if (bn_cmp_abs(a, b) == BN_LT) {
            bn_add_imp(c, b, a);
        } else {
            bn_add_imp(c, a, b);
        }
    } else {
        /* If the signs are different, subtract. */
        if (bn_cmp_abs(a, b) == BN_LT) {
            bn_sub_imp(c, b, a);
            c->sign = sb;
        } else {
            bn_sub_imp(c, a, b);
            c->sign = sa;
        }
    }
}

void bn_add_dig(bn_t c, const bn_t a, dig_t b) {
    dig_t carry;

    if (a->sign == BN_POS) {
        carry = bn_add1_low(c->dp, a->dp, b, a->used);
        if (carry) {
            c->dp[a->used] = carry;
        }
        c->used = a->used + carry;
        c->sign = BN_POS;
    } else {
        /* If a < 0 && |a| >= b, compute c = -(|a| - b). */
        if (a->used > 1 || a->dp[0] >= b) {
            carry = bn_sub1_low(c->dp, a->dp, b, a->used);
            c->used = a->used;
            c->sign = BN_NEG;
        } else {
            /* If a < 0 && |a| < b. */
            if (a->used == 1) {
                c->dp[0] = b - a->dp[0];
            } else {
                c->dp[0] = b;
            }
            c->used = 1;
            c->sign = BN_POS;
        }
    }
    bn_trim(c);
}

void bn_sub(bn_t c, const bn_t a, const bn_t b) {
    int sa, sb;

    sa = a->sign;
    sb = b->sign;

    if (sa != sb) {
        /* If the signs are different, copy the sign of the first number and
         * add. */
        c->sign = sa;
        if (bn_cmp_abs(a, b) == BN_LT) {
            bn_add_imp(c, b, a);
        } else {
            bn_add_imp(c, a, b);
        }
    } else {
        /* If the signs are equal, adjust the sign and subtract. */
        if (bn_cmp_abs(a, b) != BN_LT) {
            bn_sub_imp(c, a, b);
            c->sign = sa;
        } else {
            bn_sub_imp(c, b, a);
            c->sign = (sa == BN_POS) ? BN_NEG : BN_POS;
        }
    }
}

void bn_mul(bn_t c, const bn_t a, const bn_t b) {
    bn_t t;
    bn_new(t);

    bn_new_size(t, a->used + b->used);
    t->used = a->used + b->used;
    if (a->used == b->used) {
        bn_muln_low(t->dp, a->dp, b->dp, a->used);
    } else {
        if (a->used > b->used) {
            bn_muld_low(t->dp, a->dp, a->used, b->dp, b->used, 0, t->used);
        } else {
            bn_muld_low(t->dp, b->dp, b->used, a->dp, a->used, 0, t->used);
        }
    }

    t->sign = a->sign ^ b->sign;
    bn_trim(t);
    bn_copy(c, t);
}

void bn_div(bn_t c, bn_t d, const bn_t a, const bn_t b) {
    if (bn_is_zero(b))
        return;
    bn_div_imp(c, d, a, b);
}

void bn_mod(bn_t c, const bn_t a, const bn_t m) {
    bn_div(NULL, c, a, m);
}

void bn_mod_inv(bn_t c, const bn_t a, const bn_t b) {
    bn_t t, u;

    bn_new(t);
    bn_new(u);

    bn_mod(t, a, b);
    bn_copy(u, b);
    bn_gcd_ext(t, c, NULL, t, b);

    if (c->sign == BN_NEG)
        bn_add(c, c, u);

    if (bn_cmp_dig(t, 1) != BN_EQ)
        return;
}

void bn_mod_add(bn_t c, const bn_t a, const bn_t b, const bn_t m) {
    bn_add(c, a, b);
    if (bn_cmp(c, m) == BN_GT)
        bn_mod(c, c, m);
}

void bn_mod_sub(bn_t c, const bn_t a, const bn_t b, const bn_t m) {
    bn_sub(c, a, b);
    while (c->sign == BN_NEG)
        bn_add(c, c, m);
}

void bn_mod_mul(bn_t c, const bn_t a, const bn_t b, const bn_t m) {
    bn_mul(c, a, b);
    bn_mod(c, c, m);
}
