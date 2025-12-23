#include "bn.h"
#include <stdint.h>
#include <stdio.h>

int add() {
    bn_t a, b, c, d;
    bn_new(a);
    bn_new(b);
    bn_new(c);
    bn_new(d);

    // a + b = b + a
    for (int i = 0; i < 100; i++) {
        bn_rand(a, BN_POS, BN_BITS);
        bn_rand(b, BN_POS, BN_BITS);
        bn_add(c, a, b);
        bn_add(d, b, a);
        if (bn_cmp(c, d) != BN_EQ) {
            printf("a + b = b + a failed.\n");
            return 1;
        }
    }

    // a + 0 = a
    for (int i = 0; i < 100; i++) {
        bn_rand(a, BN_POS, BN_BITS);
        bn_zero(b);
        bn_add(c, a, b);
        if (bn_cmp(c, a) != BN_EQ) {
            printf("a + 0 = a failed.\n");
            return 1;
        }
    }

    return 0;
}

int sub() {
    bn_t a, b, c, d;
    bn_new(a);
    bn_new(b);
    bn_new(c);
    bn_new(d);

    // a - b = -(b - a)
    for (int i = 0; i < 100; i++) {
        bn_rand(a, BN_POS, BN_BITS);
        bn_rand(b, BN_POS, BN_BITS);
        bn_sub(c, a, b);
        bn_sub(d, b, a);
        if (bn_cmp_abs(c, d) != BN_EQ) {
            printf("a - b = -(b - a) failed.\n");
            return 1;
        }
    }

    // a - 0 = a
    for (int i = 0; i < 100; i++) {
        bn_rand(a, BN_POS, BN_BITS);
        bn_zero(b);
        bn_sub(c, a, b);
        if (bn_cmp(c, a) != BN_EQ) {
            printf("a - 0 = a failed.\n");
            return 1;
        }
    }

    return 0;
}

int mul() {
    bn_t a, b, c, d, e, f;
    bn_new(a);
    bn_new(b);
    bn_new(c);
    bn_new(d);
    bn_new(e);
    bn_new(f);

    // a * b = b * a
    for (int i = 0; i < 100; i++) {
        bn_rand(a, BN_POS, BN_BITS);
        bn_rand(b, BN_POS, BN_BITS);
        bn_mul(c, a, b);
        bn_mul(d, b, a);
        if (bn_cmp(c, d) != BN_EQ) {
            printf("a * b = b * a failed.\n");
            return 1;
        }
    }

    // a * 0 = 0
    for (int i = 0; i < 100; i++) {
        bn_rand(a, BN_POS, BN_BITS);
        bn_zero(b);
        bn_mul(c, a, b);
        if (!bn_is_zero(c)) {
            printf("a * 0 = 0 failed.\n");
            return 1;
        }
    }

    // a * 1 = a
    for (int i = 0; i < 100; i++) {
        bn_rand(a, BN_POS, BN_BITS);
        bn_set_dig(b, 1);
        bn_mul(c, a, b);
        if (bn_cmp(c, a) != BN_EQ) {
            printf("a * 1 = a failed.\n");
            return 1;
        }
    }

    // a * (b + c) = a * b + a * c
    for (int i = 0; i < 100; i++) {
        bn_rand(a, BN_POS, BN_BITS);
        bn_rand(b, BN_POS, BN_BITS);
        bn_rand(c, BN_POS, BN_BITS);
        bn_add(d, b, c);
        bn_mul(d, a, d);
        bn_mul(e, a, b);
        bn_mul(f, a, c);
        bn_add(e, e, f);
        if (bn_cmp(d, e) != BN_EQ) {
            printf("a * (b + c) = a * b + a * c failed.\n");
            return 1;
        }
    }

    return 0;
}

int div() {
    bn_t a, b, c, q, r;
    bn_new(a);
    bn_new(b);
    bn_new(c);
    bn_new(q);
    bn_new(r);

    // a = q * b + r
    for (int i = 0; i < 100; i++) {
        bn_rand(a, BN_POS, BN_BITS * 2);
        bn_rand(b, BN_POS, BN_BITS);
        bn_div(q, r, a, b);
        bn_mul(c, q, b);
        bn_add(c, c, r);
        if (bn_cmp(c, a) != BN_EQ) {
            printf("a = q * b + r failed.\n");
            return 1;
        }
    }

    return 0;
}

int main() {
    if (add() == 0)
        printf("Add test passed.\n");
    else
        printf("Add test failed.\n");

    if (sub() == 0)
        printf("Subtract test passed.\n");
    else
        printf("Subtract test failed.\n");

    if (mul() == 0)
        printf("Multiply test passed.\n");
    else
        printf("Multiply test failed.\n");

    if (div() == 0)
        printf("Divide test passed.\n");
    else
        printf("Divide test failed.\n");

    printf("Test done.\n");
    return 0;
}
