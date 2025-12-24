#include "SM2.h"
#include "SM3.h"
#include "bn.h"
#include "ec.h"
#include "point.h"
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

int SM2_Init(SM2_CTX *ctx) {
    bn_new(ctx->keypair.private_key);
    point_new(&ctx->keypair.public_key);
    create_group(&ctx->curve, SM2_CURVE_PARAM_P, SM2_CURVE_PARAM_A, SM2_CURVE_PARAM_B, SM2_CURVE_PARAM_GX,
                 SM2_CURVE_PARAM_GY, SM2_CURVE_PARAM_N);
    return SM2_SUCCESS;
}

int SM2_GenerateKeyPair(SM2_CTX *ctx) {
    if (ctx == NULL)
        return SM2_NULL_PTR;
    bn_rand_mod(ctx->keypair.private_key, ctx->curve.n);
    point_mul(&ctx->keypair.public_key, &ctx->curve.g, ctx->keypair.private_key, ctx->curve.p, ctx->curve.a);
    return SM2_SUCCESS;
}

void compute_z(uint8_t z[SM3_DIGEST_SIZE], SM2_CTX *ctx, const uint8_t *id, const size_t entl) {
    SM3_CTX sm3_ctx;
    SM3_Init(&sm3_ctx);
    uint8_t entl_hex[2];
    size_t len = entl * 8;
    entl_hex[0] = (uint8_t)((len >> 8) & 0xFF);
    entl_hex[1] = (uint8_t)(len & 0xFF);
    // z = H(entl)
    SM3_Update(&sm3_ctx, entl_hex, 2);
    // z = H(entl || id)
    SM3_Update(&sm3_ctx, id, entl);
    // z = H(entl || id || a)
    SM3_Update(&sm3_ctx, (uint8_t *)bn_to_hex(ctx->curve.a), strlen(bn_to_hex(ctx->curve.a)));
    // z = H(entl || id || a || b)
    SM3_Update(&sm3_ctx, (uint8_t *)bn_to_hex(ctx->curve.b), strlen(bn_to_hex(ctx->curve.b)));
    // z = H(entl || id || a || b || xg)
    SM3_Update(&sm3_ctx, (uint8_t *)bn_to_hex(ctx->curve.g.x), strlen(bn_to_hex(ctx->curve.g.x)));
    // z = H(entl || id || a || b || xg || yg)
    SM3_Update(&sm3_ctx, (uint8_t *)bn_to_hex(ctx->curve.g.y), strlen(bn_to_hex(ctx->curve.g.y)));
    // z = H(entl || id || a || b || xg || yg || xa)
    SM3_Update(&sm3_ctx, (uint8_t *)bn_to_hex(ctx->keypair.public_key.x), strlen(bn_to_hex(ctx->keypair.public_key.x)));
    // z = H(entl || id || a || b || xg || yg || xa || ya)
    SM3_Update(&sm3_ctx, (uint8_t *)bn_to_hex(ctx->keypair.public_key.y), strlen(bn_to_hex(ctx->keypair.public_key.y)));
    SM3_Final(&sm3_ctx, z);
}

void compute_e(uint8_t e[SM3_DIGEST_SIZE], const uint8_t z[SM3_DIGEST_SIZE], const uint8_t *msg, size_t mlen) {
    SM3_CTX sm3_ctx;
    SM3_Init(&sm3_ctx);
    SM3_Update(&sm3_ctx, z, SM3_DIGEST_SIZE);
    SM3_Update(&sm3_ctx, msg, mlen);
    SM3_Final(&sm3_ctx, e);
}

int SM2_Sign(SM2_CTX *ctx, const uint8_t *msg, size_t mlen, uint8_t *id, size_t entl, SM2_SIG *sig) {
    if (ctx == NULL || sig == NULL)
        return SM2_NULL_PTR;

    // step 1: compute z
    uint8_t z[SM3_DIGEST_SIZE];
    compute_z(z, ctx, id, entl);

    // step 2: compute e
    uint8_t e_hex[SM3_DIGEST_SIZE];
    compute_e(e_hex, z, msg, mlen);
    bn_t e;
    bn_new(e);
    bn_from_digest(e, e_hex);

    bn_t k, r, s, t0, t1, t2, temp;
    point Q;
    int retry;

    do {
        retry = 0;
        bn_new(k);
        bn_new(r);
        bn_new(s);
        bn_new(t0);
        bn_new(t1);
        bn_new(t2);
        bn_new(temp);

        // step 3: generate k
        bn_rand_mod(k, ctx->curve.n);

        // step 4: compute Q = kG
        point_mul(&Q, &ctx->curve.g, k, ctx->curve.p, ctx->curve.a);

        // step 5: compute r = (e + x1) mod n
        bn_mod_add(r, Q.x, e, ctx->curve.n);

        // temp = r + k mod n
        bn_mod_add(temp, r, k, ctx->curve.n);

        // if r = 0 or r + k = n, return to step 3
        if (bn_is_zero(r) || bn_is_zero(temp)) {
            retry = 1;
            continue;
        }

        // t0 = (1 + da)^-1 mod n
        bn_add_dig(t0, ctx->keypair.private_key, 1);
        bn_mod_inv(t0, t0, ctx->curve.n);
        // t1 = r * da mod n
        bn_mod_mul(t1, r, ctx->keypair.private_key, ctx->curve.n);
        // t2 = (k - r * da) mod n
        bn_mod_sub(t2, k, t1, ctx->curve.n);
        // step 6: compute s = (k - r * da) * (1 + da)^-1 mod n
        bn_mod_mul(s, t0, t2, ctx->curve.n);

        // if s = 0, return to step 3
        if (bn_is_zero(s)) {
            retry = 1;
            continue;
        }

    } while (retry);

    // step 7: output (r, s)
    bn_copy(sig->r, r);
    bn_copy(sig->s, s);

    return SM2_SUCCESS;
}

int SM2_Verify(SM2_CTX *ctx, const uint8_t *msg, size_t mlen, uint8_t *id, size_t entl, const SM2_SIG *sig) {
    if (ctx == NULL || sig == NULL)
        return SM2_NULL_PTR;

    bn_t r, s, t, R;
    bn_new(r);
    bn_new(s);
    bn_new(t);
    bn_new(R);

    point P, Q;
    point_new(&P);
    point_new(&Q);

    bn_copy(r, sig->r);
    bn_copy(s, sig->s);

    // step 1: check r
    if (bn_cmp_dig(r, 1) == BN_LT || bn_cmp(r, ctx->curve.n) != BN_LT)
        return SM2_INVALID_SIG;

    // step 2: check s
    if (bn_cmp_dig(s, 1) == BN_LT || bn_cmp(s, ctx->curve.n) != BN_LT)
        return SM2_INVALID_SIG;

    // step 3: compute z
    uint8_t z[SM3_DIGEST_SIZE];
    compute_z(z, ctx, id, entl);

    // step 4: compute e
    uint8_t e_hex[SM3_DIGEST_SIZE];
    compute_e(e_hex, z, msg, mlen);
    bn_t e;
    bn_new(e);
    bn_from_digest(e, e_hex);

    // step 5: compute t = (r + s) mod n
    bn_mod_add(t, r, s, ctx->curve.n);
    if (bn_is_zero(t))
        return SM2_INVALID_SIG;

    // step 6: compute Q = sG + tPa
    point_mul(&Q, &ctx->curve.g, s, ctx->curve.p, ctx->curve.a);
    point_mul(&P, &ctx->keypair.public_key, t, ctx->curve.p, ctx->curve.a);
    point_add(&Q, &Q, &P, ctx->curve.p, ctx->curve.a);

    // step 7: compute R = e + x1 mod n
    bn_mod_add(R, e, Q.x, ctx->curve.n);
    if (bn_cmp(R, r) != BN_EQ)
        return SM2_INVALID_SIG;

    return SM2_SUCCESS;
}
