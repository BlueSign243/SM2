#include "point.h"
#include "bn.h"

void point_new(point *p) {
    bn_new(p->x);
    bn_new(p->y);
}

int point_equals(const point *a, const point *b) {
    if (point_is_infty(a) && point_is_infty(b))
        return 1;

    if (!point_is_infty(a) && point_is_infty(b))
        return 0;

    if (point_is_infty(a) && !point_is_infty(b))
        return 0;

    return bn_cmp(a->x, b->x) == BN_EQ && bn_cmp(a->y, b->y) == BN_EQ;
}

int point_is_infty(const point *a) {
    return bn_is_zero(a->x) && bn_is_zero(a->y);
}

void point_add(point *c, const point *g, const point *b, const bn_t p, const bn_t a) {
    // 处理无穷远点的情况
    if (point_is_infty(g)) {
        bn_copy(c->x, b->x);
        bn_copy(c->y, b->y);
        return;
    }
    if (point_is_infty(b)) {
        bn_copy(c->x, g->x);
        bn_copy(c->y, g->y);
        return;
    }

    // 检查是否为同一点（需要点倍运算）
    if (point_equals(g, b)) {
        point_dbl(c, g, p, a);
        return;
    }

    // 检查x坐标是否相等（结果为无穷远点）
    if (bn_cmp(g->x, b->x) == BN_EQ) {
        point_new(c);
        return;
    }

    bn_t t0, t1, t2, x3, y3;

    bn_new(t0);
    bn_new(t1);
    bn_new(t2);
    bn_new(x3);
    bn_new(y3);

    // t0 = x2 - x1
    bn_mod_sub(t0, b->x, g->x, p);
    // t1 = y2 - y1
    bn_mod_sub(t1, b->y, g->y, p);
    // t2 = 1/(x2 - x1)
    bn_mod_inv(t2, t0, p);
    // t2 = lambda = (y2 - y1) / (x2 - x1)
    bn_mod_mul(t2, t1, t2, p);

    // x3 = lambda^2 - x1 - x2
    bn_mod_mul(x3, t2, t2, p);
    bn_mod_sub(x3, x3, g->x, p);
    bn_mod_sub(x3, x3, b->x, p);

    // y3 = lambda(x1 - x3) - y1
    bn_mod_sub(y3, g->x, x3, p);
    bn_mod_mul(y3, y3, t2, p);
    bn_mod_sub(y3, y3, g->y, p);

    bn_copy(c->x, x3);
    bn_copy(c->y, y3);
}

void point_dbl(point *c, const point *g, const bn_t p, const bn_t a) {
    // 处理无穷远点的情况
    if (point_is_infty(g)) {
        point_new(c);
        return;
    }

    // 检查y坐标是否为0（结果为无穷远点）
    if (bn_is_zero(g->y)) {
        point_new(c);
        return;
    }

    bn_t t0, t1, t2, t3, x3, y3;

    bn_new(t0);
    bn_new(t1);
    bn_new(t2);
    bn_new(t3);
    bn_new(x3);
    bn_new(y3);

    // t0 = x1^2
    bn_mod_mul(t0, g->x, g->x, p);
    // t1 = 3x1^2 + a
    bn_mod_add(t1, t0, t0, p);
    bn_mod_add(t1, t1, t0, p);
    bn_mod_add(t1, t1, a, p);
    // t2 = 2y1
    bn_mod_add(t2, g->y, g->y, p);
    // t3 = 1 / 2y1
    bn_mod_inv(t3, t2, p);
    // t3 = lambda = (3x1^2 + a) / 2y1
    bn_mod_mul(t3, t1, t3, p);

    // x3 = lambda^2 - 2x1
    bn_mod_mul(x3, t3, t3, p);
    bn_mod_sub(x3, x3, g->x, p);
    bn_mod_sub(x3, x3, g->x, p);

    // y3 = lambda(x1 - x3) - y1
    bn_mod_sub(y3, g->x, x3, p);
    bn_mod_mul(y3, y3, t3, p);
    bn_mod_sub(y3, y3, g->y, p);

    bn_copy(c->x, x3);
    bn_copy(c->y, y3);
}

void point_mul(point *c, const point *g, const bn_t k, const bn_t p, const bn_t a) {
    // 处理k=0或无穷远点的情况
    if (bn_is_zero(k) || point_is_infty(g)) {
        point_new(c);
        return;
    }

    int l = bn_bit_len(k);

    // 初始化结果点为无穷远点
    point_new(c);

    for (int i = l - 1; i >= 0; i--) {
        point_dbl(c, c, p, a);
        if (bn_get_one_bit(k, i) == 1) {
            point_add(c, c, g, p, a);
        }
    }
}