#ifndef POINT_H
#define POINT_H

#include "bn.h"

typedef struct {
    bn_t x;
    bn_t y;
} point;

void point_new(point *p);

int point_equals(const point *a, const point *b);

int point_is_infty(const point *a);

void point_add(point *c, const point *g, const point *b, const bn_t p, const bn_t a);

void point_dbl(point *c, const point *g, const bn_t p, const bn_t a);

void point_mul(point *c, const point *g, const bn_t k, const bn_t p, const bn_t a);

#endif