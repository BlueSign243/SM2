#ifndef POINT_H
#define POINT_H

#include "bn.h"

typedef struct {
    bn_t x;
    bn_t y;
} point;

void point_new(point *p);

void point_add(point *c, const point *a, const point *b);

void point_mul(point *c, const point *a, const bn_t *n);

#endif