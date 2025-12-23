#include "point.h"

void point_new(point *p) {
    bn_new(p->x);
    bn_new(p->y);
}

void point_add(point *c, const point *a, const point *b) {
}