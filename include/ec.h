#ifndef EC_H
#define EC_H

#include "bn.h"
#include "point.h"

typedef struct {
    bn_t p;
    bn_t a;
    bn_t b;
    point g;
    bn_t n;
} group;

void create_group(group *g, const char *p_hex, const char *a_hex, const char *b_hex, const char *gx_hex,
                  const char *gy_hex, const char *n_hex);

#endif