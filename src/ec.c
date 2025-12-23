#include "ec.h"
#include "bn.h"

void create_group(group *g, const char *p_hex, const char *a_hex, const char *b_hex, const char *gx_hex,
                  const char *gy_hex, const char *n_hex) {
    bn_new(g->p);
    bn_new(g->a);
    bn_new(g->b);
    bn_new(g->n);
    point_new(&g->g);
    bn_from_hex(g->p, p_hex);
    bn_from_hex(g->a, a_hex);
    bn_from_hex(g->b, b_hex);
    bn_from_hex(g->n, n_hex);
    bn_from_hex(g->g.x, gx_hex);
    bn_from_hex(g->g.y, gy_hex);
}
