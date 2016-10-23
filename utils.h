#include <relic/relic.h>

void bn_inv_mod(bn_t res, const bn_t input, const bn_t n);

void bn_rands_from_stream(bn_t *res, size_t n, size_t nr_bytes,
        uint8_t *key);

void print_bytes(uint8_t *p, int count);
