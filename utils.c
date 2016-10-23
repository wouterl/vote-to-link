#include <relic/relic.h>
#include <sodium.h>

#include "utils.h"

void
bn_inv_mod(bn_t res, const bn_t input, const bn_t n) {
    bn_t tmp1, tmp2;
    bn_null(tmp1);
    bn_new(tmp1);
    bn_null(tmp2);
    bn_new(tmp2);

    bn_gcd_ext(tmp1, res, tmp2, input, n);

    if(bn_sign(res) == BN_NEG) {
        bn_add(res, res, n);
    }
}


/*
 * Creates n bn_t's containing nr_bytes bytes of random stream
 *
 * NOTE: The key needs to be 32 bytes
 */
void
bn_rands_from_stream(bn_t *res, size_t n, size_t nr_bytes,
        uint8_t *key) {
    // Always using a fixed nonce
    uint64_t nonce = 0;

    size_t stream_len = n * nr_bytes;
    uint8_t *stream = malloc(stream_len);

    crypto_stream_salsa20(stream, stream_len, (uint8_t *) &nonce, key);

    for(int i = 0; i < n; i++) {
        bn_null(res[i]);
        bn_new(res[i]);
        bn_read_bin(res[i], stream + i * nr_bytes, nr_bytes);
    }

    free(stream);
}

void
print_bytes(uint8_t *p, int count) {
    uint8_t* p_end = p + count;
    unsigned int i = 0;
    for(;p < p_end; p++) {
        printf("%02x", *p);
        i++;
        if(i > 0 && i % 8 == 0 && i < 64) {
            printf(" ");
        }
        if(i == 32) {
            printf("\n");
            i = 0;
        }
    }
    printf("\n");
}
