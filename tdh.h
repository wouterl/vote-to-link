#include <relic/relic.h>

struct tdh_pk {
    g1_t *vk;
    g1_t pk;
    g1_t genbar;
    bn_t q;

    int threshold;
    int n;

    // Mostly for faster verification of tdh_pk
    g1_t *polycoms;
};

struct tdh_sk {
    int i;
    bn_t sshare;
};

struct tdh_ctxt {
    g1_t c;
    g1_t u;
    g1_t v;
    bn_t e;
    bn_t f;

    uint8_t* L;
    size_t lL;
};

struct tdh_dec_share {
    int i;
    int bottom;

    g1_t ui;
    bn_t ei;
    bn_t fi;
};

void tdh_keygen(struct tdh_pk **pk_res, struct tdh_sk **sks_res, int n, int k);

int tdh_pk_verify(struct tdh_pk *pk);

int tdh_pk_verify_probabilistic(struct tdh_pk *pk);

void tdh_pk_free(struct tdh_pk *pk);

void tdh_sks_free(struct tdh_sk *sks, size_t n);

void tdh_enc(struct tdh_ctxt *ctxt, struct tdh_pk *pk, g1_t m, uint8_t *L,
        size_t lL);

void tdh_enc_with_random(struct tdh_ctxt *ctxt, struct tdh_pk *pk, g1_t m,
        uint8_t *L, size_t lL, bn_t r);

int tdh_ctxt_verify(struct tdh_ctxt *ctxt, struct tdh_pk *pk);

size_t tdh_ctxt_size(struct tdh_ctxt *ctxt);

void tdh_share_dec(struct tdh_dec_share *d, struct tdh_ctxt *ctxt, struct tdh_pk *pk, struct tdh_sk *sk);

int tdh_share_verify(struct tdh_dec_share *d, struct tdh_ctxt *ctxt, struct tdh_pk *pk);

int tdh_combine(g1_t *msg, struct tdh_ctxt *ctxt, struct tdh_pk *pk, struct tdh_dec_share *ctxtshare, size_t nshares);

int tdh_combine_base(g1_t *msg, struct tdh_ctxt *ctxt, struct tdh_pk *pk,
        struct tdh_dec_share *ctxtshare, size_t nshares, int strict);

void calculate_lcoefs_at(bn_t *lcoefs, size_t *idxs, bn_t x, size_t k,  bn_t q);
