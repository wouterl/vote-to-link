#include "tdh.h"
#include "utils.h"

#include <stdio.h>
#include <relic/relic.h>

void
evaluate_polynomial(bn_t *y_res, const bn_t *fs, const size_t k, const bn_t x, const bn_t q);

void
tdh_keygen(struct tdh_pk **pk_res, struct tdh_sk **sks_res, int n, int k) {
    bn_t x;
    bn_null(x);
    bn_new(x);

    // Allocate structures for pk and sks
    struct tdh_pk *pk = malloc(sizeof(struct tdh_pk));
    struct tdh_sk *sks = malloc(n * sizeof(struct tdh_sk));

    pk->threshold = k;
    pk->n = n;

    bn_null(pk->q);
    bn_new(pk->q);
    g1_get_ord(pk->q);

    // Generate secret-sharing polynomial
    bn_t *fs = malloc(k * sizeof(bn_t));
    for(int i = 0; i < k; i++) {
        bn_null(fs[i]);
        bn_new(fs[i]);
        bn_rand_mod(fs[i], pk->q);
        // printf("f_{%i}: ", i); bn_print(fs[i]);
    }

    // Generate pk
    g1_null(pk->pk);
    g1_new(pk->pk);
    g1_mul_gen(pk->pk, fs[0]);

    // TODO: actually, need to generate this deterministically
    g1_null(pk->genbar);
    g1_new(pk->genbar);
    g1_rand(pk->genbar);

    // Generate verification and decryption keys
    pk->vk = malloc(n * sizeof(g1_t));

    for(int i = 0; i < n; i++) {
        sks[i].i = i + 1;

        bn_null(sks[i].sshare);
        bn_new(sks[i].sshare);
        bn_set_dig(x, i + 1);
        evaluate_polynomial(&(sks[i].sshare), fs, k, x, pk->q);

        //printf("f(%i): ", sks[i].i); bn_print(sks[i].sshare);

        g1_null(pk->vk[i]);
        g1_new(pk->vk[i]);
        g1_mul_gen(pk->vk[i], sks[i].sshare);
        g1_norm(pk->vk[i], pk->vk[i]);
    }

    // Generate commitments to polynomial coefficients
    pk->polycoms = malloc(k * sizeof(g1_t));
    for(int i = 0; i < k; i++) {
        g1_null(pk->polycoms[i]);
        g1_new(pk->polycoms[i]);
        g1_mul_gen(pk->polycoms[i], fs[i]);
    }

    for(int i = 0; i < k; i++) {
        bn_free(fs[i]);
    }
    free(fs);

    *pk_res = pk;
    *sks_res = sks;

    bn_new(x);
}

void
tdh_pk_free(struct tdh_pk *pk) {
    bn_free(pk->q);

    for(int i = 0; i < pk->n; i++) {
        g1_free(pk->vk[i]);
    }
    free(pk->vk);

    g1_free(pk->pk);
    g1_free(pk->genbar);

    for(int i = 0; i < pk->threshold; i++) {
        g1_free(pk->polycoms[i]);
    }
    free(pk->polycoms);

    free(pk);
}

void
tdh_sk_free(struct tdh_sk *sk) {
    bn_free(sk->sshare);
}

void
tdh_sks_free(struct tdh_sk *sks, size_t n) {
    for(int i = 0; i < n; i++) {
        tdh_sk_free(sks + i);
    }

    free(sks);
}

int
tdh_pk_verify(struct tdh_pk *pk) {
    // TODO: check deterministic generation of pk->genbar

    int result = 1;
 
    // Check evaluation of pk->vk[i] = g^{f(i + 1)}
    bn_t idx, power;
    bn_null(idx);
    bn_new(idx);
    bn_null(power);
    bn_new(power);

    g1_t expected;
    g1_null(expected);
    g1_new(expected);

    g1_t tmp;
    g1_null(tmp);
    g1_new(tmp);

    for(int i = 0; i < pk->n; i++) {
        bn_set_dig(power, 1);
        bn_set_dig(idx, i + 1);

        g1_copy(expected, pk->polycoms[0]);
        for(int j = 1; j < pk->threshold; j++) {
            // power = idx ** i
            bn_mul(power, power, idx);
            bn_mod(power, power, pk->q);

            g1_mul(tmp, pk->polycoms[j], power);
            g1_add(expected, expected, tmp);
        }

        g1_norm(expected, expected);
        if(g1_cmp(expected, pk->vk[i]) != CMP_EQ) {
            printf("Verification key %i incorrect!\n", i);
            result = 0;
            break;
        }
    }

    bn_free(idx);
    bn_free(power);
    g1_free(expected);
    g1_free(tmp);

    return result;
}

int
tdh_pk_verify_probabilistic(struct tdh_pk *pk) {
    // TODO: check deterministic generation of pk->genbar

    /*
     * We operate over sets of moderator verification keys
     * of size threshold, and evaluate them (using lagrange)
     * at a random point. This point we also evaluate using
     * the polynomial commitments. If they match, with high
     * probability the keys are correct.
     */

    bn_t x, power;
    bn_null(x);
    bn_new(x);
    bn_null(power);
    bn_new(power);

    g1_t expected;
    g1_null(expected);
    g1_new(expected);

    g1_t calculated;
    g1_null(calculated);
    g1_new(calculated);

    g1_t tmp;
    g1_null(tmp);
    g1_new(tmp);

    bn_t *lcoefs = malloc(pk->threshold * sizeof(bn_t));
    size_t *idxs = malloc(pk->threshold * sizeof(size_t));

    for(int i = 0; i < pk->threshold; i++) {
        bn_null(lcoefs[i]);
        bn_new(lcoefs[i]);
    }

    for(int i = 0; i < pk->n; i += pk->threshold) {
        // Make sure we do not run out of range
        if( (pk->n - i) < pk->threshold ) {
            i = pk->n - pk->threshold;
        }

        // Random evaluation point
        bn_rand_mod(x, pk->q);
        bn_set_dig(power, 1);

        g1_copy(expected, pk->polycoms[0]);
        for(int j = 1; j < pk->threshold; j++) {
            // power = x ** i
            bn_mul(power, power, x);
            bn_mod(power, power, pk->q);

            g1_mul(tmp, pk->polycoms[j], power);
            g1_add(expected, expected, tmp);
        }
        g1_norm(expected, expected);

        // Now evaluate set vk[i],...,vk[i + threshold - 1]
        // at the same random point x using lagrange polynomials
        for(int j = 0; j < pk->threshold; j++) {
            idxs[j] = i + j + 1;
        }
        calculate_lcoefs_at(lcoefs, idxs, x, pk->threshold,  pk->q);

        g1_set_infty(calculated);
        for(int j = 0; j < pk->threshold; j++) {
            g1_mul(tmp, pk->vk[i + j], lcoefs[j]);
            g1_add(calculated, calculated, tmp);
        }
        g1_norm(calculated, calculated);

        if(g1_cmp(expected, calculated) != CMP_EQ) {
            printf("Verification check from %i failed!\n", i);
            return 0;
        }

    }

    free(idxs);

    for(int i = 0; i < pk->threshold; i++) {
        bn_free(lcoefs[i]);
    }
    free(lcoefs);

    bn_free(x);
    bn_free(power);
    g1_free(expected);
    g1_free(calculated);
    g1_free(tmp);

    return 1;
}


void
evaluate_polynomial(bn_t *y_res, const bn_t *fs, const size_t k, const bn_t x, const bn_t q) {
    // factor = 1;
    bn_t factor;
    bn_null(factor);
    bn_new(factor);
    bn_set_dig(factor, 1);

    // y = 0
    bn_t y;
    bn_null(y);
    bn_new(y);
    bn_set_dig(y, 0);

    bn_t tmp;
    bn_null(tmp);
    bn_new(tmp);

    bn_t aux_mod;
    bn_null(aux_mod);
    bn_new(aux_mod)
    //bn_mod_pre(aux_mod, q);
    //printf("q = "); bn_print(q);

    for(int i = 0; i < k; i++) {
        // Invariant: factor = x**i
        // printf("x**%i = ", i); bn_print(factor);

        bn_mul(tmp, factor, fs[i]);
        // printf("Adding: "); bn_print(tmp);
        bn_add(y, y, tmp);

        bn_mul(factor, factor, x);
        bn_mod(factor, factor, q);

        // TODO: for some reason the faster method doesn't work
        //bn_mod(factor, factor, q, aux_mod);
    }

    bn_mod(*y_res, y, q);
}

void
tdh_enc_hash(bn_t *e, g1_t c, uint8_t *L, size_t lL, g1_t u, g1_t uhat, g1_t v, g1_t vhat) {
    uint8_t hash[MD_LEN_SH512];

    bn_null(*e);
    bn_new(*e);

    size_t lc    = g1_size_bin(c,    1);
    size_t lu    = g1_size_bin(u,    1);
    size_t luhat = g1_size_bin(uhat, 1);
    size_t lv    = g1_size_bin(v,    1);
    size_t lvhat = g1_size_bin(vhat, 1);

    /*
    printf("c   : "); g1_print(c);
    printf("u   : "); g1_print(u);
    printf("uhat: "); g1_print(uhat);
    printf("v   : "); g1_print(v);
    printf("vhat: "); g1_print(vhat);
    */

    size_t input_len = lL + lc + lu + luhat + lv + lvhat;
    //printf("Adding %i bytes to hash (%i per group element)\n", input_len, lc);

    uint8_t *input = malloc(input_len);
    uint8_t *iptr = input;

    // Adding L
    memcpy(iptr, L, lL);
    iptr += lL;

    // Adding c
    g1_write_bin(iptr, lc, c, 1);
    iptr += lc;

    // Adding u
    g1_write_bin(iptr, lu, u, 1);
    iptr += lu;

    // Adding uhat
    g1_write_bin(iptr, luhat, uhat, 1);
    iptr += luhat;

    // Adding v
    g1_write_bin(iptr, lv, v, 1);
    iptr += lv;

    // Adding vhat
    g1_write_bin(iptr, lvhat, vhat, 1);
    iptr += lvhat;

    md_map_sh512(hash, input, input_len);

    bn_t q;
    bn_null(q);
    bn_new(q);
    g1_get_ord(q);

    bn_read_bin(*e, hash, MD_LEN_SH512);
    bn_mod(*e, *e, q);

    free(input);
    bn_free(q);
}

void
tdh_enc(struct tdh_ctxt *ctxt, struct tdh_pk *pk, g1_t m, uint8_t *L, size_t lL) {
    bn_t r;

    bn_null(r);
    bn_new(r);
    bn_rand_mod(r, pk->q);

    tdh_enc_with_random(ctxt, pk, m, L, lL, r);

    bn_free(r);
}

void
tdh_enc_with_random(struct tdh_ctxt *ctxt, struct tdh_pk *pk, g1_t m, uint8_t *L,
        size_t lL, bn_t r) {
    bn_t s;

    bn_null(s);
    bn_new(s);
    bn_rand_mod(s, pk->q);

    g1_t uhat, vhat;

    g1_t tmp;
    g1_null(tmp);
    g1_new(tmp);

    // c = m * w^r;
    g1_null(ctxt->c);
    g1_new(ctxt->c);
    g1_mul(tmp, pk->pk, r);
    // printf("w^r = "); g1_norm(tmp, tmp); g1_print(tmp);
    g1_add(ctxt->c, m, tmp);

    // u = g^r
    g1_null(ctxt->u);
    g1_new(ctxt->u);
    g1_mul_gen(ctxt->u, r);

    // uhat = g^s
    g1_null(uhat);
    g1_new(uhat);
    g1_mul_gen(uhat, s);

    // v = genbar^r
    g1_null(ctxt->v);
    g1_new(ctxt->v);
    g1_mul(ctxt->v, pk->genbar, r);

    // vhat = genbar^s
    g1_null(vhat);
    g1_new(vhat);
    g1_mul(vhat, pk->genbar, s);

    // Calculate the hash
    tdh_enc_hash(&ctxt->e, ctxt->c, L, lL, ctxt->u, uhat, ctxt->v, vhat);
    // printf("Challenge e = "); bn_print(ctxt->e);

    // f = s + re
    bn_null(ctxt->f);
    bn_new(ctxt->f);

    bn_mul(ctxt->f, r, ctxt->e);
    bn_add(ctxt->f, ctxt->f, s);
    bn_mod(ctxt->f, ctxt->f, pk->q);
    // printf("Response f = "); bn_print(ctxt->f);

    ctxt->L = L;
    ctxt->lL = lL;

    bn_free(s);
    g1_free(tmp);
    g1_free(uhat);
    g1_free(vhat);
}

int
tdh_ctxt_verify(struct tdh_ctxt *ctxt, struct tdh_pk *pk) {
    g1_t uhat, vhat, tmp, tmpmin;
    bn_t e;

    g1_null(uhat);
    g1_new(uhat);

    g1_null(vhat);
    g1_new(vhat);

    g1_null(tmp);
    g1_new(tmp);

    g1_null(tmpmin);
    g1_new(tmpmin);

    // uhat = g^(ctxt->f) u^(-ctxt->e)
    g1_mul_gen(uhat, ctxt->f);
    g1_neg(tmpmin, ctxt->u);
    g1_mul(tmp, tmpmin, ctxt->e);
    g1_add(uhat, uhat, tmp);

    // vhat = genbar^(ctxt->f) v^(-ctxt->e)
    g1_mul(vhat, pk->genbar, ctxt->f);
    g1_neg(tmpmin, ctxt->v);
    g1_mul(tmp, tmpmin, ctxt->e);
    g1_add(vhat, vhat, tmp);

    // Checking hash
    bn_null(e);
    bn_new(e);
    tdh_enc_hash(&e, ctxt->c, ctxt->L, ctxt->lL, ctxt->u, uhat, ctxt->v, vhat);
    //printf("Recovered chall: "); bn_print(e);
    //
    g1_free(uhat);
    g1_free(vhat);
    g1_free(tmp);
    g1_free(tmpmin);

    int result = bn_cmp(e, ctxt->e) == CMP_EQ;
    bn_free(e);

    return result;
}

size_t
tdh_ctxt_size(struct tdh_ctxt *ctxt) {
    size_t res = 0;

    res += g1_size_bin(ctxt->c, 1);
    res += g1_size_bin(ctxt->u, 1);
    res += g1_size_bin(ctxt->v, 1);

    res += bn_size_bin(ctxt->e);
    res += bn_size_bin(ctxt->f);

    return res;
}

void
tdh_dec_hash(bn_t *e, g1_t ui, g1_t uihat, g1_t wihat) {
    uint8_t hash[MD_LEN_SH512];

    bn_null(*e);
    bn_new(*e);

    size_t lui    = g1_size_bin(ui,    1);
    size_t luihat = g1_size_bin(uihat, 1);
    size_t lwihat = g1_size_bin(wihat, 1);

    size_t input_len = lui + luihat + lwihat;
    //printf("Adding %i bytes to hash\n", input_len);

    uint8_t *input = malloc(input_len);
    uint8_t *iptr = input;

    // Adding ui
    g1_write_bin(iptr, lui, ui, 1);
    iptr += lui;

    // Adding uihat
    g1_write_bin(iptr, luihat, uihat, 1);
    iptr += luihat;

    // Adding wihat
    g1_write_bin(iptr, lwihat, wihat, 1);
    iptr += lwihat;

    md_map_sh512(hash, input, input_len);

    bn_t q;
    bn_null(q);
    bn_new(q);
    g1_get_ord(q);

    bn_read_bin(*e, hash, MD_LEN_SH512);
    bn_mod(*e, *e, q);

    free(input);
    bn_free(q);
}

void
tdh_share_dec(struct tdh_dec_share *d, struct tdh_ctxt *ctxt, struct tdh_pk *pk, struct tdh_sk *sk) {
    g1_t uihat, wihat;
    bn_t si;

    d->i = sk->i;
    if(!tdh_ctxt_verify(ctxt, pk)) {
        d->bottom = 1;
        return;
    }

    bn_null(si);
    bn_new(si);
    bn_rand_mod(si, pk->q);

    g1_null(d->ui);
    g1_new(d->ui);
    g1_mul(d->ui, ctxt->u, sk->sshare);

    g1_null(uihat);
    g1_new(uihat);
    g1_mul(uihat, ctxt->u, si);

    g1_null(wihat);
    g1_new(wihat);
    g1_mul_gen(wihat, si);

    tdh_dec_hash(&d->ei, d->ui, uihat, wihat);
    //printf("Dec %i, challenge = ", sk->i); bn_print(d->ei);

    bn_mul(d->fi, sk->sshare, d->ei);
    bn_add(d->fi, d->fi, si);
    bn_mod(d->fi, d->fi, pk->q);

    g1_free(uihat);
    g1_free(wihat);
    bn_free(si);
}

int
tdh_share_verify(struct tdh_dec_share *d, struct tdh_ctxt *ctxt, struct tdh_pk *pk) {
    if(!tdh_ctxt_verify(ctxt, pk)) {
        printf("Ctxt incorrect, share should have bottom");
        return d->bottom == 1;
    }

    g1_t uihat, wihat, tmp, tmpmin;

    g1_null(tmp);
    g1_new(tmp);
    g1_null(tmpmin);
    g1_new(tmpmin);

    g1_null(uihat);
    g1_new(uihat);
    g1_mul(uihat, ctxt->u, d->fi);
    g1_neg(tmpmin, d->ui);
    g1_mul(tmp, tmpmin, d->ei);
    g1_add(uihat, uihat, tmp);

    g1_null(wihat);
    g1_new(wihat);
    g1_mul_gen(wihat, d->fi);
    g1_neg(tmpmin, pk->vk[d->i - 1]);
    g1_mul(tmp, tmpmin, d->ei);
    g1_add(wihat, wihat, tmp);

    bn_t ei;

    tdh_dec_hash(&ei, d->ui, uihat, wihat);
    //printf("Dec %i, recv chall = ", d->i); bn_print(ei);

    int res = bn_cmp(ei, d->ei) == CMP_EQ;

    g1_free(uihat);
    g1_free(wihat);
    g1_free(tmp);
    g1_free(tmpmin);

    bn_free(ei);

    return res;
}

void
calculate_lcoefs(bn_t *lcoefs, size_t *idxs, size_t k,  bn_t q) {
    // Calculate Lagrange coefficients
    bn_t denom, numer;
    bn_null(denom);
    bn_new(denom);
    bn_null(numer);
    bn_new(numer);

    bn_t bni, bnj, tmp;
    bn_null(bni);
    bn_new(bni);
    bn_null(bnj);
    bn_new(bnj);
    bn_null(tmp);
    bn_new(tmp);

    for(int i = 0; i < k; i++) {
        bn_set_dig(denom, 1);
        bn_set_dig(numer, 1);
        bn_set_dig(bni, idxs[i]);
        for(int j = 0; j < k; j++) {
            if(j != i) {
                bn_set_dig(bnj, idxs[j]);
                bn_mul(numer, numer, bnj);
                bn_mod(numer, numer, q);

                bn_sub(tmp, bnj, bni);
                bn_mul(denom, denom, tmp);
                bn_mod(denom, denom, q);
            }
        }
        //printf("%i:\n", idxs[i]);
        //printf("  numer: "); bn_print(numer);
        //printf("  denom: "); bn_print(denom);

        bn_null(lcoefs[i]);
        bn_new(lcoefs[i]);

        bn_inv_mod(denom, denom, q);
        bn_mul(lcoefs[i], numer, denom);
        bn_mod(lcoefs[i], lcoefs[i], q);
        //printf(" result: "); bn_print(lcoefs[i]);
    }
}

void
calculate_lcoefs_at(bn_t *lcoefs, size_t *idxs, bn_t x, size_t k,  bn_t q) {
    // Calculate Lagrange coefficients
    bn_t denom, numer;
    bn_null(denom);
    bn_new(denom);
    bn_null(numer);
    bn_new(numer);

    bn_t bni, bnj, tmp;
    bn_null(bni);
    bn_new(bni);
    bn_null(bnj);
    bn_new(bnj);
    bn_null(tmp);
    bn_new(tmp);

    for(int i = 0; i < k; i++) {
        bn_set_dig(denom, 1);
        bn_set_dig(numer, 1);
        bn_set_dig(bni, idxs[i]);
        for(int j = 0; j < k; j++) {
            if(j != i) {
                bn_set_dig(bnj, idxs[j]);
                bn_sub(tmp, bnj, x);
                bn_mul(numer, numer, tmp);
                bn_mod(numer, numer, q);

                bn_sub(tmp, bnj, bni);
                bn_mul(denom, denom, tmp);
                bn_mod(denom, denom, q);
            }
        }
        //printf("%i:\n", idxs[i]);
        //printf("  numer: "); bn_print(numer);
        //printf("  denom: "); bn_print(denom);

        bn_null(lcoefs[i]);
        bn_new(lcoefs[i]);

        bn_inv_mod(denom, denom, q);
        bn_mul(lcoefs[i], numer, denom);
        bn_mod(lcoefs[i], lcoefs[i], q);
        //printf(" result: "); bn_print(lcoefs[i]);
    }

    bn_free(denom);
    bn_free(numer);
    bn_free(bni);
    bn_free(bnj);
    bn_free(tmp);
}

int
tdh_combine(g1_t *msg, struct tdh_ctxt *ctxt, struct tdh_pk *pk,
        struct tdh_dec_share *ctxtshare, size_t nshares) {
    return tdh_combine_base(msg, ctxt, pk, ctxtshare, nshares, 1);
}

int
tdh_combine_base(g1_t *msg, struct tdh_ctxt *ctxt, struct tdh_pk *pk,
        struct tdh_dec_share *ctxtshare, size_t nshares, int strict) {
    if (nshares < pk->threshold) {
        printf("Not enough shares to recover");
        return 1;
    }

    if(strict) {
        for(int i = 0; i < pk->threshold; i++) {
            if(!tdh_share_verify(&ctxtshare[i], ctxt, pk)) {
                printf("Share %i is not correct, no decryption possible", i);
                return 1;
            }
        }
    }

    bn_t *lcoef = malloc(sizeof(bn_t) * pk->threshold);
    size_t *idxs = malloc(sizeof(size_t) * pk->threshold);
    for(int i = 0; i < pk->threshold; i++) {
        idxs[i] = ctxtshare[i].i;
    }
    calculate_lcoefs(lcoef, idxs, pk->threshold, pk->q);

    g1_t prod;
    g1_null(prod);
    g1_new(prod);
    g1_set_infty(prod);

    g1_t tmp;
    g1_null(tmp);
    g1_new(tmp);

    for(int i = 0; i < pk->threshold; i++) {
        g1_mul(tmp, ctxtshare[i].ui, lcoef[i]);
        g1_add(prod, prod, tmp);
    }
    //printf("Recovered w^r = "); g1_norm(prod, prod); g1_print(prod);
    g1_neg(prod, prod);

    g1_add(*msg, ctxt->c, prod);
    g1_norm(*msg, *msg);
    //printf("Recovered msg: "); g1_print(*msg);

    for(int i = 0; i < pk->threshold; i++) {
        bn_free(lcoef[i]);
    }
    free(lcoef);
    free(idxs);

    return 0;
}

void
test_polynomial() {
    bn_t x, q;
    bn_t a[3];

    bn_null(x);
    bn_new(x);
    bn_set_dig(x, 7);

    bn_null(a[0]);
    bn_new(a[0]);
    bn_set_dig(a[0], 2);

    bn_null(a[1]);
    bn_new(a[1]);
    bn_set_dig(a[1], 9);

    bn_null(a[2]);
    bn_new(a[2]);
    bn_set_dig(a[2], 5);

    bn_null(q);
    bn_new(q);
    bn_set_dig(q, 13);

    bn_t result;
    bn_null(result);
    bn_new(result);

    evaluate_polynomial(&result, &a[0], 3, x, q);
    printf("y="); bn_print(result);
}

void
test_lagrange() {
    size_t idxs[] = {3, 5, 2};

    bn_t q;
    bn_null(q);
    bn_new(q);
    bn_set_dig(q, 7);

    bn_t lcoefs[3];

    calculate_lcoefs(lcoefs, idxs, 3, q);
}
