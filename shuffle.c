#include "shuffle.h"
#include "utils.h"

#include <stdio.h>
#include <relic/relic.h>

void
unsafe_random_permutation(unsigned int *perm, size_t n) {
    int j;
    for(int i = 0; i < n; i ++) {
        // TODO: using rand like this is really super insecure
        j = rand() % (i + 1);
        perm[i] = perm[j];
        perm[j] = i;
    }
}

void
shuffle_commit_keygen(struct shuffle_com_pk *pk, size_t n) {
    pk->nr_bases = n;
    pk->bases = malloc(n * sizeof(bn_t));

    for(int i = 0; i < n; i++) {
        g1_null(pk->bases[i]);
        g1_new(pk->bases[i]);
        g1_rand(pk->bases[i]);
    }

    g1_null(pk->rand_base);
    g1_new(pk->rand_base);
    g1_rand(pk->rand_base);

    bn_null(pk->q);
    bn_new(pk->q);
    g1_get_ord(pk->q);
}

void
shuffle_commit_new(struct shuffle_com *com, size_t n) {
    com->n = n;
    g1_null(com->com);
    g1_new(com->com);
}

void
shuffle_commit_to(struct shuffle_com *com, bn_t *vals, size_t n, bn_t r,
        struct shuffle_com_pk *pk) {
    g1_t tmp;
    g1_null(tmp);
    g1_new(tmp);
    
    /*
    printf("Committing to %i values\n", n);
    printf("Using randomness: "); bn_print(r);
    for(int i = 0; i < n; i++) {
        printf("Value %i: ", i); bn_print(vals[i]);
    }
    */

    g1_mul(com->com, pk->rand_base, r);

    bn_t tmpbn;
    bn_null(tmpbn);
    bn_new(tmpbn);

    for(int i = 0; i < n; i++) {
        // DIRTY HACK: remove this after negative exponent is fixed
        if(bn_sign(vals[i]) == BN_NEG) {
            bn_add(tmpbn, vals[i], pk->q);
        } else {
            bn_copy(tmpbn, vals[i]);
        }

        g1_mul(tmp, pk->bases[i], tmpbn);
        g1_add(com->com, com->com, tmp);
    }
}

void
shuffle_commit_exp(struct shuffle_com *res, struct shuffle_com *com, bn_t exp) {
    g1_mul(res->com, com->com, exp);
}

void
shuffle_commit_mul(struct shuffle_com *res, struct shuffle_com *com,
        struct shuffle_com *mul) {
    g1_add(res->com, com->com, mul->com);
}

int
shuffle_commit_equal(struct shuffle_com *left, struct shuffle_com *right) {
    g1_norm(left->com, left->com);
    g1_norm(right->com, right->com);
    
    return (left->n == right->n) && (g1_cmp(left->com, right->com) == 0);
}

size_t
shuffle_commit_size(struct shuffle_com *com) {
    // TODO: also encode size?
    return g1_size_bin(com->com, 1);
}

void
shuffle_commit_write_bin(uint8_t *ptr, size_t size, struct shuffle_com *com) {
    g1_write_bin(ptr, size, com->com, 1);
}

void
shuffle_proof_hash_x(bn_t x, struct shuffle_com *c, bn_t *vals, size_t n,
        uint8_t *context, size_t lcontext) {
    size_t input_len = lcontext;
    size_t commit_size = shuffle_commit_size(c);
    input_len += commit_size;
    // TODO: this is not completely secure, as the inputs are not separated
    for(int i = 0; i < n; i++) {
        input_len += bn_size_bin(vals[i]);
    }

    uint8_t *input = malloc(input_len);
    uint8_t *iptr = input;

    memcpy(iptr, context, lcontext);
    iptr += lcontext;

    shuffle_commit_write_bin(iptr, commit_size, c);
    iptr += commit_size;

    size_t len;
    for(int i = 0; i < n; i++) {
        len = bn_size_bin(vals[i]);
        bn_write_bin(iptr, len, vals[i]);
        iptr += len;
    }

    uint8_t hash[MD_LEN_SH256];
    md_map_sh256(hash, input, input_len);

    // Only read 20 bytes, to get a 160 bits value
    bn_read_bin(x, hash, 20);
}

// We take x as input so we can include all of the preceeding state
void
shuffle_proof_hash_e(bn_t e, bn_t x, struct shuffle_com *cd,
        struct shuffle_com *cdelta, struct shuffle_com *ca) {
    size_t input_len = 0;

    size_t lx      = bn_size_bin(x);

    size_t lcd     = shuffle_commit_size(cd    );
    size_t lcdelta = shuffle_commit_size(cdelta);
    size_t lca     = shuffle_commit_size(ca    );

    input_len = lx + lcd + lcdelta + lca;

    uint8_t *input = malloc(input_len);
    uint8_t *iptr = input;

    bn_write_bin(iptr, lx, x);
    iptr += lx;

    shuffle_commit_write_bin(iptr, lcd, cd);
    iptr += lcd;

    shuffle_commit_write_bin(iptr, lcdelta, cdelta);
    iptr += lcdelta;

    shuffle_commit_write_bin(iptr, lca, ca);
    iptr += lca;

    uint8_t hash[MD_LEN_SH256];
    md_map_sh256(hash, input, input_len);

    // Only read 20 bytes, to get a 160 bits value
    bn_read_bin(e, hash, 20);
}

void
shuffle_prove_known_content(struct shuffle_known_proof *proof,
        struct shuffle_com *c, bn_t r, bn_t *vals, size_t n,
        unsigned int *perm, struct shuffle_com_pk *pk,
        uint8_t *context, size_t lcontext) {
    bn_t *d, rd, rdelta;
    bn_t *delta;
    bn_t *a, ra;

    proof->n = n;

    // Determine x, based on some inputs
    bn_null(proof->x);
    bn_new(proof->x);
    shuffle_proof_hash_x(proof->x, c, vals, n, context, lcontext);

    d = malloc(n * sizeof(bn_t));
    for(int i = 0; i < n; i++) {
        bn_null(d[i]);
        bn_new(d[i]);
        bn_rand_mod(d[i], pk->q);
    }

    bn_null(rd);
    bn_new(rd);
    bn_rand_mod(rd, pk->q);

    bn_null(rdelta);
    bn_new(rdelta);
    bn_rand_mod(rdelta, pk->q);

    // Initialize \delta_i
    delta = malloc(n * sizeof(bn_t));
    bn_null(delta[0]);
    bn_new(delta[0]);
    bn_copy(delta[0], d[0]);
    for(int i = 1; i < n - 1; i++) {
        bn_null(delta[i]);
        bn_new(delta[i]);
        bn_rand_mod(delta[i], pk->q);
    }
    bn_null(delta[n - 1]);
    bn_new(delta[n - 1]);
    bn_set_dig(delta[n - 1], 0);

    // Initialize a_i
    a = malloc((n-1) * sizeof(bn_t));
    for(int i = 0; i < (n-1); i++) {
        bn_null(a[i]);
        bn_new(a[i]);
        bn_sub(a[i], vals[perm[i]], proof->x);
        if(i > 0) {
            bn_mul(a[i], a[i - 1], a[i]);
        }
        bn_mod(a[i], a[i], pk->q);
    }

    bn_null(ra);
    bn_new(ra);
    bn_rand_mod(ra, pk->q);

    shuffle_commit_new(&proof->cd, n);
    shuffle_commit_to(&proof->cd, d, n, rd, pk);

    bn_t *comdeltad;
    comdeltad = malloc((n-1) * sizeof(bn_t));
    for(int i = 0; i < (n - 1); i++) {
        bn_null(comdeltad[i]);
        bn_new(comdeltad[i]);
        bn_mul(comdeltad[i], delta[i], d[i+1]);
        bn_neg(comdeltad[i], comdeltad[i]);
        bn_mod(comdeltad[i], comdeltad[i], pk->q);
    }
    shuffle_commit_new(&proof->cdelta, n - 1);
    shuffle_commit_to(&proof->cdelta, comdeltad, n - 1, rdelta, pk);

    bn_t tmpbn;
    bn_null(tmpbn);
    bn_new(tmpbn);

    bn_t *coma;
    coma = malloc((n-1) * sizeof(bn_t));
    for(int i = 0; i < (n - 1); i++) {
        bn_null(coma[i]);
        bn_new(coma[i]);

        // coma[i] = delta[i+1] - (vals[perm[i+i]] - x)*delta[i] - a[i] d[i+1]
        bn_sub(tmpbn, vals[perm[i+1]], proof->x);
        bn_mul(tmpbn, tmpbn, delta[i]);
        bn_sub(coma[i], delta[i+1], tmpbn);
        bn_mul(tmpbn, a[i], d[i + 1]);
        bn_sub(coma[i], coma[i], tmpbn);
        bn_mod(coma[i], coma[i], pk->q);
    }
    shuffle_commit_new(&proof->ca, n - 1);
    shuffle_commit_to(&proof->ca, coma, n - 1, ra, pk);

    // Determine e, based on some inputs
    bn_null(proof->e);
    bn_new(proof->e);
    shuffle_proof_hash_e(proof->e, proof->x, &proof->cd,
            &proof->cdelta, &proof->ca);

    // Calculate responses f, z, fdelta, zdelta

    proof->f = malloc(n * sizeof(bn_t));
    for(int i = 0; i < n; i++) {
        bn_null(proof->f[i]);
        bn_new(proof->f[i]);
        bn_mul(proof->f[i], proof->e, vals[perm[i]]);
        bn_add(proof->f[i], proof->f[i], d[i]);
        bn_mod(proof->f[i], proof->f[i], pk->q);
    }
    bn_null(proof->z);
    bn_new(proof->z);
    bn_mul(proof->z, proof->e, r);
    bn_add(proof->z, proof->z, rd);
    bn_mod(proof->z, proof->z, pk->q);

    proof->fdelta = malloc((n-1) * sizeof(bn_t));
    for(int i = 0; i < (n - 1); i++) {
        bn_null(proof->fdelta[i]);
        bn_new(proof->fdelta[i]);
        bn_mul(proof->fdelta[i], proof->e, coma[i]);
        bn_add(proof->fdelta[i], proof->fdelta[i], comdeltad[i]);
        bn_mod(proof->fdelta[i], proof->fdelta[i], pk->q);
    }
    bn_null(proof->zdelta);
    bn_new(proof->zdelta);
    bn_mul(proof->zdelta, proof->e, ra);
    bn_add(proof->zdelta, proof->zdelta, rdelta);
    bn_mod(proof->zdelta, proof->zdelta, pk->q);
}

void
shuffle_commit_print(struct shuffle_com *com) {
    printf("Commit on %zu values\n", com->n);
    printf("Commit: "); g1_norm(com->com, com->com); g1_print(com->com);
}

int
shuffle_verify_known_content_proof(struct shuffle_known_proof *proof,
        struct shuffle_com *c, bn_t *vals, size_t n,
        struct shuffle_com_pk *pk, uint8_t *context, size_t lcontext) {
    // Check cd, ca, cdelta \in commit-space
    // Check f[i], z, fdelta[i], zdelta \in Zq

    // Checking whether x and e were calculated correctly
    bn_t x, e;
    bn_null(x);
    bn_new(x);
    bn_null(e);
    bn_new(e);

    shuffle_proof_hash_x(x, c, vals, n, context, lcontext);
    shuffle_proof_hash_e(e, proof->x, &proof->cd,
            &proof->cdelta, &proof->ca);

    if( bn_cmp(proof->x, x) != CMP_EQ ||
            bn_cmp(proof->e, e) != CMP_EQ) {
        printf("Challenges are incorrect");
        return 0;
    }

    // Check c^e * cdelta = com(f[0], ..., f[n-1]; z)
    struct shuffle_com left;
    shuffle_commit_new(&left, n);
    shuffle_commit_exp(&left, c, proof->e);
    shuffle_commit_mul(&left, &left, &proof->cd);

    struct shuffle_com right;
    shuffle_commit_new(&right, n);
    shuffle_commit_to(&right, proof->f, n, proof->z, pk);

    if(!shuffle_commit_equal(&left, &right)) {
        printf("First commit check failed!\n");
        return 0;
    }

    struct shuffle_com left2, right2;
    shuffle_commit_new(&left2, n - 1);
    shuffle_commit_exp(&left2, &proof->ca, proof->e);
    shuffle_commit_mul(&left2, &left2, &proof->cdelta);

    shuffle_commit_new(&right2, n - 1);
    shuffle_commit_to(&right2, proof->fdelta, n - 1, proof->zdelta, pk);

    if(!shuffle_commit_equal(&left2, &right2)) {
        printf("Second commit check failed!\n");
        return 0;
    }

    bn_t *F = malloc(n * sizeof(bn_t));
    for(int i = 0; i < n; i++) {
        bn_null(F[i]);
        bn_new(F[i]);
    }

    bn_t tmpbn;
    bn_null(tmpbn);
    bn_new(tmpbn);

    bn_t ex;
    bn_null(ex);
    bn_new(ex);
    bn_mul(ex, proof->e, proof->x);
    bn_mod(ex, ex, pk->q);

    bn_t einv;
    bn_null(einv);
    bn_new(einv);
    bn_inv_mod(einv, proof->e, pk->q);

    // F[0] = f_0 - ex
    bn_sub(F[0], proof->f[0], ex);
    bn_mod(F[0], F[0], pk->q);

    for(int i = 1; i < n; i++) {
        bn_sub(tmpbn, proof->f[i], ex);
        bn_mul(F[i], F[i - 1], tmpbn);
        bn_add(F[i], F[i], proof->fdelta[i - 1]);
        bn_mul(F[i], F[i], einv);
        bn_mod(F[i], F[i], pk->q);
    }

    bn_t Fn;
    bn_null(Fn);
    bn_new(Fn);
    bn_copy(Fn, proof->e);
    for(int i = 0; i < n; i++) {
        bn_sub(tmpbn, vals[i], proof->x);
        bn_mul(Fn, Fn, tmpbn);
        bn_mod(Fn, Fn, pk->q);
    }

    if(bn_cmp(Fn, F[n - 1]) != CMP_EQ) {
        printf("Check of Fn failed!");
        return 0;
    }

    return 1;
}

void
shuffle_elgamal_keygen(struct shuffle_elgamal_pk *pk,
        struct shuffle_elgamal_sk *sk) {
    bn_null(pk->q);
    bn_new(pk->q);
    g1_get_ord(pk->q);

    bn_null(sk->sk);
    bn_new(sk->sk);
    bn_rand_mod(sk->sk, pk->q);

    g1_null(pk->gen);
    g1_new(pk->gen);
    g1_get_gen(pk->gen);

    g1_null(pk->pk);
    g1_new(pk->pk);
    g1_mul(pk->pk, pk->gen, sk->sk);
}

size_t
shuffle_known_proof_size(struct shuffle_known_proof *p) {
    size_t res = 0;

    res += sizeof(size_t);

    res += bn_size_bin(p->x);
    res += bn_size_bin(p->e);

    res += shuffle_commit_size(&p->cd);
    res += shuffle_commit_size(&p->cdelta);
    res += shuffle_commit_size(&p->ca);

    for(int i = 0; i < p->n; i++) {
        res += bn_size_bin(p->f[i]);
        res += bn_size_bin(p->fdelta[i]);
    }

    res += bn_size_bin(p->z);
    res += bn_size_bin(p->zdelta);

    return res;
}


void
shuffle_elgamal_init(struct shuffle_elgamal_ctxt *ctxt, size_t n) {
    ctxt->n = n;

    // TODO: for now n = 1,2
    // ctxt->c1 = malloc(n * sizeof(g1_t));
    // ctxt->c2 = malloc(n * sizeof(g1_t));

    for(int i = 0; i < n; i++) {
        g1_null(ctxt->c1[i]);
        g1_new(ctxt->c1[i]);
        g1_null(ctxt->c2[i]);
        g1_new(ctxt->c2[i]);
    }
}

size_t
shuffle_elgamal_size(struct shuffle_elgamal_ctxt *ctxt) {
    // TODO: also encode size?

    size_t size = 0;

    // TODO it is better to use a more uniform encoding of elements
    // where you always use the same number of bytes, but for now
    // just use the individual sizes
    for(int i = 0; i < ctxt->n; i++) {
        size += g1_size_bin(ctxt->c1[i], 1);
        size += g1_size_bin(ctxt->c2[i], 1);
    }

    return size;
}

size_t
shuffle_elgamal_pk_size(struct shuffle_elgamal_pk *pk) {
    return g1_size_bin(pk->gen, 1) + g1_size_bin(pk->pk, 1);
}


void
shuffle_elgamal_write_bin(uint8_t *ptr, struct shuffle_elgamal_ctxt *ctxt) {
    size_t elem_size;

    for(int i = 0; i < ctxt->n; i++) {
        elem_size = g1_size_bin(ctxt->c1[i], 1);
        g1_write_bin(ptr, elem_size, ctxt->c1[i], 1);
        ptr += elem_size;
        elem_size = g1_size_bin(ctxt->c2[i], 1);
        g1_write_bin(ptr, elem_size, ctxt->c2[i], 1);
        ptr += elem_size;
    }
}

void
shuffle_elgamal_randomizer_init(struct shuffle_elgamal_randomizer *rand,
        struct shuffle_elgamal_ctxt *ctxt) {
    rand->n = ctxt->n;

    for(int i = 0; i < rand->n; i++) {
        bn_null(rand->rand[i]);
        bn_new(rand->rand[i]);
    }
}

void
shuffle_elgamal_randomizer(struct shuffle_elgamal_randomizer *rand,
        struct shuffle_elgamal_ctxt *ctxt,
        struct shuffle_elgamal_pk *pk) {
    rand->n = ctxt->n;

    for(int i = 0; i < rand->n; i++) {
        bn_null(rand->rand[i]);
        bn_new(rand->rand[i]);
        bn_rand_mod(rand->rand[i], pk->q);
    }
}

void
shuffle_elgamal_randomizer_copy(struct shuffle_elgamal_randomizer *rand,
        struct shuffle_elgamal_randomizer *orig) {
    rand->n = orig->n;

    for(int i = 0; i < rand->n; i++) {
        bn_copy(rand->rand[i], orig->rand[i]);
    }
}

void
shuffle_elgamal_randomizer_multiply(
        struct shuffle_elgamal_randomizer *res,
        struct shuffle_elgamal_randomizer *a,
        bn_t t, struct shuffle_elgamal_pk *pk) {
    res->n = a->n;

    for(int i = 0; i < a->n; i++) {
        bn_mul(res->rand[i], a->rand[i], t);
        bn_mod(res->rand[i], res->rand[i], pk->q);
    }
}

void
shuffle_elgamal_randomizer_add(
        struct shuffle_elgamal_randomizer *res,
        struct shuffle_elgamal_randomizer *a,
        struct shuffle_elgamal_randomizer *b,
        struct shuffle_elgamal_pk *pk) {
    res->n = a->n;

    for(int i = 0; i < a->n; i++) {
        bn_add(res->rand[i], a->rand[i], b->rand[i]);
        bn_mod(res->rand[i], res->rand[i], pk->q);
    }
}

size_t
shuffle_elgamal_randomizer_size( struct shuffle_elgamal_randomizer *rand) {
    size_t res = 0;

    for(int i = 0; i < rand->n; i++) {
        res += bn_size_bin(rand->rand[i]);
    }

    return res;
}

void
shuffle_elgamal_randomizer_write_bin(uint8_t *ptr,
        struct shuffle_elgamal_randomizer *rand) {
    size_t elem_size;

    for(int i = 0; i < rand->n; i++) {
        elem_size = bn_size_bin(rand->rand[i]);
        bn_write_bin(ptr, elem_size, rand->rand[i]);
        ptr += elem_size;
    }
}

void
shuffle_elgamal_empty_ctxt(struct shuffle_elgamal_ctxt *ctxt,
        const struct shuffle_elgamal_randomizer *rand,
        const struct shuffle_elgamal_pk *pk) {

    for(int i = 0; i < rand->n; i++) {
        g1_mul(ctxt->c1[i], pk->pk, rand->rand[i]);
        g1_mul(ctxt->c2[i], pk->gen, rand->rand[i]);
    }
}

void
shuffle_elgamal_encrypt(struct shuffle_elgamal_ctxt *ctxt,
        g1_t *msgs, size_t n, struct shuffle_elgamal_pk *pk) {

    shuffle_elgamal_init(ctxt, n);

    bn_t rand;
    bn_null(rand);
    bn_new(rand);

    for(int i = 0; i < n; i++) {
        bn_rand_mod(rand, pk->q);
        g1_mul(ctxt->c1[i], pk->pk, rand);
        g1_add(ctxt->c1[i], ctxt->c1[i], msgs[i]);

        g1_mul(ctxt->c2[i], pk->gen, rand);
    }
}

void
shuffle_elgamal_encrypt_with_randomizer(
        struct shuffle_elgamal_ctxt *ctxt, g1_t *msgs,
        size_t n, struct shuffle_elgamal_randomizer *rand,
        struct shuffle_elgamal_pk *pk) {

    shuffle_elgamal_init(ctxt, n);

    for(int i = 0; i < n; i++) {
        g1_mul(ctxt->c1[i], pk->pk, rand->rand[i]);
        g1_add(ctxt->c1[i], ctxt->c1[i], msgs[i]);
        g1_mul(ctxt->c2[i], pk->gen, rand->rand[i]);
    }
}

void
shuffle_elgamal_decrypt(g1_t *msgs,
        struct shuffle_elgamal_ctxt *ctxt,
        struct shuffle_elgamal_sk *sk) {

    g1_t tmp;
    g1_null(tmp);
    g1_new(tmp);

    for(int i = 0; i < ctxt->n; i++) {
        g1_null(msgs[i]);
        g1_new(msgs[i]);

        g1_mul(tmp, ctxt->c2[i], sk->sk);
        g1_sub(msgs[i], ctxt->c1[i], tmp);
    }
}

void
shuffle_elgamal_copy(struct shuffle_elgamal_ctxt *ctxt,
        struct shuffle_elgamal_ctxt *orig) {
    ctxt->n = orig->n;

    for(int i = 0; i < orig->n; i++) {
        g1_copy(ctxt->c1[i], orig->c1[i]);
        g1_copy(ctxt->c2[i], orig->c2[i]);
    }
}

void
shuffle_elgamal_multiply(struct shuffle_elgamal_ctxt *res,
        const struct shuffle_elgamal_ctxt *a,
        const struct shuffle_elgamal_ctxt *b) {

    res->n = a->n;
    for(int i = 0; i < a->n; i++) {
        g1_add(res->c1[i], a->c1[i], b->c1[i]);
        g1_add(res->c2[i], a->c2[i], b->c2[i]);
    }
}

void shuffle_elgamal_exp(struct shuffle_elgamal_ctxt *res,
        const struct shuffle_elgamal_ctxt *a,
        const bn_t exp) {

    // TODO: fix problems with negative exponents, only properly
    // works if exp < group order, needs to be fixed by RELIC instead
    bn_t tmp;
    bn_null(tmp);
    bn_new(tmp);
    if(bn_sign(exp) == BN_NEG) {
        g1_get_ord(tmp);
        bn_add(tmp, tmp, exp);
    } else {
        bn_copy(tmp, exp);
    }

    res->n = a->n;
    for(int i = 0; i < a->n; i++) {
        g1_mul(res->c1[i], a->c1[i], tmp);
        g1_mul(res->c2[i], a->c2[i], tmp);
    }
}

void
shuffle_elgamal_derandomize( struct shuffle_elgamal_ctxt *res,
        struct shuffle_elgamal_ctxt *a, bn_t rand) {

    g1_t tmp;
    g1_null(tmp);
    g1_new(tmp);

    for(int i = 0; i < a->n; i++) {
        g1_mul(tmp, a->c2[i], rand);
        g1_sub(res->c1[i], a->c1[i], tmp);
        g1_copy(res->c2[i], a->c2[i]);
    }
}

void
shuffle_elgamal_print(struct shuffle_elgamal_ctxt *ctxt) {
    printf("Ciphertext:\n");
    for(int i = 0; i < ctxt->n; i++) {
        g1_norm(ctxt->c1[i], ctxt->c1[i]);
        g1_norm(ctxt->c2[i], ctxt->c2[i]);

        printf("c1[%i]: ", i); g1_print(ctxt->c1[i]);
        printf("c2[%i]: ", i); g1_print(ctxt->c2[i]);
    }
}

int
shuffle_elgamal_equal(struct shuffle_elgamal_ctxt *left,
        struct shuffle_elgamal_ctxt *right) {
    int cmp = 0;

    for(int i = 0; i < left->n; i++) {
        // Normalizing components, should be done in RELIC
        g1_norm(left->c1[i], left->c1[i]);
        g1_norm(left->c2[i], left->c2[i]);
        g1_norm(right->c1[i], right->c1[i]);
        g1_norm(right->c2[i], right->c2[i]);

        cmp += (g1_cmp(left->c1[i], right->c1[i]) != CMP_EQ);
        cmp += (g1_cmp(left->c2[i], right->c2[i]) != CMP_EQ);
    }

    return (cmp == 0);
}

void
shuffle_and_randomize( struct shuffle_elgamal_ctxt *e,
        struct shuffle_elgamal_ctxt **E_res,
        struct shuffle_elgamal_randomizer **rand_res,
        unsigned int **perm_res,
        size_t n, struct shuffle_elgamal_pk *pk) {

    size_t nr_components = e->n;

    struct shuffle_elgamal_ctxt *E =
        malloc(n * sizeof(struct shuffle_elgamal_ctxt));
    *E_res = E;

    struct shuffle_elgamal_randomizer *rand =
        malloc(n * sizeof(struct shuffle_elgamal_randomizer));
    *rand_res = rand;

    unsigned int *perm = malloc(n * sizeof(unsigned int));
    unsafe_random_permutation(&perm[0], n);
    *perm_res = perm;

    struct shuffle_elgamal_ctxt randomizer_ctxt;
    shuffle_elgamal_init(&randomizer_ctxt, nr_components);

    for(int i = 0; i < n; i++) {
        shuffle_elgamal_init(E + i, nr_components);
        shuffle_elgamal_randomizer(rand + i, e, pk);
        shuffle_elgamal_empty_ctxt(&randomizer_ctxt, rand + i, pk);
        shuffle_elgamal_multiply(E + i, e + perm[i], &randomizer_ctxt);
    }
}

void
shuffle_proof_hash_seedti(uint8_t *seedti, struct shuffle_com *c,
        struct shuffle_com *cd,
        struct shuffle_elgamal_ctxt *Ed,
        struct shuffle_elgamal_ctxt *e, struct shuffle_elgamal_ctxt *E,
        size_t n, uint8_t *context, size_t lcontext) {

    size_t lctxts = 0;
    for(int i = 0; i < n; i++) {
        lctxts += shuffle_elgamal_size(e + i);
        lctxts += shuffle_elgamal_size(E + i);
    }
    lctxts += shuffle_elgamal_size(Ed);

    size_t lcom = shuffle_commit_size(c);

    size_t input_len = lctxts + 2 * lcom + lcontext;

    uint8_t *input = malloc(input_len);
    uint8_t *iptr = input;

    memcpy(iptr, context, lcontext);
    iptr += lcontext;

    size_t lctxt;
    for(int i = 0; i < n; i++) {
        lctxt = shuffle_elgamal_size(e + i);
        shuffle_elgamal_write_bin(iptr, e + i);
        iptr += lctxt;
    }

    for(int i = 0; i < n; i++) {
        lctxt = shuffle_elgamal_size(E + i);
        shuffle_elgamal_write_bin(iptr, E + i);
        iptr += lctxt;
    }

    shuffle_commit_write_bin(iptr, lcom, c);
    iptr += lcom;

    shuffle_commit_write_bin(iptr, lcom, cd);
    iptr += lcom;

    lctxt = shuffle_elgamal_size(Ed);
    shuffle_elgamal_write_bin(iptr, Ed);
    iptr += lctxt;

    md_map_sh256(seedti, input, input_len);
}

void
shuffle_proof_lambdabase(uint8_t *lambdabase, bn_t *f, size_t n,
        struct shuffle_elgamal_randomizer *Z, uint8_t *seedti) {

    size_t lrand = shuffle_elgamal_randomizer_size(Z);
    size_t lseedti = MD_LEN_SH256;

    size_t lfs = 0;
    // TODO: this is not completely secure, as the inputs are not separated
    for(int i = 0; i < n; i++) {
        lfs += bn_size_bin(f[i]);
    }

    size_t input_len = lfs + lrand + lseedti;

    uint8_t *input = malloc(input_len);
    uint8_t *iptr = input;

    memcpy(iptr, seedti, lseedti);
    iptr += lseedti;

    size_t lbn;
    for(int i = 0; i < n; i++) {
        lbn = bn_size_bin(f[i]);
        bn_write_bin(iptr, lbn, f[i]);
        iptr += lbn;
    }

    shuffle_elgamal_randomizer_write_bin(iptr, Z);

    md_map_sh256(lambdabase, input, input_len);
}

void
shuffle_proof_derive_lambda(bn_t lambda, uint8_t *lambdabase) {
    bn_read_bin(lambda, lambdabase, SHUFFLE_LENGTH_E / 8);
}

void
shuffle_compute_lhs_commitment(struct shuffle_com *lhs,
        bn_t **knowns_res, struct shuffle_com *c,
        struct shuffle_com *cd, bn_t lambda, bn_t *t,
        bn_t *f, size_t n, struct shuffle_com_pk *ck) {
    // Compute input to subprotocol

    bn_t bn_zero;
    bn_null(bn_zero);
    bn_new(bn_zero);
    bn_set_dig(bn_zero, 0);

    shuffle_commit_new(lhs, n);

    struct shuffle_com tmp_com;
    shuffle_commit_new(&tmp_com, n);

    shuffle_commit_to(&tmp_com, f, n, bn_zero, ck);
    shuffle_commit_mul(lhs, &tmp_com, cd);
    shuffle_commit_exp(&tmp_com, c, lambda);
    shuffle_commit_mul(lhs, lhs, &tmp_com);

    // Calculate known values used in the shuffle proof
    bn_t *knowns = malloc(n * sizeof(bn_t));
    *knowns_res = knowns;
    for(int i = 0; i < n; i++) {
        bn_null(knowns[i]);
        bn_new(knowns[i]);
        bn_mul_dig(knowns[i], lambda, i);
        bn_add(knowns[i], knowns[i], t[i]);
        bn_mod(knowns[i], knowns[i], ck->q);
    }
}

void
shuffle_prove(struct shuffle_proof *proof,
        struct shuffle_elgamal_ctxt *e, struct shuffle_elgamal_ctxt *E,
        size_t n, struct shuffle_elgamal_pk *pk, struct shuffle_com_pk *ck,
        unsigned int *perm, struct shuffle_elgamal_randomizer *R,
        uint8_t *context, size_t lcontext) {

    bn_t r;
    bn_null(r);
    bn_new(r);
    bn_rand_mod(r, pk->q);

    proof->n = n;

    struct shuffle_elgamal_randomizer Rd;
    shuffle_elgamal_randomizer(&Rd, e, pk);

    // Note storing -d[i]!
    bn_t *d = malloc(n * sizeof(bn_t));
    for(int i = 0; i < n; i++) {
        bn_null(d[i]);
        bn_new(d[i]);
        bn_rand(d[i], BN_NEG, SHUFFLE_LENGTH_E + SHUFFLE_LENGTH_S);
    }

    bn_t rd;
    bn_null(rd);
    bn_new(rd);
    bn_rand_mod(rd, pk->q);

    bn_t *bn_perm = malloc(n * sizeof(bn_t));
    for(int i = 0; i < n; i++) {
        bn_null(bn_perm[i]);
        bn_new(bn_perm[i]);
        bn_set_dig(bn_perm[i], perm[i]); // TODO: This might cause problems
                                         // if int doesn't align with digit
    }

    shuffle_commit_new(&proof->c, n);
    shuffle_commit_to(&proof->c, bn_perm, n, r, ck);

    shuffle_commit_new(&proof->cd, n);
    shuffle_commit_to(&proof->cd, d, n, rd, ck);

    // Calculate Ed
    struct shuffle_elgamal_ctxt ctxt_tmp;
    shuffle_elgamal_init(&ctxt_tmp, e->n);

    shuffle_elgamal_init(&proof->Ed, e->n);
    shuffle_elgamal_empty_ctxt(&proof->Ed, &Rd, pk);
    for(int i = 0; i < n; i++) {
        shuffle_elgamal_exp(&ctxt_tmp, E + i, d[i]);
        shuffle_elgamal_multiply(&proof->Ed, &proof->Ed, &ctxt_tmp);
    }

    // Calculate first set of challenges
    shuffle_proof_hash_seedti(&proof->tseed[0], &proof->c, &proof->cd, &proof->Ed,
            e, E, n, context, lcontext);
    bn_t *t = malloc(n * sizeof(bn_t));
    bn_rands_from_stream(t, n, SHUFFLE_LENGTH_E / 8, &proof->tseed[0]);

    // Calculate first responses
    proof->f = malloc(n * sizeof(bn_t));
    for(int i = 0; i < n; i++) {
        bn_null(proof->f[i]);
        bn_new(proof->f[i]);
        bn_sub(proof->f[i], t[perm[i]], d[i]); // Because d[i] encodes negative values
    }

    struct shuffle_elgamal_randomizer tmp_rand;
    shuffle_elgamal_randomizer_init(&proof->Z, e);
    shuffle_elgamal_randomizer_init(&tmp_rand, e);

    shuffle_elgamal_randomizer_copy(&proof->Z, &Rd);
    for(int i = 0; i < n; i++) {
        shuffle_elgamal_randomizer_multiply(&tmp_rand, R + i, t[perm[i]], pk);
        shuffle_elgamal_randomizer_add(&proof->Z, &proof->Z, &tmp_rand, pk);
    }

    // Calculate second challenge
    shuffle_proof_lambdabase(&proof->lambdabase[0], proof->f, n,
            &proof->Z, proof->tseed);

    bn_t lambda;
    bn_null(lambda);
    bn_new(lambda);
    shuffle_proof_derive_lambda(lambda, &proof->lambdabase[0]);

    // Compute input to subprotocol
    struct shuffle_com lhs;
    bn_t *knowns;
    shuffle_compute_lhs_commitment(&lhs, &knowns, &proof->c,
            &proof->cd, lambda, t, proof->f, n, ck);

    // Calculate derived randomizer
    bn_t rho;
    bn_null(rho);
    bn_new(rho);

    // rho = lambda * r + rd
    bn_mul(rho, lambda, r);
    bn_add(rho, rho, rd);

    bn_mod(rho, rho, pk->q);

    shuffle_prove_known_content(&proof->known_proof, &lhs, rho,
            knowns, n, perm, ck, proof->lambdabase, MD_LEN_SH256);
}

int
shuffle_proof_verify(struct shuffle_proof *proof,
        struct shuffle_elgamal_ctxt *e, struct shuffle_elgamal_ctxt *E,
        size_t n, struct shuffle_elgamal_pk *pk, struct shuffle_com_pk *ck,
        uint8_t *context, size_t lcontext) {

    // TODO: Check if c, cd are valid commits, if Ed is a valid ciphertext

    // Verify ranges for f[i]
    bn_t twole, twolels;
    bn_null(twole);
    bn_new(twole);
    bn_set_2b(twole, SHUFFLE_LENGTH_E);
    bn_null(twolels);
    bn_new(twolels);
    bn_set_2b(twolels, SHUFFLE_LENGTH_E + SHUFFLE_LENGTH_S);

    for(int i = 0; i < n; i++) {
        // 2^le > f[i] or f[i] >= 2^{le + ls}
        if( bn_cmp(twole, proof->f[i]) == CMP_GT ||
                bn_cmp(proof->f[i], twolels) != CMP_LT ) {
            printf("f[%i] outside of range!\n", i);
            return 0;
        }
    }

    // TODO: check that Z is a randomizer

    // Verify Fiat-Shamir heuristic
    uint8_t tseed[MD_LEN_SH256];
    shuffle_proof_hash_seedti(tseed, &proof->c, &proof->cd, &proof->Ed,
            e, E, n, context, lcontext);
    if( memcmp(tseed, proof->tseed, MD_LEN_SH256) != 0 ) {
        printf("Incorrect tseed recovered\n");
        return 0;
    }

    uint8_t lambdabase[MD_LEN_SH256];
    shuffle_proof_lambdabase(lambdabase, proof->f, n,
            &proof->Z, proof->tseed);
    if( memcmp(lambdabase, proof->lambdabase, MD_LEN_SH256) != 0 ) {
        printf("Incorrect lambdabase recovered\n");
        return 0;
    }

    // Rebuild inputs to known shuffle proof

    bn_t lambda;
    bn_null(lambda);
    bn_new(lambda);
    shuffle_proof_derive_lambda(lambda, proof->lambdabase);

    bn_t *t = malloc(n * sizeof(bn_t));
    bn_rands_from_stream(t, n, SHUFFLE_LENGTH_E / 8, &proof->tseed[0]);

    // Verify known shuffle proof

    // Recompute inputs to known-shuffle argument
    struct shuffle_com lhs;
    bn_t *knowns;
    shuffle_compute_lhs_commitment(&lhs, &knowns, &proof->c,
            &proof->cd, lambda, t, proof->f, n, ck);

    if(!shuffle_verify_known_content_proof(&proof->known_proof, &lhs, knowns, n,
                ck, proof->lambdabase, MD_LEN_SH256)) {
        printf("Known shuffle proof does not verify!!");
        return 0;
    }

    // Verifying product of ciphertexts
    struct shuffle_elgamal_ctxt lhs_ctxt;
    struct shuffle_elgamal_ctxt tmp_ctxt;
    struct shuffle_elgamal_ctxt rhs_ctxt;

    shuffle_elgamal_init(&lhs_ctxt, e->n);
    shuffle_elgamal_init(&tmp_ctxt, e->n);
    shuffle_elgamal_init(&rhs_ctxt, e->n);

    bn_t tmpbn;
    bn_null(tmpbn);
    bn_new(tmpbn);

    shuffle_elgamal_copy(&lhs_ctxt, &proof->Ed);
    for(int i = 0; i < n; i++) {
        // tmpbn = -t[i] (mod q)
        bn_sub(tmpbn, pk->q, t[i]);
        shuffle_elgamal_exp(&tmp_ctxt, e + i, tmpbn);
        shuffle_elgamal_multiply(&lhs_ctxt, &lhs_ctxt, &tmp_ctxt);
    }
    for(int i = 0; i < n; i++) {
        shuffle_elgamal_exp(&tmp_ctxt, E + i, proof->f[i]);
        shuffle_elgamal_multiply(&lhs_ctxt, &lhs_ctxt, &tmp_ctxt);
    }

    shuffle_elgamal_empty_ctxt(&rhs_ctxt, &proof->Z, pk);

    if( !shuffle_elgamal_equal(&lhs_ctxt, &rhs_ctxt)) {
        printf("Ciphertext product does not compare!\n");
        return 0;
    }

    return 1;
}

size_t
shuffle_proof_size(struct shuffle_proof *p) {
    size_t res = 0;

    res += shuffle_commit_size(&p->c);
    res += shuffle_commit_size(&p->cd);
    res += shuffle_elgamal_size(&p->Ed);

    res += MD_LEN_SH256;

    for(int i = 0; i < p->n; i++) {
        res += bn_size_bin(p->f[i]);
    }

    res += MD_LEN_SH256;
    res += shuffle_known_proof_size(&p->known_proof);

    return res;
}
