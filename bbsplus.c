#include "bbsplus.h"
#include "utils.h"

#include <stdio.h>
#include <relic/relic.h>

void
bbsplus_keygen(struct bbsplus_pk *pk, struct bbsplus_sk *sk, size_t nr_attributes) {
    // Setting group order
    bn_null(pk->q);
    bn_new(pk->q);
    g1_get_ord(pk->q);

    // Generate private key
    bn_null(sk->x);
    bn_new(sk->x);
    bn_rand_mod(sk->x, pk->q);

    g2_null(pk->w);
    g2_new(pk->w);
    g2_mul_gen(pk->w, sk->x);

    pk->bases = malloc((nr_attributes + 1) * sizeof(g1_t));
    for(int i = 0; i <= nr_attributes; i++) {
        g1_null(pk->bases[i]);
        g1_new(pk->bases[i]);
        g1_rand(pk->bases[i]);
    }
    pk->nr_bases = nr_attributes + 1;

    g1_null(pk->g1bar);
    g1_new(pk->g1bar);
    g1_rand(pk->g1bar);

    // Phat = (e(C1, g2)^{-1})^{ehat} * e(base[0], g2)^{shat} *
    //        e(g1bar, pk->w)^{r1hat} * e(g1bar, g2)^{a1hat} *
    //        prod_{i = 1}^{L} e(base[i], g2)^{mhat[i-1]}
    
    // Precompute some of the pairing values
    gt_null(pk->pairing_g1bar_w);
    gt_new(pk->pairing_g1bar_w);
    pc_map(pk->pairing_g1bar_w, pk->g1bar, pk->w);

    g1_t g1;
    g1_null(g1);
    g1_new(g1);
    g1_get_gen(g1);

    g2_t g2;
    g2_null(g2);
    g2_new(g2);
    g2_get_gen(g2);

    gt_null(pk->pairing_g1bar_g2);
    gt_new(pk->pairing_g1bar_g2);
    pc_map(pk->pairing_g1bar_g2, pk->g1bar, g2);

    gt_null(pk->pairing_g1_g2);
    gt_new(pk->pairing_g1_g2);
    pc_map(pk->pairing_g1_g2, g1, g2);
    
    pk->pairing_bases_g2 = malloc((nr_attributes + 1) * sizeof(gt_t));
    for(int i = 0; i <= nr_attributes; i++) {
        gt_null(pk->pairing_bases_g2[i]);
        gt_new(pk->pairing_bases_g2[i]);
        pc_map(pk->pairing_bases_g2[i], pk->bases[i], g2);
    }
}

void
bbsplus_pk_free(struct bbsplus_pk *pk) {
    for(int i = 0; i < pk->nr_bases; i++) {
        g1_free(pk->bases[i]);
    }
    free(pk->bases);

    g2_free(pk->g1_bar);
    bn_free(pk->q);

    gt_free(pk->pairing_g1_g2);
    gt_free(pk->pairing_g1bar_w);
    gt_free(pk->pairing_g1bar_g2);

    for(int i = 0; i < pk->nr_bases; i++) {
        gt_free(pk->pairing_bases_g2[i]);
    }
    free(pk->pairing_bases_g2);
}

void
bbsplus_sk_free(struct bbsplus_sk *sk) {
    bn_free(sk->x);
}

void
bbsplus_represent(g1_t A, struct bbsplus_pk *pk, bn_t s, bn_t *msgs, size_t nr_msgs) {
    g1_t tmp;
    g1_null(tmp);
    g1_new(tmp);

    g1_null(A);
    g1_new(A);
    g1_get_gen(A);

    g1_mul(tmp, pk->bases[0], s); 
    g1_add(A, A, tmp);

    for(int i = 1; i <= nr_msgs; i++) {
        g1_mul(tmp, pk->bases[i], msgs[i - 1]); 
        g1_add(A, A, tmp);
    }

    g1_free(tmp);
}


void
bbsplus_sign(struct bbsplus_sign *sign, struct bbsplus_pk *pk, struct bbsplus_sk *sk,
        bn_t *msgs, size_t nr_msgs) {
    bn_null(sign->e);
    bn_new(sign->e);
    bn_null(sign->s);
    bn_new(sign->s);

    bn_rand_mod(sign->e, pk->q);
    bn_rand_mod(sign->s, pk->q);

    bbsplus_represent(sign->A, pk, sign->s,  msgs, nr_msgs);

    bn_t exp;
    bn_null(exp);
    bn_new(exp);
    bn_add(exp, sk->x, sign->e);
    bn_mod(exp, exp, pk->q);
    bn_inv_mod(exp, exp, pk->q);
    g1_mul(sign->A, sign->A, exp);
}

int
bbsplus_verify(struct bbsplus_sign *sign, struct bbsplus_pk *pk, bn_t *msgs, size_t nr_msgs) {
    g1_t rep;
    g1_null(rep);
    g1_new(rep);

    g2_t g2;
    g2_null(g2);
    g2_new(g2);
    g2_get_gen(g2);

    g2_t tmp;
    g2_null(tmp);
    g2_new(tmp);

    gt_t gt1, gt2;
    gt_null(gt1);
    gt_new(gt1);
    gt_null(gt2);
    gt_new(gt2);

    g2_mul_gen(tmp, sign->e);
    g2_add(tmp, tmp, pk->w);
    pc_map(gt1, sign->A, tmp);

    bbsplus_represent(rep, pk, sign->s, msgs, nr_msgs);
    pc_map(gt2, rep, g2);

    int result = gt_cmp(gt1, gt2) == CMP_EQ;

    g1_free(rep);
    g1_free(g2);
    g1_free(tmp);
    g1_free(gt1);
    g1_free(gt2);

    return result;
}

void
bbsplus_prove(struct bbsplus_proof *proof,
        struct bbsplus_sign *sign, struct bbsplus_pk *pk, bn_t *msgs,
        size_t nr_msgs, uint8_t *L, size_t lL) {

    struct bbsplus_proof_randomizers rand;
    struct bbsplus_proof_commitments coms;

    bn_t c;

    bbsplus_proof_randomizers(&rand, pk, nr_msgs);
    bbsplus_proof_commitments(&coms, &rand, sign, pk, nr_msgs);
    bbsplus_proof_challenge(c, &coms, L, lL);
    bbsplus_proof_create(proof, &rand, &coms, sign, msgs, pk, c, nr_msgs);

    bbsplus_proof_randomizers_free(&rand);
    bbsplus_proof_commitments_free(&coms);
    bn_free(c);
}

void
bbsplus_proof_randomizers(struct bbsplus_proof_randomizers *rand,
        struct bbsplus_pk *pk, size_t nr_msgs) {

    bn_null(rand->r1);
    bn_new(rand->r1);
    bn_rand_mod(rand->r1, pk->q);

    bn_null(rand->r2);
    bn_new(rand->r2);
    bn_rand_mod(rand->r2, pk->q);

    bn_null(rand->r1hat);
    bn_new(rand->r1hat);
    bn_rand_mod(rand->r1hat, pk->q);

    bn_null(rand->r2hat);
    bn_new(rand->r2hat);
    bn_rand_mod(rand->r2hat, pk->q);

    bn_null(rand->a1hat);
    bn_new(rand->a1hat);
    bn_rand_mod(rand->a1hat, pk->q);

    bn_null(rand->a2hat);
    bn_new(rand->a2hat);
    bn_rand_mod(rand->a2hat, pk->q);

    bn_null(rand->ehat);
    bn_new(rand->ehat);
    bn_rand_mod(rand->ehat, pk->q);

    bn_null(rand->shat);
    bn_new(rand->shat);
    bn_rand_mod(rand->shat, pk->q);

    rand->mhat = malloc(nr_msgs * sizeof(bn_t));
    for(int i = 0; i < nr_msgs; i++) {
        bn_null(rand->mhat[i]);
        bn_new(rand->mhat[i]);
        bn_rand_mod(rand->mhat[i], pk->q);
    }

    rand->nr_msgs = nr_msgs;
}

void
bbsplus_proof_randomizers_free(struct bbsplus_proof_randomizers *rand) {
    bn_free(r1);
    bn_free(r2);

    bn_free(r1hat);
    bn_free(r2hat);

    bn_free(a1hat);
    bn_free(a2hat);

    bn_free(ehat);
    bn_free(shat);

    for(int i = 0; i < rand->nr_msgs; i++) {
        bn_free(rand->mhat[i]);
    }
    free(rand->mhat);
}


void
bbsplus_proof_commitments(struct bbsplus_proof_commitments *coms,
        struct bbsplus_proof_randomizers *rand, struct bbsplus_sign *sign,
        struct bbsplus_pk *pk, size_t nr_msgs) {

    // First commit to the signature
    g1_t tmp1;
    g1_null(tmp1);
    g1_new(tmp1);

    // C1 = A * g1bar^r1
    g1_null(coms->C1);
    g1_new(coms->C1);
    g1_mul(tmp1, pk->g1bar, rand->r1);
    g1_add(coms->C1, sign->A, tmp1);
    // printf("+++ C1: \n"); g1_norm(coms->C1, coms->C1); g1_print(coms->C1);

    // C2 = g1^r1 * g1bar^r2
    g1_null(coms->C2);
    g1_new(coms->C2);
    g1_mul_gen(coms->C2, rand->r1);
    g1_mul(tmp1, pk->g1bar, rand->r2);
    g1_add(coms->C2, coms->C2, tmp1);
    // printf("+++ C2: \n"); g1_norm(coms->C2, coms->C2); g1_print(coms->C2);

    // Initialize and compute commitments

    // coms->C2hat = g1^{r1hat} * g1bar^{r2hat}
    g1_null(coms->C2hat);
    g1_new(coms->C2hat);
    g1_mul_gen(coms->C2hat, rand->r1hat);
    g1_mul(tmp1, pk->g1bar, rand->r2hat);
    g1_add(coms->C2hat, coms->C2hat, tmp1);
    // printf("+++ C2hat: \n"); g1_norm(coms->C2hat, coms->C2hat); g1_print(coms->C2hat);

    // C2neg = C2^{-1}
    g1_t C2neg;
    g1_null(C2neg);
    g1_new(C2neg);
    g1_neg(C2neg, coms->C2);

    // coms->C2hathat = C2neg^{ehat} * g1^{a1hat} * g1bar^{a2hat}
    g1_null(coms->C2hathat);
    g1_new(coms->C2hathat);
    g1_mul_gen(coms->C2hathat, rand->a1hat);
    g1_mul(tmp1, pk->g1bar, rand->a2hat);
    g1_add(coms->C2hathat, coms->C2hathat, tmp1);
    g1_mul(tmp1, C2neg, rand->ehat);
    g1_add(coms->C2hathat, coms->C2hathat, tmp1);
    // printf("+++ C2hathat: \n"); g1_norm(coms->C2hathat, coms->C2hathat); g1_print(coms->C2hathat);

    // Phat = (e(C1, g2)^{-1})^{ehat} * e(base[0], g2)^{shat} *
    //        e(g1bar, pk->w)^{r1hat} * e(g1bar, g2)^{a1hat} *
    //        prod_{i = 1}^{L} e(base[i], g2)^{mhat[i-1]}
    gt_null(coms->Phat);
    gt_new(coms->Phat);

    gt_t tmpt;
    gt_null(tmpt);
    gt_new(tmpt);

    g2_t g2;
    g2_null(g2);
    g2_new(g2);
    g2_get_gen(g2);

    // (e(C1, g2)^{-1})^{ehat}
    pc_map(tmpt, coms->C1, g2);
    gt_inv(tmpt, tmpt);
    gt_exp(coms->Phat, tmpt, rand->ehat);

    // e(base[0], g2)^{shat}
    gt_exp(tmpt, pk->pairing_bases_g2[0], rand->shat);
    gt_mul(coms->Phat, coms->Phat, tmpt);

    // e(g1bar, pk->w)^{r1hat}
    gt_exp(tmpt, pk->pairing_g1bar_w, rand->r1hat);
    gt_mul(coms->Phat, coms->Phat, tmpt);

    // e(g1bar, g2)^{a1hat}
    gt_exp(tmpt, pk->pairing_g1bar_g2, rand->a1hat);
    gt_mul(coms->Phat, coms->Phat, tmpt);

    for(int i = 1; i <= nr_msgs; i++) {
        // e(base[i], g2)^{mhat[i-1]}
        gt_exp(tmpt, pk->pairing_bases_g2[i], rand->mhat[i - 1]);
        gt_mul(coms->Phat, coms->Phat, tmpt);
    }
    // printf("+++ Phat:\n"); gt_print(coms->Phat);

    g1_free(tmp1);
    g1_free(C2neg);
    gt_free(tmpt);
    g2_free(g2);
}

void
bbsplus_proof_commitments_free(struct bbsplus_proof_commitments *coms) {
    g1_free(coms->C1);
    g1_free(coms->C2);
    g1_free(coms->C2hat);
    g1_free(coms->C2hathat);

    gt_free(Phat);
}

int
bbsplus_proof_commitments_size(struct bbsplus_proof_commitments *coms) {
    size_t lc1       = g1_size_bin(coms->C1,       1);
    size_t lc2       = g1_size_bin(coms->C2,       1);
    size_t lc2hat    = g1_size_bin(coms->C2hat,    1);
    size_t lc2hathat = g1_size_bin(coms->C2hathat, 1);
    size_t lphat     = gt_size_bin(coms->Phat,     1);

    return lc1 + lc2 + lc2hat + lc2hathat + lphat;
}

void
bbsplus_proof_commitments_write_bin(uint8_t *ptr,
        size_t len, struct bbsplus_proof_commitments *coms) {

    size_t lc1       = g1_size_bin(coms->C1,       1);
    size_t lc2       = g1_size_bin(coms->C2,       1);
    size_t lc2hat    = g1_size_bin(coms->C2hat,    1);
    size_t lc2hathat = g1_size_bin(coms->C2hathat, 1);
    size_t lphat     = gt_size_bin(coms->Phat,     1);

    size_t input_len = lc1 + lc2 + lc2hat + lc2hathat + lphat;

    if(input_len != len) {
        printf("ERROR: incorrect hash input size!\n");
        return;
    }

    // Adding C1
    g1_write_bin(ptr, lc1, coms->C1, 1);
    ptr += lc1;

    // Adding C2
    g1_write_bin(ptr, lc2, coms->C2, 1);
    ptr += lc2;

    // Adding C2hat
    g1_write_bin(ptr, lc2hat, coms->C2hat, 1);
    ptr += lc2hat;

    // Adding C2hathat
    g1_write_bin(ptr, lc2hathat, coms->C2hathat, 1);
    ptr += lc2hathat;

    // Adding Phat
    gt_write_bin(ptr, lphat, coms->Phat, 1);
    ptr += lphat;
}

void
bbsplus_proof_challenge(bn_t c, struct bbsplus_proof_commitments *coms,
        uint8_t *L, size_t lL) {
    uint8_t hash[MD_LEN_SH256];

    bn_null(c);
    bn_new(c);

    size_t lcom  = bbsplus_proof_commitments_size(coms);

    size_t input_len = lL + lcom;

    uint8_t *input = malloc(input_len);
    uint8_t *iptr = input;

    // Adding L & commitments
    memcpy(iptr, L, lL);
    iptr += lL;
    bbsplus_proof_commitments_write_bin(iptr, lcom, coms);

    // Calculate hash
    md_map_sh256(hash, input, input_len);
    bn_read_bin(c, hash, BBSPLUS_CHALLENGE_SEC_PAR / 8);

    free(input);
}

void
bbsplus_proof_create(struct bbsplus_proof *proof,
        struct bbsplus_proof_randomizers *rand,
        struct bbsplus_proof_commitments *coms,
        struct bbsplus_sign *sign, bn_t *msgs, struct bbsplus_pk *pk,
        bn_t c, size_t nr_msgs) {

    g1_null(proof->C1);
    g1_new(proof->C1);
    g1_copy(proof->C1, coms->C1);

    g1_null(proof->C1);
    g1_new(proof->C1);
    g1_copy(proof->C2, coms->C2);

    bn_null(proof->challenge);
    bn_new(proof->challenge);
    bn_copy(proof->challenge, c);

    proof->nr_mresps = nr_msgs;

    // Calculate responses
    bn_null(proof->r1resp);
    bn_new(proof->r1resp);
    bn_mul(proof->r1resp, proof->challenge, rand->r1);
    bn_add(proof->r1resp, proof->r1resp, rand->r1hat);
    bn_mod(proof->r1resp, proof->r1resp, pk->q);
    // printf("Response r1resp = "); bn_print(proof->r1resp);

    bn_null(proof->r2resp);
    bn_new(proof->r2resp);
    bn_mul(proof->r2resp, proof->challenge, rand->r2);
    bn_add(proof->r2resp, proof->r2resp, rand->r2hat);
    bn_mod(proof->r2resp, proof->r2resp, pk->q);
    // printf("Response r2resp = "); bn_print(proof->r2resp);

    bn_t a1, a2;

    bn_null(a1);
    bn_new(a1);
    bn_mul(a1, sign->e, rand->r1);
    bn_mod(a1, a1, pk->q);

    bn_null(a2);
    bn_new(a2);
    bn_mul(a2, sign->e, rand->r2);
    bn_mod(a2, a2, pk->q);

    bn_null(proof->a1resp);
    bn_new(proof->a1resp);
    bn_mul(proof->a1resp, proof->challenge, a1);
    bn_add(proof->a1resp, proof->a1resp, rand->a1hat);
    bn_mod(proof->a1resp, proof->a1resp, pk->q);
    // printf("Response a1resp = "); bn_print(proof->a1resp);

    bn_null(proof->a2resp);
    bn_new(proof->a2resp);
    bn_mul(proof->a2resp, proof->challenge, a2);
    bn_add(proof->a2resp, proof->a2resp, rand->a2hat);
    bn_mod(proof->a2resp, proof->a2resp, pk->q);
    // printf("Response a2resp = "); bn_print(proof->a2resp);

    bn_null(proof->eresp);
    bn_new(proof->eresp);
    bn_mul(proof->eresp, proof->challenge, sign->e);
    bn_add(proof->eresp, proof->eresp, rand->ehat);
    bn_mod(proof->eresp, proof->eresp, pk->q);
    // printf("Response eresp = "); bn_print(proof->eresp);

    proof->mresps = malloc(nr_msgs * sizeof(bn_t));
    for(int i = 0; i < nr_msgs; i++) {
        bn_null(proof->mresps[i]);
        bn_new(proof->mresps[i]);
        bn_mul(proof->mresps[i], proof->challenge, msgs[i]);
        bn_add(proof->mresps[i], proof->mresps[i], rand->mhat[i]);
        bn_mod(proof->mresps[i], proof->mresps[i], pk->q);
    }

    bn_null(proof->sresp);
    bn_new(proof->sresp);
    bn_mul(proof->sresp, proof->challenge, sign->s);
    bn_add(proof->sresp, proof->sresp, rand->shat);
    bn_mod(proof->sresp, proof->sresp, pk->q);
    // printf("Response sresp = "); bn_print(proof->sresp);
}

void
bbsplus_proof_free(struct bbsplus_proof *proof) {
    g1_free(proof->C1);
    g1_free(proof->C2);

    bn_free(proof->r1resp);
    bn_free(proof->r2resp);
    bn_free(proof->a1resp);
    bn_free(proof->a2resp);
    bn_free(proof->eresp);
    bn_free(proof->sresp);

    for(int i = 0; i < proof->nr_mresps; i++) {
        bn_free(proof->mresps[i]);
    }
    free(proof->mresps);

    bn_free(challenge);
}

void
bbsplus_proof_reconstruct_commitments( struct bbsplus_proof_commitments *coms,
        struct bbsplus_proof *proof, struct bbsplus_pk *pk, size_t nr_msgs) {

    g1_t tmp1;
    g1_null(tmp1);
    g1_new(tmp1);

    // Recovering C2hat
    g1_null(coms->C2hat);
    g1_new(coms->C2hat);

    g1_copy(coms->C1, proof->C1);
    g1_copy(coms->C2, proof->C2);

    // C2neg = C2^{-1}
    g1_t C2neg;
    g1_null(C2neg);
    g1_new(C2neg);
    g1_neg(C2neg, proof->C2);

    // C2hat = C2neg^{challenge} * g1^{r1resp} * g1bar^{r2resp}
    g1_mul(coms->C2hat, C2neg, proof->challenge);
    g1_mul_gen(tmp1, proof->r1resp);
    g1_add(coms->C2hat, coms->C2hat, tmp1);
    g1_mul(tmp1, pk->g1bar, proof->r2resp);
    g1_add(coms->C2hat, coms->C2hat, tmp1);
    // printf("--- C2hat: \n"); g1_norm(coms->C2hat, coms->C2hat); g1_print(coms->C2hat);

    // Recovering C2hathat
    g1_null(coms->C2hathat);
    g1_new(coms->C2hathat);

    // C2hathat = C2neg^{eresp} * g1^{a1resp} * g1bar^{a2resp}
    g1_mul(coms->C2hathat, C2neg, proof->eresp);
    g1_mul_gen(tmp1, proof->a1resp);
    g1_add(coms->C2hathat, coms->C2hathat, tmp1);
    g1_mul(tmp1, pk->g1bar, proof->a2resp);
    g1_add(coms->C2hathat, coms->C2hathat, tmp1);
    // printf("--- C2hathat: \n"); g1_norm(coms->C2hathat, coms->C2hathat); g1_print(coms->C2hathat);

    // Phat = (e(g1, g2)^{-1}*e(C1, pk->w))^{-challenge}
    //        (e(C1, g2)^{-1})^{eresp} * e(base[0], g2)^{sresp} *
    //        e(g1bar, pk->w)^{r1resp} * e(g1bar, g2)^{a1resp} *
    //        prod_{i = 1}^{L} e(base[i], g2)^{mresp[i-1]}
    gt_null(coms->Phat);
    gt_new(coms->Phat);

    gt_t tmpt;
    gt_null(tmpt);
    gt_new(tmpt);

    g2_t g2;
    g2_null(g2);
    g2_new(g2);
    g2_get_gen(g2);

    // (e(g1, g2)*e(C1, pk->w)^{-1})^{challenge}
    pc_map(tmpt, proof->C1, pk->w);
    gt_inv(tmpt, tmpt);
    gt_mul(coms->Phat, pk->pairing_g1_g2, tmpt);
    gt_exp(coms->Phat, coms->Phat, proof->challenge);

    // (e(C1, g2)^{-1})^{eresp}
    pc_map(tmpt, proof->C1, g2);
    gt_inv(tmpt, tmpt);
    gt_exp(tmpt, tmpt, proof->eresp);
    gt_mul(coms->Phat, coms->Phat, tmpt);

    // e(base[0], g2)^{sresp}
    gt_exp(tmpt, pk->pairing_bases_g2[0], proof->sresp);
    gt_mul(coms->Phat, coms->Phat, tmpt);

    // e(g1bar, pk->w)^{r1resp}
    gt_exp(tmpt, pk->pairing_g1bar_w, proof->r1resp);
    gt_mul(coms->Phat, coms->Phat, tmpt);

    // e(g1bar, g2)^{a1resp}
    gt_exp(tmpt, pk->pairing_g1bar_g2, proof->a1resp);
    gt_mul(coms->Phat, coms->Phat, tmpt);

    for(int i = 1; i <= nr_msgs; i++) {
        // e(base[i], g2)^{mresps[i-1]}
        gt_exp(tmpt, pk->pairing_bases_g2[i], proof->mresps[i - 1]);
        gt_mul(coms->Phat, coms->Phat, tmpt);
    }
    // printf("--- Phat:\n"); gt_print(coms->Phat);
}

int
bbsplus_proof_verify(struct bbsplus_proof *proof, struct bbsplus_pk *pk, size_t nr_msgs, uint8_t *L, size_t lL) {

    struct bbsplus_proof_commitments coms;
    bbsplus_proof_reconstruct_commitments(&coms, proof, pk, nr_msgs);

    bn_t challenge;
    bbsplus_proof_challenge(challenge, &coms, L, lL);
    // printf("--- challenge: "); bn_print(challenge);

    return bn_cmp(challenge, proof->challenge) == CMP_EQ;
}

size_t
bbsplus_proof_size(struct bbsplus_proof *p) {
    size_t res = 0;

    res += g1_size_bin(p->C1, 1);
    res += g1_size_bin(p->C2, 1);

    res += bn_size_bin(p->r1resp);
    res += bn_size_bin(p->r2resp);
    res += bn_size_bin(p->a1resp);
    res += bn_size_bin(p->a2resp);
    res += bn_size_bin(p->eresp);
    res += bn_size_bin(p->sresp);

    for(int i = 0; i < p->nr_mresps; i++) {
        res += bn_size_bin(p->mresps[i]);
    }

    res += bn_size_bin(p->challenge);

    return res;
}
