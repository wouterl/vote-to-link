#include "vtr.h"
#include "utils.h"

#include <stdio.h>
#include <relic/relic.h>

void
vtr_transact(struct vtr_record *trans, struct bbsplus_sign *sign,
        bn_t x, struct tdh_pk *tdhpk, struct bbsplus_pk *bbspk,
        uint8_t *L, size_t lL, uint8_t *epoch, size_t lepoch) {

    trans->transaction = L;
    trans->ltransaction = lL;
    trans->epoch = epoch;
    trans->lepoch = lepoch;

    g2_t h;
    g2_null(h);
    g2_new(h);
    g2_get_gen(h);

    // ***
    // Calculate linking tokens
    // ***

    // gepoch = H(epoch)
    g1_null(trans->gepoch);
    g1_new(trans->gepoch);
    g1_map(trans->gepoch, epoch, lepoch);

    // ***
    // Calculating (encrypted) revocation token
    // ***
    bn_t r;
    bn_null(r);
    bn_new(r);
    bn_rand_mod(r, tdhpk->q);

    g1_t msg;
    g1_null(msg);
    g1_new(msg);
    g1_mul(msg, trans->gepoch, x);
    // printf("Linking token:\n"); g1_norm(msg, msg); g1_print(msg);
    tdh_enc_with_random(&trans->ctxt, tdhpk, msg, L, lL, r);

    // Testing
    bn_t tmp;
    bn_null(tmp);
    bn_new(tmp);
    bn_copy(tmp, x);

    // Calculating credential proof & vtr proof
    struct bbsplus_proof_randomizers bbsrand;
    struct bbsplus_proof_commitments bbscoms;
    bbsplus_proof_randomizers(&bbsrand, bbspk, 1);
    bbsplus_proof_commitments(&bbscoms, &bbsrand, sign, bbspk, 1);

    struct vtr_proof_randomizers vtrrand;
    struct vtr_proof_commitments vtrcoms;
    vtr_proof_randomizers(&vtrrand, x, tdhpk);
    bn_copy(vtrrand.xhat, bbsrand.mhat[0]);
    vtr_proof_commitments(&vtrcoms, &vtrrand, trans->gepoch, tdhpk);

    bn_t c;
    vtr_proof_combined_challenge(c, &vtrcoms, &bbscoms, L, lL);

    bbsplus_proof_create(&trans->cred_proof, &bbsrand, &bbscoms, sign, &tmp, bbspk, c, 1);
    vtr_proof_create(&trans->link_proof, &vtrrand, &vtrcoms,
            x, r, tdhpk, c);

    g2_free(h);
    bn_free(r);
    bn_free(tmp);
    bn_free(c);

    bbsplus_proof_randomizers_free(&bbsrand);
    bbsplus_proof_commitments_free(&bbscoms);
}

void
vtr_proof_randomizers(struct vtr_proof_randomizers *rand,
        bn_t x, struct tdh_pk *pk) {

    bn_null(rand->z);
    bn_new(rand->z);
    bn_rand_mod(rand->z, pk->q);

    bn_null(rand->a);
    bn_new(rand->a);
    bn_mul(rand->a, rand->z, x);
    bn_mod(rand->a, rand->a, pk->q);

    bn_null(rand->rhat);
    bn_new(rand->rhat);
    bn_rand_mod(rand->rhat, pk->q);

    bn_null(rand->zhat);
    bn_new(rand->zhat);
    bn_rand_mod(rand->zhat, pk->q);

    bn_null(rand->ahat);
    bn_new(rand->ahat);
    bn_rand_mod(rand->ahat, pk->q);

    bn_null(rand->xhat);
    bn_new(rand->xhat);
    bn_rand_mod(rand->xhat, pk->q);
}


void
vtr_proof_commitments(struct vtr_proof_commitments *coms,
        struct vtr_proof_randomizers *rand, g1_t gepoch,
        struct tdh_pk *pk) {

    g1_t tmp1;
    g1_null(tmp1);
    g1_new(tmp1);

    g2_t tmp2;
    g2_null(tmp2);
    g2_new(tmp2);

    g2_t h;
    g2_null(h);
    g2_new(h);
    g2_get_gen(h);

    // t1 = g^z
    g2_null(coms->t1);
    g2_new(coms->t1);
    g2_mul_gen(coms->t1, rand->z);

    // t2 = e(gepoch^{a}, h);
    gt_null(coms->t2);
    gt_new(coms->t2);
    g1_mul(tmp1, gepoch, rand->a);
    pc_map(coms->t2, tmp1, h);

    // chat = g_{\epoch}^xhat w^rhat (w = pk->pk)
    g1_null(coms->chat);
    g1_new(coms->chat);
    g1_mul(coms->chat, gepoch, rand->xhat);
    g1_mul(tmp1, pk->pk, rand->rhat);
    g1_add(coms->chat, coms->chat, tmp1);
    // printf("+++ chat: \n"); g1_norm(coms->chat, coms->chat); g1_print(coms->chat);

    // t1hat = h^zhat
    g2_null(coms->t1hat);
    g2_new(coms->t1hat);
    g2_mul_gen(coms->t1hat, rand->zhat);
    // printf("+++ t1hat: \n"); g2_norm(coms->t1hat, coms->t1hat); g2_print(coms->t1hat);

    // t2hat = e(g_{\epoch}, h)^{ahat}
    // t2hat = e(g_{\epoch}^{ahat}, h) (this is about 10x faster)
    // Note: precomputation of the pairing would be faster, but it is essential
    // that the user checks that the correct epoch is used.
    gt_null(coms->t2hat);
    gt_new(coms->t2hat);
    g1_mul(tmp1, gepoch, rand->ahat);
    pc_map(coms->t2hat, tmp1, h);
    // printf("+++ t2hat: \n"); gt_print(coms->t2hat);

    // t1hhat = (t1^-1)^{xhat} h^{ahat}
    g2_null(coms->t1hhat);
    g2_new(coms->t1hhat);
    g2_mul_gen(coms->t1hhat, rand->ahat);
    g2_neg(tmp2, coms->t1);
    g2_mul(tmp2, tmp2, rand->xhat);
    g2_add(coms->t1hhat, coms->t1hhat, tmp2);
    // printf("+++ t1hhat: \n"); g2_norm(coms->t1hhat, coms->t1hhat); g2_print(coms->t1hhat);
}

int
vtr_proof_commitments_size(struct vtr_proof_commitments *coms) {
    size_t lt1      = g2_size_bin(coms->t1,     1);
    size_t lt2      = gt_size_bin(coms->t2,     1);
    size_t lchat    = g1_size_bin(coms->chat,   1);
    size_t lt1hat   = g2_size_bin(coms->t1hat,  1);
    size_t lt2hat   = gt_size_bin(coms->t2hat,  1);
    size_t lt1hhat  = g2_size_bin(coms->t1hhat, 1);

    return lt1 + lt2 + lchat + lt1hat + lt2hat + lt1hhat;
}

void
vtr_proof_commitments_write_bin(uint8_t *ptr,
        size_t len, struct vtr_proof_commitments *coms) {
    size_t lt1      = g2_size_bin(coms->t1,     1);
    size_t lt2      = gt_size_bin(coms->t2,     1);
    size_t lchat    = g1_size_bin(coms->chat,   1);
    size_t lt1hat   = g2_size_bin(coms->t1hat,  1);
    size_t lt2hat   = gt_size_bin(coms->t2hat,  1);
    size_t lt1hhat  = g2_size_bin(coms->t1hhat, 1);

    size_t input_len = lt1 + lt2 + lchat + lt1hat + lt2hat + lt1hhat;

    if(input_len != len) {
        printf("ERROR: incorrect hash input size!\n");
        return;
    }

    // Adding t1
    g2_write_bin(ptr, lt1, coms->t1, 1);
    ptr += lt1;

    // Adding t2
    gt_write_bin(ptr, lt2, coms->t2, 1);
    ptr += lt2;

    // Adding chat
    g1_write_bin(ptr, lchat, coms->chat, 1);
    ptr += lchat;

    // Adding t1hat
    g2_write_bin(ptr, lt1hat, coms->t1hat, 1);
    ptr += lt1hat;

    // Adding t2hat
    gt_write_bin(ptr, lt2hat, coms->t2hat, 1);
    ptr += lt2hat;

    // Adding lt1hhat
    g2_write_bin(ptr, lt1hhat, coms->t1hhat, 1);
    ptr += lt1hhat;
}

void
vtr_proof_challenge(bn_t c, struct vtr_proof_commitments *coms,
        uint8_t *L, size_t lL) {
    uint8_t hash[MD_LEN_SH256];

    bn_null(c);
    bn_new(c);

    size_t lcom = vtr_proof_commitments_size(coms);
    size_t input_len = lL + lcom;

    uint8_t *input = malloc(input_len);
    uint8_t *iptr = input;

    // Adding L & commitments
    memcpy(iptr, L, lL);
    iptr += lL;
    vtr_proof_commitments_write_bin(iptr, lcom, coms);

    // Calculate hash
    md_map_sh256(hash, input, input_len);
    bn_read_bin(c, hash, VTR_CHALLENGE_SEC_PAR / 8);


    free(input);
}

void
vtr_proof_combined_challenge(bn_t c,
        struct vtr_proof_commitments *vtrcoms,
        struct bbsplus_proof_commitments *bbscoms,
        uint8_t *L, size_t lL) {
    uint8_t hash[MD_LEN_SH256];

    bn_null(c);
    bn_new(c);

    size_t lvtrcom = vtr_proof_commitments_size(vtrcoms);
    size_t lbbscom = bbsplus_proof_commitments_size(bbscoms);
    size_t input_len = lL + lvtrcom + lbbscom;

    uint8_t *input = malloc(input_len);
    uint8_t *iptr = input;

    // Adding L & commitments
    memcpy(iptr, L, lL);
    iptr += lL;
    vtr_proof_commitments_write_bin(iptr, lvtrcom, vtrcoms);
    iptr += lvtrcom;
    bbsplus_proof_commitments_write_bin(iptr, lbbscom, bbscoms);

    //printf("The input to the hash function\n");
    //print_bytes(iptr, lbbscom);

    // Calculate hash
    md_map_sh256(hash, input, input_len);
    bn_read_bin(c, hash, VTR_CHALLENGE_SEC_PAR / 8);

    free(input);
}

void
vtr_proof_create(struct vtr_proof *proof,
        struct vtr_proof_randomizers *rand,
        struct vtr_proof_commitments *coms,
        bn_t x, bn_t r, struct tdh_pk *pk, bn_t c) {

    bn_null(proof->challenge);
    bn_new(proof->challenge);
    bn_copy(proof->challenge, c);

    g2_null(proof->t1);
    g2_new(proof->t1);
    g2_copy(proof->t1, coms->t1);

    gt_null(proof->t2);
    gt_new(proof->t2);
    gt_copy(proof->t2, coms->t2);

    // Calculating responses
    bn_null(proof->xresp);
    bn_new(proof->xresp);
    bn_mul(proof->xresp, proof->challenge, x);
    bn_add(proof->xresp, proof->xresp, rand->xhat);
    bn_mod(proof->xresp, proof->xresp, pk->q);

    bn_null(proof->rresp);
    bn_new(proof->rresp);
    bn_mul(proof->rresp, proof->challenge, r);
    bn_add(proof->rresp, proof->rresp, rand->rhat);
    bn_mod(proof->rresp, proof->rresp, pk->q);

    bn_null(proof->zresp);
    bn_new(proof->zresp);
    bn_mul(proof->zresp, proof->challenge, rand->z);
    bn_add(proof->zresp, proof->zresp, rand->zhat);
    bn_mod(proof->zresp, proof->zresp, pk->q);

    bn_null(proof->aresp);
    bn_new(proof->aresp);
    bn_mul(proof->aresp, proof->challenge, rand->a);
    bn_add(proof->aresp, proof->aresp, rand->ahat);
    bn_mod(proof->aresp, proof->aresp, pk->q);
}

void
vtr_verify_reconstruct_commitments(struct vtr_proof_commitments *coms,
        struct vtr_proof *proof, g1_t gepoch, struct tdh_ctxt *ctxt,
        struct tdh_pk *pk) {

    g1_null(coms->chat);
    g1_new(coms->chat);

    g2_null(coms->t1hat);
    g2_new(coms->t1hat);

    gt_null(coms->t2hat);
    gt_new(coms->t2hat);

    g2_null(coms->t1hhat);
    g2_new(coms->t1hhat);

    g1_t tmp1;
    g1_null(tmp1);
    g1_new(tmp1);

    g2_t tmp2;
    g2_null(tmp2);
    g2_new(tmp2);

    gt_t tmpt;
    gt_null(tmpt);
    gt_new(tmpt);

    g2_t h;
    g2_null(h);
    g2_new(h);
    g2_get_gen(h);

    // Add t1 and t2 to constructed commitments
    g2_null(coms->t1);
    g2_new(coms->t1);
    g2_copy(coms->t1, proof->t1);

    gt_null(coms->t2);
    gt_new(coms->t2);
    gt_copy(coms->t2, proof->t2);

    // Recovering chat
    // chat = cneg^{challenge} * gepoch^{xresp} * w^{rresp}
    g1_neg(tmp1, ctxt->c);
    g1_mul(coms->chat, tmp1, proof->challenge);
    g1_mul(tmp1, gepoch, proof->xresp);
    g1_add(coms->chat, coms->chat, tmp1);
    g1_mul(tmp1, pk->pk, proof->rresp);
    g1_add(coms->chat, coms->chat, tmp1);
    // printf("--- chat: \n"); g1_norm(coms->chat, coms->chat); g1_print(coms->chat);

    // t1hat = t1^{challenge} * h^{zresp}
    g2_neg(tmp2, proof->t1);
    g2_mul(coms->t1hat, tmp2, proof->challenge);
    g2_mul_gen(tmp2, proof->zresp);
    g2_add(coms->t1hat, coms->t1hat, tmp2);
    // printf("--- t1hat: \n"); g2_norm(coms->t1hat, coms->t1hat); g2_print(coms->t1hat);

    // t2hat = t2neg^{challenge} * e(gepoch, h)^{aresp}
    // Calculating: t2neg^{challenge} * e(gepoch^{aresp}, h)
    gt_inv(tmpt, proof->t2);
    gt_exp(coms->t2hat, tmpt, proof->challenge);
    g1_mul(tmp1, gepoch, proof->aresp);
    pc_map(tmpt, tmp1, h);
    gt_mul(coms->t2hat, coms->t2hat, tmpt);
    // printf("--- t2hat: \n"); gt_print(coms->t2hat);

    // t1hhat = (t1^-1)^{xhat} h^{ahat}
    // Proving 1 = (t1^-1)^{xhat} h^{ahat}
    // so verify: t1hhat = 1^{-challenge} (t1^{-1})^{xresp} * h^{aresp}
    g2_mul_gen(coms->t1hhat, proof->aresp);
    g2_neg(tmp2, proof->t1);
    g2_mul(tmp2, tmp2, proof->xresp);
    g2_add(coms->t1hhat, coms->t1hhat, tmp2);
    // printf("--- t1hhat: \n"); g2_norm(coms->t1hhat, coms->t1hhat); g2_print(coms->t1hhat);
}

int
vtr_verify_proof(struct vtr_proof *proof,
        g1_t gepoch, struct tdh_ctxt *ctxt,
        struct tdh_pk *pk, uint8_t *L, size_t lL) {

    struct vtr_proof_commitments coms;

    vtr_verify_reconstruct_commitments(&coms, proof, gepoch, ctxt, pk);

    bn_t challenge;
    vtr_proof_challenge(challenge, &coms, L, lL);
    // printf("--- challenge:\n"); bn_print(challenge);

    return bn_cmp(challenge, proof->challenge) == CMP_EQ;
}

size_t
vtr_proof_size(struct vtr_proof *p) {
    size_t res = 0;

    res += g2_size_bin(p->t1, 1);
    res += gt_size_bin(p->t2, 1);

    res += bn_size_bin(p->challenge);

    res += bn_size_bin(p->xresp);
    res += bn_size_bin(p->zresp);
    res += bn_size_bin(p->aresp);
    res += bn_size_bin(p->rresp);

    return res;
}


int
vtr_verify_transaction(struct vtr_record *trans, struct tdh_pk *tdhpk,
        struct bbsplus_pk *bbspk) {

    struct vtr_proof_commitments vtrcoms;
    vtr_verify_reconstruct_commitments(&vtrcoms, &trans->link_proof,
            trans->gepoch, &trans->ctxt, tdhpk);

    struct bbsplus_proof_commitments bbscoms;
    bbsplus_proof_reconstruct_commitments(&bbscoms, &trans->cred_proof,
            bbspk, 1);

    // Recompute challenge
    bn_t challenge;
    vtr_proof_combined_challenge(challenge, &vtrcoms, &bbscoms, trans->transaction,
            trans->ltransaction);
    int proofs_ok = bn_cmp(challenge, trans->link_proof.challenge) == CMP_EQ &&
        bn_cmp(challenge, trans->cred_proof.challenge) == CMP_EQ;

    int enc_ok = tdh_ctxt_verify(&trans->ctxt, tdhpk);

    // Check if same private key is used in cred_proof and link proof
    int same_x = bn_cmp(trans->cred_proof.mresps[0],
            trans->link_proof.xresp) == CMP_EQ;

    return proofs_ok && enc_ok && same_x;
}

size_t
vtr_record_size(struct vtr_record *t) {
    size_t res = g1_size_bin(t->gepoch, 1);

    res += tdh_ctxt_size(&t->ctxt);
    res += bbsplus_proof_size(&t->cred_proof);
    res += vtr_proof_size(&t->link_proof);

    return res;
}
