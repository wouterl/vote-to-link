#include "vtr.h"
#include "anonvtr.h"
#include "utils.h"

#include <stdio.h>
#include <relic/relic.h>

void
anonvtr_encode_pks(struct shuffle_elgamal_ctxt *ctxt,
        struct shuffle_elgamal_pk *stub_pk,
        struct shuffle_elgamal_pk *pk, size_t n) {

    // Initialize stub key
    g1_null(stub_pk->gen);
    g1_new(stub_pk->gen);
    g1_rand(stub_pk->gen);

    g1_null(stub_pk->pk);
    g1_new(stub_pk->pk);
    g1_get_gen(stub_pk->pk);

    bn_null(stub_pk->q);
    bn_new(stub_pk->q);
    g1_get_ord(stub_pk->q);

    // Setup trivial randomizer
    struct shuffle_elgamal_randomizer rand;
    rand.n = 1;
    bn_null(rand.rand[0]);
    bn_new(rand.rand[0]);
    bn_set_dig(rand.rand[0], 0);

    // Encode the public keys
    for(int i = 0; i < n; i++) {
        shuffle_elgamal_encrypt_with_randomizer(ctxt + i, &pk[i].pk,
                1, &rand, stub_pk);
    }
}

int
anonvtr_verify_pk_encoding(struct shuffle_elgamal_pk *pk,
        struct shuffle_elgamal_ctxt *ctxt, size_t n) {

    for(int i = 0; i < n; i++) {
        if(!g1_is_infty(ctxt->c2[0])) {
            return 0;
        }

        g1_norm((ctxt + i)->c1[0], (ctxt + i)->c1[0]);
        g1_norm((pk + i)->pk, (pk + i)->pk);
        if(g1_cmp((ctxt + i)->c1[0], (pk + i)->pk) != CMP_EQ) {
            printf("Ciphertext component doesn't match pk!\n");
            return 0;
        }
    }

    return 1;
}

void
anonvtr_sp_randomize_pks(struct anonvtr_msg_sp *msg,
        struct anonvtr_sp_private *priv,
        struct shuffle_elgamal_pk *pk, size_t n,
        struct shuffle_com_pk *ck, uint8_t *transaction,
        size_t ltransaction) {

    msg->n = n;

    msg->encoded_pks = malloc(n * sizeof(struct shuffle_elgamal_ctxt));
    anonvtr_encode_pks(msg->encoded_pks, &msg->stub_pk, pk, n);

    shuffle_and_randomize(msg->encoded_pks, &msg->shuffled_pks, 
            &priv->rand, &priv->perm, n, &msg->stub_pk);

    shuffle_prove( &msg->shuffle_proof, msg->encoded_pks, msg->shuffled_pks,
            n, &msg->stub_pk, ck,  priv->perm, priv->rand,
            transaction, ltransaction);
}


int
anonvtr_verify_msg_sp(struct anonvtr_msg_sp *msg,
        struct shuffle_elgamal_pk *pk, size_t n,
        struct shuffle_com_pk *ck, uint8_t *transaction,
        size_t ltransaction) {

    if(!anonvtr_verify_pk_encoding(pk, msg->encoded_pks, n)) {
        printf("Incorrect encoding of moderator pks\n");
        return 0;
    }

    if(!shuffle_proof_verify(&msg->shuffle_proof, msg->encoded_pks,
                msg->shuffled_pks, n, &msg->stub_pk, ck,
                transaction, ltransaction)) {
        printf("SP Shuffle proof does not verify!\n");
        return 0;
    }

    return 1;
}

size_t
anonvtr_msg_sp_size(struct anonvtr_msg_sp *m) {
    size_t res = 0;

    res += shuffle_elgamal_pk_size(&m->stub_pk);

    for(int i = 0; i < m->n; i++) {
        // res += shuffle_elgamal_ctxt_size(encoded_pks + i);
        res += shuffle_elgamal_size(m->shuffled_pks + i);
    }

    res += shuffle_proof_size(&m->shuffle_proof);

    res += sizeof(size_t);

    return res;
}

void
anonvtr_user_encrypt_decshares(struct shuffle_elgamal_ctxt *e,
        struct shuffle_elgamal_randomizer *rand,
        struct shuffle_elgamal_pk *pk,
        struct tdh_sk *tdhsk, g1_t u, size_t n) {

    g1_t msg[2];
    g1_null(msg[0]);
    g1_new(msg[0]);
    g1_null(msg[1]);
    g1_new(msg[1]);

    // Dummy ctxt to hold shuffle size
    struct shuffle_elgamal_ctxt ctxt;
    ctxt.n = 2;

    bn_t idx;
    bn_null(idx);
    bn_new(idx);

    // TODO: user still needs to do shuffle

    for(int i = 0; i < n; i++) {
        // Initialize randomizer, use trivial randomizer for first component
        shuffle_elgamal_randomizer(rand + i, &ctxt, pk);
        bn_set_dig(rand[i].rand[0], 0);

        bn_set_dig(idx, tdhsk[i].i);
        g1_mul_gen(msg[0], idx);
        g1_mul(msg[1], u, tdhsk[i].sshare);

        // printf("Encrypting share %i against key: %i\n", tdhsk[i].i, i);
        // g1_print(msg[1]);

        shuffle_elgamal_encrypt_with_randomizer(e + i, msg, 2, rand + i, pk);
    }
}

void
anonvtr_user_reencrypt_decshares(struct shuffle_elgamal_ctxt *e,
        struct shuffle_elgamal_randomizer *rand,
        unsigned int *perm, struct shuffle_elgamal_pk *pk,
        struct tdh_sk *tdhsk, g1_t u, size_t n) {

    g1_t msg[2];
    g1_null(msg[0]);
    g1_new(msg[0]);
    g1_null(msg[1]);
    g1_new(msg[1]);

    // Dummy ctxt to hold shuffle size
    struct shuffle_elgamal_ctxt ctxt;
    ctxt.n = 2;

    bn_t idx;
    bn_null(idx);
    bn_new(idx);

    for(int i = 0; i < n; i++) {
        shuffle_elgamal_randomizer(rand + i, &ctxt, pk);

        bn_set_dig(idx, tdhsk[perm[i]].i);
        g1_mul_gen(msg[0], idx);
        g1_mul(msg[1], u, tdhsk[perm[i]].sshare);

        shuffle_elgamal_encrypt_with_randomizer(e + i, msg, 2, rand + i, pk + i);
    }
}

void
anonvtr_user_proof_decshares_hash(bn_t challenge, g1_t hprimehat,
        g1_t *c1hat, g1_t *c2hat, g1_t *wihat, size_t n,
        uint8_t *L, size_t lL) {

    uint8_t hash[MD_LEN_SH256];

    bn_null(challenge);
    bn_new(challenge);

    // TODO: also include public values like ciphertexts in hash?

    size_t lhprimehat = g1_size_bin(hprimehat, 1);

    size_t lrest = 0;
    for(int i = 0; i < n; i++) {
        lrest += g1_size_bin(c1hat[i], 1);
        lrest += g1_size_bin(c2hat[i], 1);
        lrest += g1_size_bin(wihat[i], 1);
    }

    size_t input_len = lhprimehat + lrest + lL;

    uint8_t *input = malloc(input_len);
    uint8_t *iptr = input;

    // Adding L
    memcpy(iptr, L, lL);
    iptr += lL;

    g1_write_bin(iptr, lhprimehat, hprimehat, 1);
    iptr += lhprimehat;

    size_t lelem  = 0;
    for(int i = 0; i < n; i++) {
        lelem = g1_size_bin(c1hat[i], 1);
        g1_write_bin(iptr, lelem, c1hat[i], 1);
        iptr += lelem;

        lelem = g1_size_bin(c2hat[i], 1);
        g1_write_bin(iptr, lelem, c2hat[i], 1);
        iptr += lelem;

        lelem = g1_size_bin(wihat[i], 1);
        g1_write_bin(iptr, lelem, wihat[i], 1);
        iptr += lelem;
    }

    md_map_sh256(hash, input, input_len);

    bn_read_bin(challenge, hash, VTR_CHALLENGE_SEC_PAR / 8);
}

void
anonvtr_user_prove_decshares(struct anonvtr_proof_decshares *proof,
        struct shuffle_elgamal_ctxt *e,
        struct shuffle_elgamal_randomizer *rand, size_t n,
        struct shuffle_elgamal_pk *pk, struct shuffle_elgamal_sk *sk,
        struct tdh_pk *tdhpk, struct tdh_sk *tdhsk, struct tdh_ctxt *tdhctxt,
        uint8_t *transaction, size_t ltransaction) {

    // Note: the encryption of the indices is deterministic, no proof necessary

    bn_t xprimehat;
    bn_t *kihat = malloc(n * sizeof(bn_t));
    bn_t *rihat = malloc(n * sizeof(bn_t));

    bn_null(xprimehat);
    bn_new(xprimehat);
    bn_rand_mod(xprimehat, pk->q);

    for(int i = 0; i < n; i++) {
        bn_null(kihat[i]);
        bn_new(kihat[i]);
        bn_rand_mod(kihat[i], pk->q);

        bn_null(rihat[i]);
        bn_new(rihat[i]);
        bn_rand_mod(rihat[i], pk->q);
    }

    g1_t hprimehat;
    g1_t *c1hat = malloc(n * sizeof(g1_t));
    g1_t *c2hat = malloc(n * sizeof(g1_t));
    g1_t *wihat = malloc(n * sizeof(g1_t));

    g1_null(hprimehat);
    g1_new(hprimehat);
    g1_mul_gen(hprimehat, xprimehat);
    // printf("+++ hprimehat: "); g1_norm(hprimehat, hprimehat); g1_print(hprimehat);

    g1_t tmp;
    g1_null(tmp);
    g1_new(tmp);

    for(int i = 0; i < n; i++) {
        g1_null(c1hat[i]);
        g1_new(c1hat[i]);
        g1_mul(c1hat[i], tdhctxt->u, kihat[i]);
        g1_mul(tmp, pk->pk, rihat[i]);
        g1_add(c1hat[i], c1hat[i], tmp);
        // printf("+++ c1hat[%i]: ", i); g1_norm(c1hat[i], c1hat[i]); g1_print(c1hat[i]);

        g1_null(c2hat[i]);
        g1_new(c2hat[i]);
        g1_mul_gen(c2hat[i], rihat[i]);
        // printf("+++ c2hat[%i]: ", i); g1_norm(c2hat[i], c2hat[i]); g1_print(c2hat[i]);

        g1_null(wihat[i]);
        g1_new(wihat[i]);
        g1_mul_gen(wihat[i], kihat[i]);
        // printf("+++ wihat[%i]: ", i); g1_norm(wihat[i], wihat[i]); g1_print(wihat[i]);
    }

    anonvtr_user_proof_decshares_hash(proof->challenge, hprimehat,
            c1hat, c2hat, wihat, n, transaction, ltransaction);

    // Calculate responses
    // Calculating responses
    bn_null(proof->xprimeresp);
    bn_new(proof->xprimeresp);
    bn_mul(proof->xprimeresp, proof->challenge, sk->sk);
    bn_add(proof->xprimeresp, proof->xprimeresp, xprimehat);
    bn_mod(proof->xprimeresp, proof->xprimeresp, pk->q);

    proof->kiresp = malloc(n * sizeof(bn_t));
    proof->riresp = malloc(n * sizeof(bn_t));
    for(int i = 0; i < n; i++) {
        bn_null(proof->kiresp[i]);
        bn_new(proof->kiresp[i]);
        bn_mul(proof->kiresp[i], proof->challenge, tdhsk[i].sshare);
        bn_add(proof->kiresp[i], proof->kiresp[i], kihat[i]);
        bn_mod(proof->kiresp[i], proof->kiresp[i], pk->q);

        bn_null(proof->riresp[i]);
        bn_new(proof->riresp[i]);
        bn_mul(proof->riresp[i], proof->challenge, rand[i].rand[1]);
        bn_add(proof->riresp[i], proof->riresp[i], rihat[i]);
        bn_mod(proof->riresp[i], proof->riresp[i], pk->q);
    }
}

int
anonvtr_user_verify_decshares(struct anonvtr_proof_decshares *proof,
        struct shuffle_elgamal_ctxt *e, size_t n,
        struct shuffle_elgamal_pk *pk,
        struct tdh_pk *tdhpk, struct tdh_ctxt *tdhctxt,
        uint8_t *transaction, size_t ltransaction) {

    g1_t tmp;
    g1_null(tmp);
    g1_null(tmp);

    bn_t idx;
    bn_null(idx);
    bn_new(idx);

    // Verify that first components 'encrypt' g^i
    for(int i = 0; i < n; i++) {
        bn_set_dig(idx, i + 1);
        g1_mul_gen(tmp, idx);

        g1_norm(tmp, tmp);
        g1_norm(e[i].c1[0], e[i].c1[0]);
        if(g1_cmp(tmp, e[i].c1[0]) != CMP_EQ) {
            printf("Incorrect encryption of index\n");
            return 0;
        }

        if(!g1_is_infty(e[i].c2[0])) {
            printf("Incorrect index randomizer\n");
            return 0;
        }
    }


    g1_t hprimehat;
    g1_t *c1hat = malloc(n * sizeof(g1_t));
    g1_t *c2hat = malloc(n * sizeof(g1_t));
    g1_t *wihat = malloc(n * sizeof(g1_t));

    g1_null(hprimehat);
    g1_new(hprimehat);
    g1_neg(tmp, pk->pk);
    g1_mul(hprimehat, tmp, proof->challenge);
    g1_mul_gen(tmp, proof->xprimeresp);
    g1_add(hprimehat, hprimehat, tmp);
    // printf("--- hprimehat: "); g1_norm(hprimehat, hprimehat); g1_print(hprimehat);

    for(int i = 0; i < n; i++) {
        // c1hat = c1^{-challenge} u^{kiresp} h'^{riresp}
        g1_null(c1hat[i]);
        g1_new(c1hat[i]);
        g1_neg(tmp, e[i].c1[1]);
        g1_mul(c1hat[i], tmp, proof->challenge);
        g1_mul(tmp, tdhctxt->u, proof->kiresp[i]);
        g1_add(c1hat[i], c1hat[i], tmp);
        g1_mul(tmp, pk->pk, proof->riresp[i]);
        g1_add(c1hat[i], c1hat[i], tmp);
        // printf("--- c1hat[%i]: ", i); g1_norm(c1hat[i], c1hat[i]); g1_print(c1hat[i]);

        // c2hat = c2^{-challenge} g^{riresp}
        g1_null(c2hat[i]);
        g1_new(c2hat[i]);
        g1_neg(tmp, e[i].c2[1]);
        g1_mul(c2hat[i], tmp, proof->challenge);
        g1_mul_gen(tmp, proof->riresp[i]);
        g1_add(c2hat[i], c2hat[i], tmp);
        // printf("--- c2hat[%i]: ", i); g1_norm(c2hat[i], c2hat[i]); g1_print(c2hat[i]);

        // wihat = wi^{-challenge} g^{kiresp}
        g1_null(wihat[i]);
        g1_new(wihat[i]);
        g1_neg(tmp, tdhpk->vk[i]);
        g1_mul(wihat[i], tmp, proof->challenge);
        g1_mul_gen(tmp, proof->kiresp[i]);
        g1_add(wihat[i], wihat[i], tmp);
        // printf("--- wihat[%i]: ", i); g1_norm(wihat[i], wihat[i]); g1_print(wihat[i]);
    }

    bn_t challenge;
    anonvtr_user_proof_decshares_hash(challenge, hprimehat,
            c1hat, c2hat, wihat, n, transaction, ltransaction);

    return bn_cmp(challenge, proof->challenge) == CMP_EQ;
}

size_t
anonvtr_proof_decshares_size(struct anonvtr_proof_decshares *p, size_t n) {
    size_t res = 0;

    res += bn_size_bin(p->challenge);

    res += bn_size_bin(p->xprimeresp);

    for(int i = 0; i < n; i++) {
        res += bn_size_bin(p->kiresp[i]);
        res += bn_size_bin(p->riresp[i]);
    }

    return res;
}


void
anonvtr_recover_shuffled_pks(struct shuffle_elgamal_pk *shuffled_pks,
        struct shuffle_elgamal_ctxt *shuffled_ctxts, size_t n) {

    for(int i = 0; i < n; i++) {
        bn_null(shuffled_pks[i].q);
        bn_new(shuffled_pks[i].q);
        g1_get_ord(shuffled_pks[i].q);

        g1_null(shuffled_pks[i].gen);
        g1_new(shuffled_pks[i].gen);
        g1_get_gen(shuffled_pks[i].gen);

        g1_null(shuffled_pks[i].pk);
        g1_new(shuffled_pks[i].pk);
        g1_copy(shuffled_pks[i].pk, shuffled_ctxts[i].c1[0]);
    }
}

void
anonvtr_user_proof_reencrypt_hash(bn_t challenge,
        struct shuffle_elgamal_ctxt *ctildehat,
        struct shuffle_elgamal_ctxt *chat,
        size_t n, uint8_t *L, size_t lL) {

    uint8_t hash[MD_LEN_SH256];

    bn_null(challenge);
    bn_new(challenge);

    lL = 0;

    size_t input_len = lL;
    for(int i = 0; i < n; i++) {
        input_len += shuffle_elgamal_size(ctildehat + i);
        input_len += shuffle_elgamal_size(chat + i);
    }

    uint8_t *input = malloc(input_len);
    uint8_t *iptr = input;

    // Adding L
    memcpy(iptr, L, lL);
    iptr += lL;

    size_t lelem  = 0;
    for(int i = 0; i < n; i++) {
        lelem = shuffle_elgamal_size(ctildehat + i);
        shuffle_elgamal_write_bin(iptr, ctildehat + i);
        iptr += lelem;

        lelem = shuffle_elgamal_size(chat + i);
        shuffle_elgamal_write_bin(iptr, chat + i);
        iptr += lelem;

    }

    md_map_sh256(hash, input, input_len);

    bn_read_bin(challenge, hash, VTR_CHALLENGE_SEC_PAR / 8);
}

void
anonvtr_user_prove_reencrypt(struct anonvtr_proof_reencrypt *proof,
        struct shuffle_elgamal_ctxt *ctilde,
        struct shuffle_elgamal_randomizer *rand_ctilde,
        struct shuffle_elgamal_ctxt *c,
        struct shuffle_elgamal_randomizer *rand_c,
        struct shuffle_elgamal_pk *shuffled_pks,
        unsigned int *perm, size_t n, struct shuffle_elgamal_pk *hprime,
        struct tdh_sk *sks, g1_t u, uint8_t *L, size_t lL) {

#if 0
    // Let start by doing some sanity checks
    g1_t tmp;
    g1_null(tmp);
    g1_new(tmp);

    g1_t c1;
    g1_null(c1);
    g1_new(c1);

    bn_t tmpbn;
    bn_null(tmpbn);
    bn_new(tmpbn);

    for(int i = 0; i < n; i++) {
        for(int j = 0; j < 2; j++) {
            g1_norm(ctilde[i].c1[j], ctilde[i].c1[j]);
            g1_norm(ctilde[i].c2[j], ctilde[i].c2[j]);

            g1_mul_gen(tmp, rand_ctilde[i].rand[j]);
            g1_norm(tmp, tmp);
            if(g1_cmp(ctilde[i].c2[j], tmp) != CMP_EQ) {
                printf("ERROR: c2[%i] (i = %i) not as expected!\n", j, i);
            }

            if(j == 0) {
                // c1 = g^[perm[i] + 1] * h'^rand[j]
                bn_set_dig(tmpbn, sks[perm[i]].i);
                g1_mul_gen(c1, tmpbn);
            } else {
                // c1 = u^(sshare[perm[i]]) * h'^rand[j]
                g1_mul(c1, u, sks[perm[i]].sshare);
            }
            g1_mul(tmp, hprime->pk, rand_ctilde[i].rand[j]);
            g1_add(c1, c1, tmp);
            g1_norm(c1, c1);

            if(g1_cmp(ctilde[i].c1[j], c1) != CMP_EQ) {
                printf("ERROR: c1[%i] (i = %i) not as expected!\n", j, i);
            }
        }
    }
#endif

    bn_t *idxhat = malloc(n * sizeof(bn_t));
    bn_t *khat = malloc(n * sizeof(bn_t));
    struct shuffle_elgamal_randomizer *rtildehat =
        malloc(n * sizeof(struct shuffle_elgamal_randomizer));
    struct shuffle_elgamal_randomizer *rhat =
        malloc(n * sizeof(struct shuffle_elgamal_randomizer));

    for(int i = 0; i < n; i++) {
        bn_null(idxhat[i]);
        bn_new(idxhat[i]);
        bn_rand_mod(idxhat[i], hprime->q);

        bn_null(khat[i]);
        bn_new(khat[i]);
        bn_rand_mod(khat[i], hprime->q);

        shuffle_elgamal_randomizer(rtildehat + i, ctilde, hprime);
        shuffle_elgamal_randomizer(rhat + i, ctilde, hprime);
    }

    struct shuffle_elgamal_ctxt *ctildehat =
        malloc(n * sizeof(struct shuffle_elgamal_ctxt));
    struct shuffle_elgamal_ctxt *chat =
        malloc(n * sizeof(struct shuffle_elgamal_ctxt));

    g1_t msgs[2];
    g1_null(msgs[0]);
    g1_new(msgs[0]);
    g1_null(msgs[1]);
    g1_new(msgs[1]);

    for(int i = 0; i < n; i++) {
        g1_mul_gen(msgs[0], idxhat[i]);
        g1_mul(msgs[1], u, khat[i]);

        shuffle_elgamal_encrypt_with_randomizer(ctildehat + i, msgs, 2,
                rtildehat + i, hprime);

        shuffle_elgamal_encrypt_with_randomizer(chat + i, msgs, 2,
                rhat + i, shuffled_pks + i);

        /*
        if(i == 2) {
            printf("+++ ctildehat[%i]:\n", i);
            shuffle_elgamal_print(ctildehat + i);
            printf("+++ chat[%i]:\n", i);
            shuffle_elgamal_print(chat + i);
        }*/
    }

    anonvtr_user_proof_reencrypt_hash(proof->challenge, ctildehat, chat, n, L, lL);
    // printf("+++ challenge: "); bn_print(proof->challenge);

    proof->rtilderesp = malloc(n * sizeof(struct shuffle_elgamal_randomizer));
    proof->rresp = malloc(n * sizeof(struct shuffle_elgamal_randomizer));
    proof->idxresp = malloc(n * sizeof(bn_t));
    proof->kresp = malloc(n * sizeof(bn_t));

    bn_t idx;
    bn_null(idx);
    bn_new(idx);

    for(int i = 0; i < n; i++) {
        bn_null(proof->idxresp[i]);
        bn_new(proof->idxresp[i]);
        bn_set_dig(idx, sks[perm[i]].i);
        bn_mul(proof->idxresp[i], proof->challenge, idx);
        bn_add(proof->idxresp[i], proof->idxresp[i], idxhat[i]);
        bn_mod(proof->idxresp[i], proof->idxresp[i], hprime->q);

        bn_null(proof->kresp[i]);
        bn_new(proof->kresp[i]);
        bn_mul(proof->kresp[i], proof->challenge, sks[perm[i]].sshare);
        bn_add(proof->kresp[i], proof->kresp[i], khat[i]);
        bn_mod(proof->kresp[i], proof->kresp[i], hprime->q);

        shuffle_elgamal_randomizer_init(proof->rtilderesp + i, ctilde);
        shuffle_elgamal_randomizer_multiply(proof->rtilderesp + i, rand_ctilde + i,
                proof->challenge, hprime);
        shuffle_elgamal_randomizer_add(proof->rtilderesp + i,
                proof->rtilderesp + i, rtildehat + i, hprime);

        shuffle_elgamal_randomizer_init(proof->rresp + i, c);
        shuffle_elgamal_randomizer_multiply(proof->rresp + i, rand_c + i,
                proof->challenge, hprime);
        shuffle_elgamal_randomizer_add(proof->rresp + i,
                proof->rresp + i, rhat + i, hprime);

    }
}

int
anonvtr_user_verify_reencrypt(struct anonvtr_proof_reencrypt *proof,
        struct shuffle_elgamal_ctxt *ctilde,
        struct shuffle_elgamal_ctxt *c,
        struct shuffle_elgamal_pk *shuffled_pks,
        size_t n, struct shuffle_elgamal_pk *hprime,
        g1_t u, uint8_t *L, size_t lL) {

    bn_t minchal;
    bn_null(minchal);
    bn_new(minchal);
    bn_sub(minchal, hprime->q, proof->challenge);

    g1_t msgs[2];
    g1_null(msgs[0]);
    g1_new(msgs[0]);
    g1_null(msgs[1]);
    g1_new(msgs[1]);

    struct shuffle_elgamal_ctxt *ctildehat =
        malloc(n * sizeof(struct shuffle_elgamal_ctxt));
    struct shuffle_elgamal_ctxt *chat =
        malloc(n * sizeof(struct shuffle_elgamal_ctxt));

    struct shuffle_elgamal_ctxt tmp_ctxt;
    shuffle_elgamal_init(&tmp_ctxt, c->n);

    for(int i = 0; i < n; i++) {
        g1_mul_gen(msgs[0], proof->idxresp[i]);
        g1_mul(msgs[1], u, proof->kresp[i]);

        shuffle_elgamal_encrypt_with_randomizer(ctildehat + i, msgs, 2,
                proof->rtilderesp + i, hprime);
        shuffle_elgamal_exp(&tmp_ctxt, ctilde + i, minchal);
        shuffle_elgamal_multiply(ctildehat + i, ctildehat + i, &tmp_ctxt);

        shuffle_elgamal_encrypt_with_randomizer(chat + i, msgs, 2,
                proof->rresp + i, shuffled_pks + i);
        shuffle_elgamal_exp(&tmp_ctxt, c + i, minchal);
        shuffle_elgamal_multiply(chat + i, chat + i, &tmp_ctxt);

        /*
        if(i == 2) {
            printf("--- ctildehat[%i]:\n", i);
            shuffle_elgamal_print(ctildehat + i);
            printf("--- chat[%i]:\n", i);
            shuffle_elgamal_print(chat + i);
        }*/
    }

    bn_t challenge;
    anonvtr_user_proof_reencrypt_hash(challenge, ctildehat, chat, n, L, lL);
    // printf("--- challenge: "); bn_print(challenge);

    return bn_cmp(proof->challenge, challenge) == CMP_EQ;
}

size_t
anonvtr_proof_reencrypt_size(struct anonvtr_proof_reencrypt *p, size_t n) {
    size_t res = 0;

    res += bn_size_bin(p->challenge);

    for(int i = 0; i < n; i++) {
        res += shuffle_elgamal_randomizer_size(p->rtilderesp + i);
        res += shuffle_elgamal_randomizer_size(p->rresp + i);

        res += bn_size_bin(p->idxresp[i]);
        res += bn_size_bin(p->kresp[i]);
    }

    return res;
}

void
anonvtr_user_message(struct anonvtr_msg_user *msg,
        struct anonvtr_msg_sp *msg_sp,
        struct bbsplus_sign *sign, bn_t x, struct bbsplus_pk *bbspk,
        struct shuffle_com_pk *ck, size_t n, size_t k,
        uint8_t *L, size_t lL, uint8_t *epoch, size_t lepoch) {

    struct tdh_sk *sks;
    struct shuffle_elgamal_sk elgamalsk;

    msg->n = n;

    // Step 0:
    tdh_keygen(&msg->tdhpk, &sks, n, k);

    vtr_transact(&msg->record, sign, x, msg->tdhpk, bbspk,
            L, lL, epoch, lepoch);

    shuffle_elgamal_keygen(&msg->hprime, &elgamalsk);

    // *******
    // Step a:
    // *******
    msg->chat = malloc(n * sizeof(struct shuffle_elgamal_ctxt));

    struct shuffle_elgamal_randomizer *rand_enc =
        malloc(n * sizeof(struct shuffle_elgamal_randomizer));

    anonvtr_user_encrypt_decshares(msg->chat, rand_enc, &msg->hprime,
            sks, msg->record.ctxt.u, n);

    anonvtr_user_prove_decshares(&msg->decshare_proof, msg->chat,
            rand_enc, n, &msg->hprime, &elgamalsk, msg->tdhpk, sks,
            &msg->record.ctxt, L, lL);

    // *******
    // Step b:
    // *******
    struct shuffle_elgamal_randomizer *rand_shuffle;
    unsigned int *perm;
    shuffle_and_randomize(msg->chat, &msg->ctilde,
            &rand_shuffle, &perm, n, &msg->hprime);

    shuffle_prove( &msg->shuffle_proof, msg->chat, msg->ctilde,
            n, &msg->hprime, ck, perm, rand_shuffle, L, lL);

    // *******
    // Step c:
    // *******

    // Determine resulting randomizer
    struct shuffle_elgamal_randomizer *rand_resulting =
        malloc(n * sizeof(struct shuffle_elgamal_randomizer));
    for(int i = 0; i < n; i++) {
        shuffle_elgamal_randomizer_init(rand_resulting + i, msg->chat);
        shuffle_elgamal_randomizer_add(rand_resulting + i, rand_enc + perm[i],
                rand_shuffle + i, &msg->hprime);
    }

    // Reencrypt the decryption shares against the shuffled moderator keys
    struct shuffle_elgamal_pk *shuffled_pks =
        malloc(n * sizeof(struct shuffle_elgamal_pk));
    anonvtr_recover_shuffled_pks(shuffled_pks, msg_sp->shuffled_pks, n);

    msg->c = malloc(n * sizeof(struct shuffle_elgamal_ctxt));
    struct shuffle_elgamal_randomizer *rand_reencrypt =
        malloc(n * sizeof(struct shuffle_elgamal_randomizer));
    anonvtr_user_reencrypt_decshares(msg->c, rand_reencrypt, perm,
            shuffled_pks, sks, msg->record.ctxt.u, n);

    // Prove correctness of reencryption
    anonvtr_user_prove_reencrypt( &msg->reencrypt_proof, msg->ctilde,
            rand_resulting, msg->c, rand_reencrypt, shuffled_pks,
            perm, n, &msg->hprime, sks, msg->record.ctxt.u, L, lL);
}

int
anonvtr_verify_msg_user(struct anonvtr_msg_user *msg,
        struct anonvtr_msg_sp *msg_sp,
//        struct anonvtr_sp_private *sp_priv, struct shuffle_elgamal_sk *sk,
        struct bbsplus_pk *bbspk, struct shuffle_com_pk *ck,
        size_t n, size_t k, uint8_t *L, size_t lL) {

    if(!vtr_verify_transaction(&msg->record, msg->tdhpk, bbspk)) {
        printf("Transaction doesn't verify!\n");
        return 0;
    }

    if(!anonvtr_user_verify_decshares(&msg->decshare_proof, msg->chat, n,
            &msg->hprime, msg->tdhpk, &msg->record.ctxt, L, lL)) {
        printf("Verification of decshare encryption failed!\n");
        return 0;
    }

    if(!shuffle_proof_verify(&msg->shuffle_proof, msg->chat,
                msg->ctilde, n, &msg->hprime, ck, L, lL)) {
        printf("User shuffle proof does not verify!\n");
        return 0;
    }

    // Recover shuffled public keys
    struct shuffle_elgamal_pk *shuffled_pks =
        malloc(n * sizeof(struct shuffle_elgamal_pk));
    anonvtr_recover_shuffled_pks(shuffled_pks, msg_sp->shuffled_pks, n);

#if 0
    printf("Testing idea of encrypting against shuffled keys\n");
    struct shuffle_elgamal_ctxt ctxt;

    g1_t m;
    g1_null(m);
    g1_new(m);
    g1_rand(m);
    printf("Message: "); g1_norm(m, m); g1_print(m);

    // ctxt = Enc( m, shuffled_pks[0]) = Enc(m, modpks[perm[0]];
    shuffle_elgamal_init(&ctxt, 1);
    shuffle_elgamal_encrypt(&ctxt, &m, 1, shuffled_pks);

    unsigned int *invperm = malloc(n * sizeof(unsigned int));
    for(int i = 0; i < n; i++) {
        invperm[sp_priv->perm[i]] = i;
    }

    shuffle_elgamal_derandomize(&ctxt, sp_priv->rand[0].rand[0]);

    g1_t mrec;
    g1_null(mrec);
    g1_new(mrec);

    shuffle_elgamal_decrypt(&mrec, &ctxt, &sk[sp_priv->perm[0]]);
    printf("Recovered: "); g1_norm(mrec, mrec); g1_print(mrec);
#endif

    if(!anonvtr_user_verify_reencrypt( &msg->reencrypt_proof, msg->ctilde,
            msg->c, shuffled_pks, n, &msg->hprime, msg->record.ctxt.u,
            L, lL)) {
        printf("User reencryption proof does not verify!\n");
        return 0;
    }

#if 0
    // Verify verification keys in the TDH public key
    if(!tdh_pk_verify(msg->tdhpk)) {
        printf("User-provided TDH public key does not verify!\n");
        return 0;
    }
#endif

    // Verify verification keys in the TDH public key
    if(!tdh_pk_verify_probabilistic(msg->tdhpk)) {
        printf("User-provided TDH public key does not verify (prob)!\n");
        return 0;
    }

    return 1;
}

void anonvtr_sp_reconstruct_mod_messages(struct shuffle_elgamal_ctxt *res,
        struct anonvtr_msg_user *user_msg,
        struct anonvtr_msg_sp *sp_msg,
        struct anonvtr_sp_private *sp_priv, size_t n) {

    for(int i = 0; i < n; i++) {
        shuffle_elgamal_init(res + i, 2);
        shuffle_elgamal_derandomize(res + sp_priv->perm[i],
                user_msg->c + i, sp_priv->rand[i].rand[0]);
    }
}

size_t
anonvtr_msg_user_size(struct anonvtr_msg_user *m) {
    size_t res = 0;

    res += sizeof(size_t);

    for(int i = 0; i < m->n; i++) {
        res += shuffle_elgamal_size(m->chat + i);
        res += shuffle_elgamal_size(m->ctilde + i);
        res += shuffle_elgamal_size(m->c + i);
    }

    res += vtr_record_size(&m->record);
    res += shuffle_elgamal_pk_size(&m->hprime);

    res += anonvtr_proof_decshares_size(&m->decshare_proof, m->n);
    res += shuffle_proof_size(&m->shuffle_proof);
    res += anonvtr_proof_reencrypt_size(&m->reencrypt_proof, m->n);

    return res;
}


void
anonvtr_moderator_decrypt(struct tdh_dec_share *share,
        struct shuffle_elgamal_ctxt *ctxt,
        struct shuffle_elgamal_sk *sk, size_t n) {

    g1_t tmp;
    g1_null(tmp);
    g1_new(tmp);

    bn_t idx;
    bn_null(idx);
    bn_new(idx);

    g1_t m[2];
    shuffle_elgamal_decrypt(m, ctxt, sk);

    // Recover index, naive method
    share->i = -1;

    g1_norm(m[0], m[0]);
    for(int j = 1; j <= n && share->i == -1; j++) {
        bn_set_dig(idx, j);
        g1_mul_gen(tmp, idx);
        g1_norm(tmp, tmp);
        if(g1_cmp(m[0], tmp) == CMP_EQ) {
            share->i = j;
        }
    }

    // Assign decryption share
    g1_null(share->ui);
    g1_new(share->ui);
    g1_norm(share->ui, m[1]);
}
