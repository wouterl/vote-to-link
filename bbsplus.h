#include <relic/relic.h>

#define BBSPLUS_CHALLENGE_SEC_PAR 160

struct bbsplus_pk {
    g1_t *bases;
    size_t nr_bases;
    g2_t w;

    // Used for commitments in disclosure proof
    g1_t g1bar;

    bn_t q;
    
    // Precomputed pairing values
    gt_t pairing_g1_g2;
    gt_t pairing_g1bar_w;
    gt_t pairing_g1bar_g2;
    gt_t *pairing_bases_g2;
};

struct bbsplus_sk {
    bn_t x;
};

struct bbsplus_sign {
    g1_t A;
    bn_t e;
    bn_t s;
};

struct bbsplus_proof_randomizers {
    bn_t r1, r2;
    bn_t r1hat, r2hat;
    bn_t a1hat, a2hat;
    bn_t ehat;
    bn_t shat;
    bn_t *mhat;

    size_t nr_msgs;
};

struct bbsplus_proof_commitments {
    g1_t C1, C2;
    g1_t C2hat, C2hathat;
    gt_t Phat;

};

struct bbsplus_proof {
    g1_t C1, C2;
    bn_t r1resp;
    bn_t r2resp;
    bn_t a1resp;
    bn_t a2resp;
    bn_t eresp;
    bn_t sresp;

    bn_t *mresps;
    size_t nr_mresps;

    bn_t challenge;
};

void bbsplus_keygen(struct bbsplus_pk *pk, struct bbsplus_sk *sk, size_t nr_attributes);

void bbsplus_pk_free(struct bbsplus_pk *pk);
void bbsplus_sk_free(struct bbsplus_sk *sk);

void bbsplus_sign(struct bbsplus_sign *sign, struct bbsplus_pk *pk, struct bbsplus_sk *sk, bn_t *msgs, size_t nr_msgs);

int bbsplus_verify(struct bbsplus_sign *sign, struct bbsplus_pk *pk, bn_t *msgs, size_t nr_msgs);

void bbsplus_prove(struct bbsplus_proof *proof, struct bbsplus_sign *sign,
        struct bbsplus_pk *pk, bn_t *msgs, size_t nr_msgs,
        uint8_t *L, size_t lL);

void bbsplus_proof_randomizers(struct bbsplus_proof_randomizers *rand,
        struct bbsplus_pk *pk, size_t nr_msgs);

void bbsplus_proof_randomizers_free(struct bbsplus_proof_randomizers *rand);

void bbsplus_proof_commitments(struct bbsplus_proof_commitments *coms,
        struct bbsplus_proof_randomizers *rand, struct bbsplus_sign *sign,
        struct bbsplus_pk *pk, size_t nr_msgs);

void bbsplus_proof_commitments_free(struct bbsplus_proof_commitments *coms);

int bbsplus_proof_commitments_size(struct bbsplus_proof_commitments *coms);
void bbsplus_proof_commitments_write_bin(uint8_t *ptr,
        size_t len, struct bbsplus_proof_commitments *coms);

void bbsplus_proof_challenge(bn_t c, struct bbsplus_proof_commitments *coms,
        uint8_t *L, size_t lL);

void bbsplus_proof_create(struct bbsplus_proof *proof,
        struct bbsplus_proof_randomizers *rand,
        struct bbsplus_proof_commitments *coms,
        struct bbsplus_sign *sign, bn_t *msgs, struct bbsplus_pk *pk,
        bn_t c, size_t nr_msgs);

void bbsplus_proof_free(struct bbsplus_proof *proof);

void bbsplus_proof_reconstruct_commitments(
        struct bbsplus_proof_commitments *coms,
        struct bbsplus_proof *proof, struct bbsplus_pk *pk, size_t nr_msgs);

int bbsplus_proof_verify(struct bbsplus_proof *proof, struct bbsplus_pk *pk, size_t nr_msgs, uint8_t *L, size_t lL);

size_t bbsplus_proof_size(struct bbsplus_proof *p);
