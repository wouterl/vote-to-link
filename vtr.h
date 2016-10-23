#include <relic/relic.h>
#include "tdh.h"
#include "bbsplus.h"

#define VTR_CHALLENGE_SEC_PAR 160

struct vtr_proof_randomizers {
    bn_t z;
    bn_t a;

    bn_t rhat;
    bn_t zhat;
    bn_t ahat;
    bn_t xhat;
};

struct vtr_proof_commitments {
    g2_t t1;
    gt_t t2;

    g1_t chat;
    g2_t t1hat;
    gt_t t2hat;
    g2_t t1hhat;
};

struct vtr_proof {
    g2_t t1;
    gt_t t2;

    bn_t challenge;

    bn_t xresp;
    bn_t zresp;
    bn_t aresp;
    bn_t rresp;
};

struct vtr_record {
    g1_t gepoch;

    uint8_t *transaction;
    size_t ltransaction;

    uint8_t *epoch;
    size_t lepoch;

    struct tdh_ctxt ctxt;
    struct bbsplus_proof cred_proof;
    struct vtr_proof link_proof;
};

void
vtr_transact(struct vtr_record *trans, struct bbsplus_sign *sign,
        bn_t x, struct tdh_pk *tdhpk, struct bbsplus_pk *bbspk, uint8_t *L,
        size_t lL, uint8_t *epoch, size_t lepoch);

void vtr_proof_randomizers(struct vtr_proof_randomizers *rand,
        bn_t x, struct tdh_pk *pk);

void vtr_proof_commitments(struct vtr_proof_commitments *coms,
        struct vtr_proof_randomizers *rand, g1_t gepoch,
        struct tdh_pk *pk);

int vtr_proof_commitments_size(struct vtr_proof_commitments *coms);

void vtr_proof_commitments_write_bin(uint8_t *ptr,
        size_t len, struct vtr_proof_commitments *coms);

void vtr_proof_combined_challenge(bn_t c,
        struct vtr_proof_commitments *vtrcoms,
        struct bbsplus_proof_commitments *bbscoms,
        uint8_t *L, size_t lL);

void vtr_proof_create(struct vtr_proof *proof,
        struct vtr_proof_randomizers *rand,
        struct vtr_proof_commitments *coms,
        bn_t x, bn_t r, struct tdh_pk *pk, bn_t c);

size_t vtr_proof_size(struct vtr_proof *p);

void vtr_verify_reconstruct_commitments(struct vtr_proof_commitments *coms,
        struct vtr_proof *proof, g1_t gepoch, struct tdh_ctxt *ctxt,
        struct tdh_pk *pk);

int
vtr_verify_proof(struct vtr_proof *proof, g1_t gepoch, struct tdh_ctxt *ctxt,
        struct tdh_pk *pk, uint8_t *L, size_t lL);

int
vtr_verify_transaction(struct vtr_record *trans, struct tdh_pk *tdhpk,
        struct bbsplus_pk *bbspk);

size_t vtr_record_size(struct vtr_record *t);
