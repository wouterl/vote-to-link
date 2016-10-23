#include "shuffle.h"

#include <stdio.h>
#include <relic/relic.h>

struct anonvtr_sp_private {
    struct shuffle_elgamal_randomizer *rand;
    unsigned int *perm;
};

struct anonvtr_msg_sp {
    struct shuffle_elgamal_pk stub_pk;

    struct shuffle_elgamal_ctxt *encoded_pks;
    struct shuffle_elgamal_ctxt *shuffled_pks;

    struct shuffle_proof shuffle_proof;

    size_t n;
};

struct anonvtr_proof_decshares {
    bn_t challenge;

    bn_t xprimeresp;
    bn_t *kiresp;
    bn_t *riresp;
};

struct anonvtr_proof_reencrypt {
    bn_t challenge;

    struct shuffle_elgamal_randomizer *rtilderesp;
    struct shuffle_elgamal_randomizer *rresp;

    bn_t *idxresp;
    bn_t *kresp;
};

struct anonvtr_msg_user {
    struct tdh_pk *tdhpk;

    struct shuffle_elgamal_ctxt *chat;
    struct shuffle_elgamal_ctxt *ctilde;
    struct shuffle_elgamal_ctxt *c;

    struct vtr_record record;
    struct shuffle_elgamal_pk hprime;
    struct anonvtr_proof_decshares decshare_proof;

    struct shuffle_proof shuffle_proof;

    struct anonvtr_proof_reencrypt reencrypt_proof;

    size_t n;
};

void anonvtr_encode_pks(struct shuffle_elgamal_ctxt *ctxt,
        struct shuffle_elgamal_pk *stub_pk,
        struct shuffle_elgamal_pk *pk, size_t n);

int anonvtr_verify_pk_encoding(struct shuffle_elgamal_pk *pk,
        struct shuffle_elgamal_ctxt *ctxt, size_t n);

void anonvtr_sp_randomize_pks(struct anonvtr_msg_sp *msg,
        struct anonvtr_sp_private *priv,
        struct shuffle_elgamal_pk *pk, size_t n,
        struct shuffle_com_pk *ck, uint8_t *transaction,
        size_t ltransaction);

int anonvtr_verify_msg_sp(struct anonvtr_msg_sp *msg,
        struct shuffle_elgamal_pk *pk, size_t n,
        struct shuffle_com_pk *ck, uint8_t *transaction,
        size_t ltransaction);

size_t anonvtr_msg_sp_size(struct anonvtr_msg_sp *m);

void anonvtr_user_message(struct anonvtr_msg_user *msg,
        struct anonvtr_msg_sp *msg_sp,
        struct bbsplus_sign *sign, bn_t x, struct bbsplus_pk *bbspk,
        struct shuffle_com_pk *ck, size_t n, size_t k,
        uint8_t *L, size_t lL, uint8_t *epoch, size_t lepoch);

int anonvtr_verify_msg_user(struct anonvtr_msg_user *msg,
        struct anonvtr_msg_sp *msg_sp,
//        struct anonvtr_sp_private *sp_priv, struct shuffle_elgamal_sk *sk,
        struct bbsplus_pk *bbspk, struct shuffle_com_pk *ck,
        size_t n, size_t k, uint8_t *L, size_t lL);

size_t anonvtr_msg_user_size(struct anonvtr_msg_user *m);

void anonvtr_sp_reconstruct_mod_messages(struct shuffle_elgamal_ctxt *res,
        struct anonvtr_msg_user *user_msg,
        struct anonvtr_msg_sp *sp_msg,
        struct anonvtr_sp_private *sp_priv, size_t n);

void anonvtr_moderator_decrypt(struct tdh_dec_share *share,
        struct shuffle_elgamal_ctxt *ctxt,
        struct shuffle_elgamal_sk *sk, size_t n);
