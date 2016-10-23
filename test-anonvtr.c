#include "vtr.h"
#include "utils.h"
#include "anonvtr.h"
#include "sput.h"

#include <stdio.h>
#include <relic/relic.h>

#include <time.h>

#define NR_MODS 5
#define THRESHOLD 3

#define NR_TESTS 10
#define NR_EXPERIMENTS 1000

struct system {
    struct shuffle_elgamal_sk modsk[NR_MODS];
    struct shuffle_elgamal_pk modpk[NR_MODS];

    uint8_t *transaction;
    size_t ltransaction;

    uint8_t *epoch;
    size_t lepoch;

    bn_t x;
    struct bbsplus_pk bbspk;
    struct bbsplus_sign sign;

    struct shuffle_com_pk ck;
};

void
setup_system(struct system *sys) {
    for(int i = 0; i < NR_MODS; i++) {
        shuffle_elgamal_keygen(sys->modpk + i, sys->modsk + i);
    }
    shuffle_commit_keygen(&sys->ck, NR_MODS);

    sys->transaction = malloc(2);
    sys->transaction[0] = 33;
    sys->transaction[1] = 87;
    sys->ltransaction = 2;

    sys->epoch = malloc(2);
    sys->epoch[0] = 11;
    sys->epoch[1] = 37;
    sys->lepoch = 2;

    struct bbsplus_sk bbssk;
    bbsplus_keygen(&sys->bbspk, &bbssk, 2);

    bn_null(sys->x);
    bn_new(sys->x);
    bn_rand_mod(sys->x, sys->ck.q);

    bbsplus_sign(&sys->sign, &sys->bbspk, &bbssk, &sys->x, 1);
}

void
test_pk_encoding() {
    struct system sys;
    setup_system(&sys);

    struct shuffle_elgamal_pk stub_pk;
    struct shuffle_elgamal_ctxt encoded_modpk[NR_MODS];
    anonvtr_encode_pks(encoded_modpk, &stub_pk, sys.modpk, NR_MODS);

    int valid_encoding =
        anonvtr_verify_pk_encoding(sys.modpk, encoded_modpk, NR_MODS);

    sput_fail_unless(valid_encoding, "encoding of pks should validate");
}

void
test_sp_msg() {
    struct system sys;
    setup_system(&sys);

    struct anonvtr_msg_sp msg;
    struct anonvtr_sp_private priv;

    anonvtr_sp_randomize_pks(&msg, &priv, sys.modpk, NR_MODS,
            &sys.ck, sys.transaction, sys.ltransaction);

    int valid_sp_msg =
        anonvtr_verify_msg_sp(&msg, sys.modpk, NR_MODS, &sys.ck,
                sys.transaction, sys.ltransaction);

    sput_fail_unless(valid_sp_msg, "sp shuffle pks msg should be valid");
}

void
test_user_msg() {
    struct system sys;
    setup_system(&sys);

    struct anonvtr_msg_sp msg;
    struct anonvtr_sp_private priv;

    anonvtr_sp_randomize_pks(&msg, &priv, sys.modpk, NR_MODS,
            &sys.ck, sys.transaction, sys.ltransaction);

    struct anonvtr_msg_user msgu;
    anonvtr_user_message(&msgu, &msg, &sys.sign, sys.x, &sys.bbspk,
            &sys.ck, NR_MODS, THRESHOLD, sys.transaction, sys.ltransaction,
            sys.epoch, sys.lepoch);

    int valid_user_msg =
        anonvtr_verify_msg_user(&msgu, &msg,
                &sys.bbspk, &sys.ck,
                NR_MODS, THRESHOLD, sys.transaction, sys.ltransaction);

    sput_fail_unless(valid_user_msg, "User message should be valid");

    struct shuffle_elgamal_ctxt res[NR_MODS];
    anonvtr_sp_reconstruct_mod_messages(res, &msgu, &msg, &priv, NR_MODS);

    struct tdh_dec_share dec_shares[NR_MODS];
    for(int i = 0; i < NR_MODS; i++) {
        anonvtr_moderator_decrypt(dec_shares + i, res + i, &sys.modsk[i], NR_MODS);
        // printf("Recovered decryption share %i\n", dec_shares[i].i);
        // g1_print(dec_shares[i].ui);
    }

    g1_t linking_token;
    g1_null(linking_token);
    g1_new(linking_token);

    tdh_combine_base(&linking_token, &msgu.record.ctxt, msgu.tdhpk,
            dec_shares, THRESHOLD, 0);
    // printf("Recovered linking_token:\n");
    // g1_norm(linking_token, linking_token); g1_print(linking_token);

    // Verify linking token
    gt_t t2;
    gt_null(t2);
    gt_new(t2);
    pc_map(t2, linking_token, msgu.record.link_proof.t1);
    int linking_token_ok = gt_cmp(t2, msgu.record.link_proof.t2) == CMP_EQ;
    sput_fail_unless(linking_token_ok, "Recovered linking token shoul be valid");
}

void
test_step1_sp() {
    test_pk_encoding();
    test_sp_msg();
}

void
test_step2_user() {
    test_user_msg();
}

int
main(int argc, char **argv) {
    printf("Testing anonymous VtR scheme!\n");

    // Initialize relic
    if( core_init() != STS_OK ) {
        core_clean();
        printf("Error loading relic");
        return 1;
    }

    if( pc_param_set_any() != STS_OK ) {
        printf("Error: No curve!");
        return 1;
    }

    sput_start_testing();

    sput_enter_suite("Testing step 1 (from SP -> User)");
    sput_run_test(test_step1_sp);

    sput_enter_suite("Testing step 2 (from User -> SP)");
    sput_run_test(test_step2_user);

    sput_finish_testing();

    return sput_get_return_value();
}
