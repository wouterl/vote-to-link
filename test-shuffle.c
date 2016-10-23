#include "shuffle.h"
#include "utils.h"
#include "sput.h"

#include <stdio.h>
#include <relic/relic.h>

#include <time.h>

#define NR_EXPERIMENTS 1000
#define SHUFFLE_SIZE 32
#define NR_TESTS 10

void
test_known_shuffle() {
    struct shuffle_com_pk pk;

    printf("Doing basic testing\n");
    shuffle_commit_keygen(&pk, SHUFFLE_SIZE);

    printf("Computing permutation\n");
    unsigned int perm[SHUFFLE_SIZE];

    unsafe_random_permutation(&perm[0], SHUFFLE_SIZE);
    printf("Permutation:\n");
    for(int i = 0; i < SHUFFLE_SIZE; i++) {
        printf("%i ", perm[i]);
    }
    printf("\n");

    bn_t msgs[SHUFFLE_SIZE];
    bn_t msgs_shuffled[SHUFFLE_SIZE];
    for(int i = 0; i < SHUFFLE_SIZE; i++) {
        bn_null(msgs[i]);
        bn_new(msgs[i]);
        bn_rand_mod(msgs[i], pk.q);

        printf("Msg %i: ", i); bn_print(msgs[i]);
    }

    for(int i = 0; i < SHUFFLE_SIZE; i++) {
        bn_null(msgs_shuffled[i]);
        bn_new(msgs_shuffled[i]);
        bn_copy(msgs_shuffled[i], msgs[perm[i]]);
        printf("MSH %i: ", i); bn_print(msgs_shuffled[i]);
    }

    clock_t tic, toc;

    struct shuffle_com c;
    bn_t r;
    bn_null(r);
    bn_new(r);
    bn_rand_mod(r, pk.q);
    printf("committing to shuffled messages\n");
    tic = clock();
    shuffle_commit_to(&c, msgs_shuffled, SHUFFLE_SIZE, r, &pk);
    toc = clock();
    printf("Time to commit to %i values: %e seconds\n", SHUFFLE_SIZE, (double)(toc - tic) / CLOCKS_PER_SEC);

    uint8_t context[] = {22, 44, 19};
    size_t lcontext = 3;

    printf("Computing known proof\n");
    struct shuffle_known_proof prf;
    shuffle_prove_known_content(&prf, &c, r, msgs, SHUFFLE_SIZE, &perm[0], &pk,
            &context[0], lcontext);

    printf("Verifying answer\n");
    if( shuffle_verify_known_content_proof(&prf, &c, msgs, SHUFFLE_SIZE,
                &pk, &context[0], lcontext) != 0) {
        printf("Known shuffle proof failed!!!\n");
    } else {
        printf("Known shuffle proof passed!\n");
    }
}

void
test_rand_from_stream() {
    uint8_t hash[MD_LEN_SH256];
    uint8_t msg = 33;

    md_map_sh256(&hash[0], &msg, 1);

    bn_t t[SHUFFLE_SIZE];
    bn_rands_from_stream(&t[0], SHUFFLE_SIZE, 20, &hash[0]);
    for(int i = 0; i < SHUFFLE_SIZE; i++) {
        printf("Random elt %03i: ", i); bn_print(t[i]);
    }
}


void
test_elgamal_encryption() {
    struct shuffle_elgamal_sk sk;
    struct shuffle_elgamal_pk pk;
    struct shuffle_elgamal_ctxt ctxt;

    shuffle_elgamal_keygen(&pk, &sk);
    g1_t msgs[NR_ELGAMAL_COMPONENTS];
    g1_t msgs_dec[NR_ELGAMAL_COMPONENTS];

    for(int j = 0; j < NR_ELGAMAL_COMPONENTS; j++) {
        g1_null(msgs[j]);
        g1_new(msgs[j]);
        g1_null(msgs_dec[j]);
        g1_new(msgs_dec[j]);
    }

    for(int n = 1; n <= NR_ELGAMAL_COMPONENTS; n++) {
        for(int i = 0; i < NR_TESTS; i++) {
            for(int j = 0; j < n; j++) {
                g1_rand(msgs[j]);
            }

            shuffle_elgamal_encrypt(&ctxt, &msgs[0], n, &pk);
            shuffle_elgamal_decrypt(&msgs_dec[0], &ctxt, &sk);

            for(int j = 0; j < n; j++) {
                // TODO: remove after cmp has been fixed in RELIC
                g1_norm(msgs_dec[j], msgs_dec[j]);
                sput_fail_unless(g1_cmp(msgs[j], msgs_dec[j]) == CMP_EQ,
                        "Incorrect recovery");
            }
        }
    }
}

void
test_elgamal_randomize() {
    struct shuffle_elgamal_sk sk;
    struct shuffle_elgamal_pk pk;
    struct shuffle_elgamal_ctxt ctxt;

    struct shuffle_elgamal_ctxt ctxt_empty, ctxt_randomized;
    struct shuffle_elgamal_randomizer randomizer;

    shuffle_elgamal_keygen(&pk, &sk);
    g1_t msgs[NR_ELGAMAL_COMPONENTS];
    g1_t msgs_dec[NR_ELGAMAL_COMPONENTS];

    for(int j = 0; j < NR_ELGAMAL_COMPONENTS; j++) {
        g1_null(msgs[j]);
        g1_new(msgs[j]);
        g1_null(msgs_dec[j]);
        g1_new(msgs_dec[j]);
    }

    for(int n = 1; n <= NR_ELGAMAL_COMPONENTS; n++) {
        for(int i = 0; i < NR_TESTS; i++) {
            for(int j = 0; j < n; j++) {
                g1_rand(msgs[j]);
            }

            shuffle_elgamal_encrypt(&ctxt, &msgs[0], n, &pk);

            // Randomize
            shuffle_elgamal_init(&ctxt_empty, n);
            shuffle_elgamal_init(&ctxt_randomized, n);

            shuffle_elgamal_randomizer(&randomizer, &ctxt, &pk);
            shuffle_elgamal_empty_ctxt(&ctxt_empty,  &randomizer, &pk);
            shuffle_elgamal_multiply(&ctxt_randomized, &ctxt, &ctxt_empty);

            for(int j = 0; j < n; j++) {
                // Normalize for cmp, remove at some point
                g1_norm(ctxt.c1[j], ctxt.c1[j]);
                g1_norm(ctxt.c2[j], ctxt.c2[j]);
                g1_norm(ctxt_randomized.c1[j], ctxt_randomized.c1[j]);
                g1_norm(ctxt_randomized.c2[j], ctxt_randomized.c2[j]);

                sput_fail_if(g1_cmp(ctxt.c1[j], ctxt_randomized.c1[j]) == CMP_EQ,
                        "Randomized components should be different");
                sput_fail_if(g1_cmp(ctxt.c2[j], ctxt_randomized.c2[j]) == CMP_EQ,
                        "Randomized components should be different");
            }

            shuffle_elgamal_decrypt(&msgs_dec[0], &ctxt_randomized, &sk);
 
            for(int j = 0; j < n; j++) {
                // TODO: remove after cmp has been fixed in RELIC
                g1_norm(msgs_dec[j], msgs_dec[j]);
                sput_fail_unless(g1_cmp(msgs[j], msgs_dec[j]) == CMP_EQ,
                        "Randomized ctxt should decrypt properly");
            }
        }
    }
}

void
test_shuffle_and_randomize() {
    struct shuffle_elgamal_sk sk;
    struct shuffle_elgamal_pk pk;

    struct shuffle_elgamal_ctxt ctxt[SHUFFLE_SIZE];

    // These will be filled using shuffle_and_randomize
    struct shuffle_elgamal_ctxt *ctxt_shuffled;
    struct shuffle_elgamal_randomizer *randomizer;

    unsigned int *perm;

    shuffle_elgamal_keygen(&pk, &sk);
    g1_t msgs[SHUFFLE_SIZE];

    for(int i = 0; i < SHUFFLE_SIZE; i++) {
        g1_null(msgs[i]);
        g1_new(msgs[i]);
        g1_rand(msgs[i]);

        shuffle_elgamal_encrypt(ctxt + i, msgs + i, 1, &pk);
    }

    shuffle_and_randomize(&ctxt[0], &ctxt_shuffled, &randomizer, &perm, SHUFFLE_SIZE, &pk);

    g1_t decrypted_msg;
    g1_null(decrypted_msg);
    g1_new(decrypted_msg);

    for(int i = 0; i < SHUFFLE_SIZE; i++) {
        shuffle_elgamal_decrypt(&decrypted_msg, ctxt_shuffled + i, &sk);

        // TODO remove when cmp is fixed
        g1_norm(decrypted_msg, decrypted_msg);
        sput_fail_unless(g1_cmp(msgs[perm[i]], decrypted_msg) == CMP_EQ,
                "Shuffling correctly decrypts");
    }
}

void
test_shuffle_proof() {
    struct shuffle_elgamal_sk sk;
    struct shuffle_elgamal_pk pk;
    struct shuffle_com_pk ck;

    struct shuffle_elgamal_ctxt ctxt[SHUFFLE_SIZE];

    // These will be filled using shuffle_and_randomize
    struct shuffle_elgamal_ctxt *ctxt_shuffled;
    struct shuffle_elgamal_randomizer *randomizer;

    unsigned int *perm;

    shuffle_elgamal_keygen(&pk, &sk);
    g1_t msgs[SHUFFLE_SIZE];

    for(int i = 0; i < SHUFFLE_SIZE; i++) {
        g1_null(msgs[i]);
        g1_new(msgs[i]);
        g1_rand(msgs[i]);

        shuffle_elgamal_encrypt(ctxt + i, msgs + i, 1, &pk);
    }

    shuffle_and_randomize(&ctxt[0], &ctxt_shuffled, &randomizer, &perm, SHUFFLE_SIZE, &pk);

    shuffle_commit_keygen(&ck, SHUFFLE_SIZE);

    uint8_t context[3] = {11, 88, 37};
    size_t lcontext = 3;

    struct shuffle_proof proof;
    shuffle_prove(&proof, &ctxt[0], ctxt_shuffled, SHUFFLE_SIZE,
            &pk, &ck, perm, randomizer, context, lcontext);

    int success = shuffle_proof_verify(&proof, ctxt, ctxt_shuffled, SHUFFLE_SIZE,
            &pk, &ck, context, lcontext);
    sput_fail_unless(success, "Shuffle proof should verify");

    // Changing tseed, proof should fail
    shuffle_prove(&proof, &ctxt[0], ctxt_shuffled, SHUFFLE_SIZE,
            &pk, &ck, perm, randomizer, context, lcontext);
    proof.tseed[0] = proof.tseed[0] + 1;
    success = shuffle_proof_verify(&proof, ctxt, ctxt_shuffled, SHUFFLE_SIZE,
            &pk, &ck, context, lcontext);
    sput_fail_if(success, "Incorrect shuffle proof should not verify");

    // Changing f[0], range check should fail
    shuffle_prove(&proof, &ctxt[0], ctxt_shuffled, SHUFFLE_SIZE,
            &pk, &ck, perm, randomizer, context, lcontext);
    bn_set_dig(proof.f[0], 1);
    success = shuffle_proof_verify(&proof, ctxt, ctxt_shuffled, SHUFFLE_SIZE,
            &pk, &ck, context, lcontext);
    sput_fail_if(success, "Incorrect shuffle proof should not verify");

    // Changing f[0], proof should fail
    shuffle_prove(&proof, &ctxt[0], ctxt_shuffled, SHUFFLE_SIZE,
            &pk, &ck, perm, randomizer, context, lcontext);
    bn_set_2b(proof.f[0], SHUFFLE_LENGTH_E + 1);
    success = shuffle_proof_verify(&proof, ctxt, ctxt_shuffled, SHUFFLE_SIZE,
            &pk, &ck, context, lcontext);
    sput_fail_if(success, "Incorrect shuffle proof should not verify");

    // Changing shuffle ciphertexts, should not verify
    shuffle_elgamal_copy(&ctxt_shuffled[1], &ctxt_shuffled[2]);
    shuffle_prove(&proof, &ctxt[0], ctxt_shuffled, SHUFFLE_SIZE,
            &pk, &ck, perm, randomizer, context, lcontext);
    success = shuffle_proof_verify(&proof, ctxt, ctxt_shuffled, SHUFFLE_SIZE,
            &pk, &ck, context, lcontext);
    sput_fail_if(success, "Incorrect shuffle proof should not verify");

}

void
test_shuffle_proof2() {
    struct shuffle_elgamal_sk sk;
    struct shuffle_elgamal_pk pk;
    struct shuffle_com_pk ck;

    struct shuffle_elgamal_ctxt ctxt[SHUFFLE_SIZE];

    // These will be filled using shuffle_and_randomize
    struct shuffle_elgamal_ctxt *ctxt_shuffled;
    struct shuffle_elgamal_randomizer *randomizer;

    unsigned int *perm;

    shuffle_elgamal_keygen(&pk, &sk);
    g1_t msgs[2*SHUFFLE_SIZE];

    for(int i = 0; i < 2*SHUFFLE_SIZE; i++) {
        g1_null(msgs[i]);
        g1_new(msgs[i]);
        g1_rand(msgs[i]);
    }

    for(int i = 0; i < SHUFFLE_SIZE; i++) {
        shuffle_elgamal_encrypt(ctxt + i, msgs + 2*i, 2, &pk);
    }

    shuffle_and_randomize(&ctxt[0], &ctxt_shuffled, &randomizer, &perm, SHUFFLE_SIZE, &pk);

    shuffle_commit_keygen(&ck, SHUFFLE_SIZE);

    uint8_t context[3] = {11, 88, 37};
    size_t lcontext = 3;

    struct shuffle_proof proof;
    shuffle_prove(&proof, &ctxt[0], ctxt_shuffled, SHUFFLE_SIZE,
            &pk, &ck, perm, randomizer, context, lcontext);

    int success = shuffle_proof_verify(&proof, ctxt, ctxt_shuffled, SHUFFLE_SIZE,
            &pk, &ck, context, lcontext);
    sput_fail_unless(success, "Shuffle proof (2) should verify");
}

int
main(int argc, char **argv) {
    printf("Testing Groth's shuffles!\n");

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

    pc_param_print();

    // test_rand_from_stream();

    test_known_shuffle();

    sput_start_testing();

    sput_enter_suite("Elgamal Encryption: encrypt/decrypt");
    sput_run_test(test_elgamal_encryption);

    sput_enter_suite("Elgamal Encryption: randomization");
    sput_run_test(test_elgamal_randomize);

    sput_enter_suite("Elgamal Encryption: shuffle and randomize");
    sput_run_test(test_shuffle_and_randomize);

    sput_enter_suite("Fully shuffle proof");
    test_shuffle_proof();
    test_shuffle_proof2();

    sput_finish_testing();

    return sput_get_return_value();
}
