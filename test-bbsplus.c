#include "bbsplus.h"
#include "utils.h"

#include <stdio.h>
#include <relic/relic.h>

#include <time.h>

#define NR_TESTS 10
#define NR_EXPERIMENTS 100

int
main(int argc, char **argv) {
    printf("Testing BBS+ credentials!\n");

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

    printf("\nDoing basic tests: ");
    struct bbsplus_pk pk;
    struct bbsplus_sk sk;

    bn_t msgs[2];
    for(int i = 0; i < 2; i++) {
        bn_null(msgs[i]);
        bn_new(msgs[i]);
    }

    struct bbsplus_sign sign;
    struct bbsplus_proof proof;

    uint8_t L[] = {8, 44, 18};
    size_t lL = 3;

    for(int i = 0; i < NR_TESTS; i++) {
        bbsplus_keygen(&pk, &sk, 2);

        for(int j = 0; j < 2; j++) {
            bn_rand_mod(msgs[j], pk.q);
        }

        bbsplus_sign(&sign, &pk, &sk, &msgs[0], 2);

        if(!bbsplus_verify(&sign, &pk, &msgs[0], 2)) {
            printf("ERROR: signature invalid\n");
            return 1;
        }

        bbsplus_prove(&proof, &sign, &pk, &msgs[0], 2, &L[0], lL);
        if(!bbsplus_proof_verify(&proof, &pk, 2, &L[0], lL)) {
            printf("ERROR: proof doesn't verify\n");
            return 1;
        }

        bbsplus_proof_free(&proof);
        bbsplus_pk_free(&pk);
        bbsplus_sk_free(&sk);
    }
    printf("\nTest passed!\n");

    printf("Doing performance tests\n");
    clock_t tic, toc;

    bbsplus_keygen(&pk, &sk, 2);
    for(int i = 0; i < 2; i++) {
        bn_rand_mod(msgs[i], pk.q);
    }
    bbsplus_sign(&sign, &pk, &sk, &msgs[0], 2);

    tic = clock();
    struct bbsplus_proof proofs[NR_EXPERIMENTS];
    for(int i = 0; i < NR_EXPERIMENTS; i++) {
        bbsplus_prove(proofs + i, &sign, &pk, &msgs[0], 2, &L[0], lL);
    }
    toc = clock();
    printf("Time per disclosure proof: %e seconds\n", (double)(toc - tic) / CLOCKS_PER_SEC / NR_EXPERIMENTS);

    tic = clock();
    for(int i = 0; i < NR_EXPERIMENTS; i++) {
        bbsplus_proof_verify(proofs + i, &pk, 2, &L[0], lL);
    }
    toc = clock();
    printf("Time per disclosure proof verification: %e seconds\n", (double)(toc - tic) / CLOCKS_PER_SEC / NR_EXPERIMENTS);

    // Cleanup proofs
    for(int i = 0; i < NR_EXPERIMENTS; i++) {
        bbsplus_proof_free(proofs + i);
    }
    bbsplus_pk_free(&pk);
    bbsplus_sk_free(&sk);

    return 0;
}
