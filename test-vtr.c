#include "vtr.h"
#include "utils.h"

#include <stdio.h>
#include <relic/relic.h>

#include <time.h>

#define NR_TESTS 10
#define NR_EXPERIMENTS 1000

int
main(int argc, char **argv) {
    printf("Testing basic VtR scheme!\n");

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

    struct tdh_pk *tdhpk;
    struct tdh_sk *sks;

    struct bbsplus_pk bbspk;
    struct bbsplus_sk bbssk;
    struct bbsplus_sign sign;

    struct vtr_record trans;

    uint8_t transaction[] = {8, 44, 18};
    size_t ltransaction = 3;

    uint8_t epoch[] = {24, 7, 14};
    size_t lepoch = 3;

    printf("\nDoing basic tests: ");
    bn_t x;
    bn_null(x);
    bn_new(x);

    for(int i = 0; i < NR_TESTS; i++) {
        tdh_keygen(&tdhpk, &sks, 10, 3);
        bbsplus_keygen(&bbspk, &bbssk, 2);
        bn_rand_mod(x, tdhpk->q);
        bbsplus_sign(&sign, &bbspk, &bbssk, &x, 1);
        vtr_transact(&trans, &sign, x, tdhpk, &bbspk, &transaction[0], ltransaction, &epoch[0], lepoch);
        if(!vtr_verify_transaction(&trans, tdhpk, &bbspk)) {
            printf("\nTransaction proof does not verify!\n");
            return 1;
        } else {
            printf("+");
        }

        tdh_sks_free(sks, tdhpk->n);
        tdh_pk_free(tdhpk);

        bbsplus_pk_free(&bbspk);
        bbsplus_sk_free(&bbssk);
    }
    printf("\nTests passed\n");
}
