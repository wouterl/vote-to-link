#include "tdh.h"
#include "utils.h"

#include <stdio.h>
#include <relic/relic.h>

#include <time.h>

#define NR_TESTS 10
#define NR_EXPERIMENTS 1000

int
main(int argc, char **argv) {
    printf("Testing TDH encryption!\n");

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

    struct tdh_pk *pk;
    struct tdh_sk *sks;
    struct tdh_ctxt ctxt;
    struct tdh_dec_share ctxtshare[3];

    g1_t m;
    g1_null(m);
    g1_new(m);

    g1_t m_recovered;
    g1_null(m_recovered);
    g1_new(m_recovered);

    uint8_t L[] = {8, 44, 18};
    size_t lL = 3;

    printf("\nDoing basic tests: ");

    for(int i = 0; i < NR_TESTS; i++) {
        tdh_keygen(&pk, &sks, 10, 3);

        if(!tdh_pk_verify(pk)) {
            printf("Key doesn't verify!!\n");
            return 1;
        }

        if(!tdh_pk_verify_probabilistic(pk)) {
            printf("Key doesn't verify probabilistically!!\n");
            return 1;
        }

        g1_rand(m);

        tdh_enc(&ctxt, pk, m, &L[0], lL);
        if(!tdh_ctxt_verify(&ctxt, pk)){
            printf("Ctxt doesn't verify!!");
            return 1;
        }

        int idxs[] = {2,5,8};
        for(int i = 0; i < 3; i++) {
            int idx = idxs[i];
            tdh_share_dec(&ctxtshare[i], &ctxt, pk, &sks[idx]);
            if(!tdh_share_verify(&ctxtshare[i], &ctxt, pk)) {
                printf("Ctxt share doesn't verify!");
                return 1;
            }
        }

        tdh_combine(&m_recovered, &ctxt, pk, &ctxtshare[0], 3);

        if(g1_cmp(m, m_recovered) == 0) {
            printf("+");
        } else {
            printf("Incorrect recovery!!\n");
            return 1;
        }

        tdh_sks_free(sks, pk->n);
        tdh_pk_free(pk);
    }
    printf("\nTest passed!\n");

    printf("Doing performance tests\n");
    clock_t tic, toc;

    tdh_keygen(&pk, &sks, 10, 3);
    g1_rand(m);
    
    tic = clock();
    for(int i = 0; i < NR_EXPERIMENTS; i++) {
        tdh_enc(&ctxt, pk, m, &L[0], lL);
    }
    toc = clock();
    printf("Time per encryption: %e seconds\n", (double)(toc - tic) / CLOCKS_PER_SEC / NR_EXPERIMENTS);

    tic = clock();
    for(int i = 0; i < NR_EXPERIMENTS; i++) {
        tdh_share_dec(&ctxtshare[0], &ctxt, pk, &sks[i % 10]);
    }
    toc = clock();
    printf("Time per dec-share: %e seconds\n", (double)(toc - tic) / CLOCKS_PER_SEC / NR_EXPERIMENTS);

    tdh_sks_free(sks, pk->n);
    tdh_pk_free(pk);

    tdh_keygen(&pk, &sks, 100, 30);
    tic = clock();
    for(int i = 0; i < 10; i++) {
        tdh_pk_verify(pk);
    }
    toc = clock();
    printf("Time per pk verification (n = 100, k = 30): %e seconds\n", (double)(toc - tic) / CLOCKS_PER_SEC / 10);

    tdh_sks_free(sks, pk->n);
    tdh_pk_free(pk);

    g1_free(m_recovered);
    g1_free(m);

    return 0;
}
