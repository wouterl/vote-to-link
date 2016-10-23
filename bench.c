#include "vtr.h"
#include "anonvtr.h"
#include "utils.h"

#include <stdio.h>
#include <relic/relic.h>
#include <openssl/rand.h>

#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <time.h>

#define NR_EXPERIMENTS 10

#define TRANSACTION_LEN 32
#define EPOCH_LEN 16

#define VTR_NR_MODS 64
#define VTR_THRESHOLD 10

char *output_dir;

struct setup {
    uint8_t *transaction;
    size_t ltransaction;

    uint8_t *epoch;
    size_t lepoch;

    struct tdh_pk *tdhpk;
    struct tdh_sk *tdhsks;

    struct bbsplus_pk bbspk;
    struct bbsplus_sk bbssk;

    struct bbsplus_sign sign;
    bn_t x;

    struct shuffle_elgamal_pk *modpk;
    struct shuffle_elgamal_sk *modsk;

    struct shuffle_com_pk ck;
};

void
setup(struct setup *s) {
    s->transaction = malloc(TRANSACTION_LEN);
    RAND_bytes(s->transaction, TRANSACTION_LEN);
    s->ltransaction = TRANSACTION_LEN;

    s->epoch = malloc(EPOCH_LEN);
    RAND_bytes(s->epoch, EPOCH_LEN);
    s->lepoch = EPOCH_LEN;

    // Setup keys
    tdh_keygen(&s->tdhpk, &s->tdhsks, VTR_NR_MODS, VTR_THRESHOLD);
    bbsplus_keygen(&s->bbspk, &s->bbssk, 1);

    bn_null(s->x);
    bn_new(s->x);
    bn_rand_mod(s->x, s->tdhpk->q);

    bbsplus_sign(&s->sign, &s->bbspk, &s->bbssk, &s->x, 1);
}

void
setup_anon(struct setup *s, size_t nr_mods) {
    setup(s);

    s->modpk = malloc(nr_mods * sizeof(struct shuffle_elgamal_pk));
    s->modsk = malloc(nr_mods * sizeof(struct shuffle_elgamal_sk));

    for(int i = 0; i < nr_mods; i++) {
        shuffle_elgamal_keygen(s->modpk + i, s->modsk + i);
    }

    shuffle_commit_keygen(&s->ck, nr_mods);
}

int
test_performance_vtr() {
    struct vtr_record trans[NR_EXPERIMENTS];
    clock_t tic, toc;

    struct setup s;
    setup(&s);

    tic = clock();
    for(int i = 0; i < NR_EXPERIMENTS; i++) {
        vtr_transact(&trans[i], &s.sign, s.x, s.tdhpk, &s.bbspk,
                s.transaction, s.ltransaction, s.epoch, s.lepoch);
    }
    toc = clock();
    printf("PerformTransact (user): %e seconds\n",
            (double)(toc - tic) / CLOCKS_PER_SEC / NR_EXPERIMENTS);

    tic = clock();
    for(int i = 0; i < NR_EXPERIMENTS; i++) {
        if(!vtr_verify_transaction(&trans[i], s.tdhpk, &s.bbspk)) {
            printf("ERROR: vtr transaction incorrect!");
            return 0;
        }
    }
    toc = clock();
    printf("PerformTransact (sp):   %e seconds\n",
            (double)(toc - tic) / CLOCKS_PER_SEC / NR_EXPERIMENTS);

    struct tdh_dec_share dec_shares[NR_EXPERIMENTS];
    tic = clock();
    for(int i = 0; i < NR_EXPERIMENTS; i++) {
        tdh_share_dec(dec_shares + i, &trans[i].ctxt, s.tdhpk,
                s.tdhsks + (i % VTR_NR_MODS));
    }
    toc = clock();
    printf("VoteToLink:             %e seconds\n",
            (double)(toc - tic) / CLOCKS_PER_SEC / NR_EXPERIMENTS);

    // Actually decrypt trans[0]
    for(int i = 0; i < VTR_THRESHOLD; i++) {
        tdh_share_dec(dec_shares + i, &trans[0].ctxt, s.tdhpk,
                s.tdhsks + i);
    }

    g1_t linking_token;
    g1_null(linking_token);
    g1_new(linking_token);
    tic = clock();
    for(int i = 0; i < NR_EXPERIMENTS; i++) {
        tdh_combine(&linking_token, &trans[0].ctxt, s.tdhpk,
            dec_shares, VTR_THRESHOLD);
    }
    toc = clock();
    printf("Combine:                %e seconds\n",
            (double)(toc - tic) / CLOCKS_PER_SEC / NR_EXPERIMENTS);

    gt_t t2;
    gt_null(t2);
    gt_new(t2);
    tic = clock();
    for(int i = 0; i < NR_EXPERIMENTS; i++) {
        pc_map(t2, linking_token, trans[i].link_proof.t1);
        if(gt_cmp(t2, trans[i].link_proof.t2) != CMP_EQ) {
            printf("ERROR: recovered linking token incorrect!\n");
            return 0;
        }
    }
    toc = clock();
    printf("Link check (n = %5i): %e seconds\n", NR_EXPERIMENTS,
            (double)(toc - tic) / CLOCKS_PER_SEC);


    printf("Size of transaction record: %zu bytes\n", vtr_record_size(trans));

    return 1;
}

int
test_performance_anonvtr(size_t nr_mods, size_t threshold) {
    clock_t tic, toc;

    struct setup s;
    setup_anon(&s, nr_mods);

    struct anonvtr_msg_sp msg;
    struct anonvtr_sp_private priv;

    // Open file for writing
    FILE *f = NULL;
    if(output_dir) {
        char buf[1024];
        strcpy(buf, output_dir);
        sprintf(buf + strlen(output_dir), "performance-k-%zu.dat", threshold);
        printf("Writing to file: %s\n", buf);
        f = fopen(buf, "a");
    }


    tic = clock();
    for(int i = 0; i < NR_EXPERIMENTS; i++) {
        anonvtr_sp_randomize_pks(&msg, &priv, s.modpk, nr_mods,
                &s.ck, s.transaction, s.ltransaction);
    }
    toc = clock();
    double time_randomize_sp = (double)(toc - tic) / CLOCKS_PER_SEC / NR_EXPERIMENTS;
    printf("PerformTransact (randomize-sp): %e seconds\n", time_randomize_sp);

    struct anonvtr_msg_user msgu[NR_EXPERIMENTS];
    tic = clock();
    for(int i = 0; i < NR_EXPERIMENTS; i++) {
        anonvtr_user_message(msgu + i, &msg, &s.sign, s.x, &s.bbspk,
                &s.ck, nr_mods, threshold, s.transaction, s.ltransaction,
                s.epoch, s.lepoch);
    }
    toc = clock();
    double time_user = (double)(toc - tic) / CLOCKS_PER_SEC / NR_EXPERIMENTS;
    printf("PerformTransact (user):         %e seconds\n", time_user);


    struct shuffle_elgamal_ctxt *res =
        malloc(nr_mods * sizeof(struct shuffle_elgamal_ctxt));
    tic = clock();
    for(int i = 0; i < NR_EXPERIMENTS; i++) {
        if(!anonvtr_verify_msg_user(msgu + i, &msg,
                &s.bbspk, &s.ck, nr_mods, threshold,
                s.transaction, s.ltransaction)) {
            printf("ERROR: user message incorrect!\n");
            return 0;
        }
        anonvtr_sp_reconstruct_mod_messages(res, msgu + i, &msg, &priv, nr_mods);
    }
    toc = clock();
    double time_verify_sp = (double)(toc - tic) / CLOCKS_PER_SEC / NR_EXPERIMENTS;
    printf("PerformTransact (verify-sp):    %e seconds\n", time_verify_sp);

    struct tdh_dec_share dec_share;
    tic = clock();
    for(int i = 0; i < NR_EXPERIMENTS; i++) {
        anonvtr_moderator_decrypt(&dec_share, res + i, &s.modsk[i], nr_mods);
    }
    toc = clock();
    double time_decrypt = (double)(toc - tic) / CLOCKS_PER_SEC / NR_EXPERIMENTS;
    printf("VoteToLink (mod):    %e seconds\n", time_decrypt);

    double time_total = time_randomize_sp + time_user + time_verify_sp;
    printf("PerformTransact (total):        %e seconds\n", time_total);

    printf("Size of SP message:   %9zu bytes\n", anonvtr_msg_sp_size(&msg));
    printf("Size of User message: %9zu bytes\n", anonvtr_msg_user_size(msgu));

    if(f) {
        fprintf(f, "Num_moderators Threshold Time Time_SP_Randomize Time_User Time_SP_Verify\n");
        fprintf(f, "%zu %zu %e %e %e %e\n", nr_mods, threshold, time_total,
                time_randomize_sp, time_user, time_verify_sp);
        fclose(f);
    }

    return 0;
}


int
main(int argc, char **argv) {
    if(argc > 1) {
        struct stat s;
        int err = stat(argv[1], &s);
        if(err == -1) {
            if(errno == ENOENT) {
                printf("Supplied directory %s does not exist. Create it.\n", argv[1]);
                exit(1);
            } else {
                printf("Something wrong with your directory\n");
                exit(1);
            }
        } else {
            if(S_ISDIR(s.st_mode)) {
                printf("Writing output to %s\n", argv[1]);
                output_dir = argv[1];
            } else {
                printf("Supplied file %s is not a directory!\n", argv[1]);
            }
        }
    } else {
        output_dir = NULL;
    }


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

    printf("++++ PERFORMANCE OF VOTE-TO-REVOKE ++++\n\n");
    int vtr_ok = test_performance_vtr();

    int threshold = 32;
    for(int nr_mods = 64; nr_mods <= 1024; nr_mods *= 2) {
        printf("\n\n++++ PERFORMANCE OF ANONYMOUS VOTE-TO-REVOKE (n = %i, k = %i) ++++\n", nr_mods, threshold);
        test_performance_anonvtr(nr_mods, threshold);
    }

    threshold = 128;
    for(int nr_mods = 128; nr_mods <= 1024; nr_mods *= 2) {
        printf("\n\n++++ PERFORMANCE OF ANONYMOUS VOTE-TO-REVOKE (n = %i, k = %i) ++++\n", nr_mods, threshold);
        test_performance_anonvtr(nr_mods, threshold);
    }

    return vtr_ok;
}
