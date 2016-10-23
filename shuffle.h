#include <relic/relic.h>

#define NR_ELGAMAL_COMPONENTS 2

// Sizes in bits
#define SHUFFLE_LENGTH_E 160
#define SHUFFLE_LENGTH_S  80

struct shuffle_com_pk {
    g1_t *bases;
    g1_t rand_base;

    size_t nr_bases;
    bn_t q;
};

struct shuffle_com {
    g1_t com;
    size_t n;
};

struct shuffle_elgamal_sk {
    bn_t sk;
};

struct shuffle_elgamal_pk {
    g1_t gen;
    g1_t pk;

    bn_t q;
};

struct shuffle_elgamal_randomizer {
    size_t n;
    bn_t rand[NR_ELGAMAL_COMPONENTS];
};

/*
 * Elgamal ciphertext encoding n messages
 */
struct shuffle_elgamal_ctxt {
    size_t n;
    g1_t c1[NR_ELGAMAL_COMPONENTS];
    g1_t c2[NR_ELGAMAL_COMPONENTS];
};

struct shuffle_known_proof {
    size_t n;

    bn_t x;
    bn_t e;

    struct shuffle_com cd, cdelta, ca;

    bn_t *f;
    bn_t z;
    bn_t *fdelta;
    bn_t zdelta;
};

struct shuffle_proof {
    size_t n;

    struct shuffle_com c, cd;
    struct shuffle_elgamal_ctxt Ed;

    uint8_t tseed[MD_LEN_SH256];

    bn_t *f;
    struct shuffle_elgamal_randomizer Z;

    uint8_t lambdabase[MD_LEN_SH256];

    struct shuffle_known_proof known_proof;
};

void unsafe_random_permutation(unsigned int *perm, size_t n);

// ****************************
// Pederson's commitment scheme
// ****************************

void shuffle_commit_keygen(struct shuffle_com_pk *pk, size_t n);

void shuffle_commit_new(struct shuffle_com *com, size_t n);

void shuffle_commit_to(struct shuffle_com *com, bn_t *vals, size_t n, bn_t r,
        struct shuffle_com_pk *pk);

void shuffle_commit_exp(struct shuffle_com *res, struct shuffle_com *com,
        bn_t exp);

void shuffle_commit_mul(struct shuffle_com *res, struct shuffle_com *com,
        struct shuffle_com *mul);

void shuffle_commit_print(struct shuffle_com *com);

int shuffle_commit_equal(struct shuffle_com *left, struct shuffle_com *right);

// ******************
// ElGamal encryption
// ******************

void shuffle_elgamal_keygen(struct shuffle_elgamal_pk *pk,
        struct shuffle_elgamal_sk *sk);

void shuffle_elgamal_init(struct shuffle_elgamal_ctxt *ctxt, size_t n);

void shuffle_elgamal_randomizer(struct shuffle_elgamal_randomizer *rand,
        struct shuffle_elgamal_ctxt *ctxt, struct shuffle_elgamal_pk *pk);

void shuffle_elgamal_randomizer_init(struct shuffle_elgamal_randomizer *rand,
        struct shuffle_elgamal_ctxt *ctxt);

void shuffle_elgamal_randomizer_add(
        struct shuffle_elgamal_randomizer *res,
        struct shuffle_elgamal_randomizer *a,
        struct shuffle_elgamal_randomizer *b,
        struct shuffle_elgamal_pk *pk);

void
shuffle_elgamal_randomizer_multiply(
        struct shuffle_elgamal_randomizer *res,
        struct shuffle_elgamal_randomizer *a,
        bn_t t, struct shuffle_elgamal_pk *pk);

size_t
shuffle_elgamal_randomizer_size( struct shuffle_elgamal_randomizer *rand);

void shuffle_elgamal_empty_ctxt(struct shuffle_elgamal_ctxt *ctxt,
        const struct shuffle_elgamal_randomizer *rand,
        const struct shuffle_elgamal_pk *pk);

void shuffle_elgamal_exp(struct shuffle_elgamal_ctxt *res,
        const struct shuffle_elgamal_ctxt *a,
        const bn_t exp);

void shuffle_elgamal_copy(struct shuffle_elgamal_ctxt *ctxt,
        struct shuffle_elgamal_ctxt *orig);

void shuffle_elgamal_multiply(struct shuffle_elgamal_ctxt *res,
        const struct shuffle_elgamal_ctxt *a,
        const struct shuffle_elgamal_ctxt *b);

void shuffle_elgamal_encrypt(struct shuffle_elgamal_ctxt *ctxt,
        g1_t *msgs, size_t n, struct shuffle_elgamal_pk *pk);

void shuffle_elgamal_encrypt_with_randomizer(
        struct shuffle_elgamal_ctxt *ctxt, g1_t *msgs,
        size_t n, struct shuffle_elgamal_randomizer *rand,
        struct shuffle_elgamal_pk *pk);

void shuffle_elgamal_decrypt(g1_t *msgs, struct shuffle_elgamal_ctxt *ctxt,
        struct shuffle_elgamal_sk *sk);

size_t shuffle_elgamal_size(struct shuffle_elgamal_ctxt *ctxt);

size_t shuffle_elgamal_pk_size(struct shuffle_elgamal_pk *pk);

void shuffle_elgamal_write_bin(uint8_t *ptr, struct shuffle_elgamal_ctxt *ctxt);

void shuffle_elgamal_derandomize( struct shuffle_elgamal_ctxt *res,
        struct shuffle_elgamal_ctxt *a, bn_t rand);

// ***********************
// Proof of known contents
// ***********************

void shuffle_prove_known_content(struct shuffle_known_proof *proof,
        struct shuffle_com *c, bn_t r, bn_t *vals, size_t n,
        unsigned int *perm, struct shuffle_com_pk *pk, uint8_t *context,
        size_t lcontext);

int shuffle_verify_known_content_proof(struct shuffle_known_proof *proof,
        struct shuffle_com *c, bn_t *vals, size_t n,
        struct shuffle_com_pk *pk, uint8_t *context, size_t lcontext);

size_t shuffle_known_proof_size(struct shuffle_known_proof *p);

void shuffle_and_randomize( struct shuffle_elgamal_ctxt *e,
        struct shuffle_elgamal_ctxt **E_res,
        struct shuffle_elgamal_randomizer **rand_res,
        unsigned int **perm_res,
        size_t n, struct shuffle_elgamal_pk *pk);

void
shuffle_prove(struct shuffle_proof *proof,
        struct shuffle_elgamal_ctxt *e, struct shuffle_elgamal_ctxt *E,
        size_t n, struct shuffle_elgamal_pk *pk, struct shuffle_com_pk *ck,
        unsigned int *perm, struct shuffle_elgamal_randomizer *R,
        uint8_t *context, size_t lcontext);

int
shuffle_proof_verify(struct shuffle_proof *proof,
        struct shuffle_elgamal_ctxt *e, struct shuffle_elgamal_ctxt *E,
        size_t n, struct shuffle_elgamal_pk *pk, struct shuffle_com_pk *ck,
        uint8_t *context, size_t lcontext);

size_t shuffle_proof_size(struct shuffle_proof *p);

void shuffle_elgamal_print(struct shuffle_elgamal_ctxt *ctxt);
