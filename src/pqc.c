#include <crypto_kem/ml-kem-1024/clean/api.h>
#include <crypto_sign/falcon-padded-512/clean/api.h>
#include <crypto_sign/ml-dsa-87/clean/api.h>
#include <stddef.h>
#include <stdint.h>

#include "pqc.h"
#include "types.h"

// =====================================================================
// Algorithm Info Table
// =====================================================================
static const pqc_algo_info_t pqc_algos[] = {
    {
        .type = KEM_MLKEM1024,
        .name = "KEM-ML-KEM-1024",
        .public_key_len = PQCLEAN_MLKEM1024_CLEAN_CRYPTO_PUBLICKEYBYTES,
        .private_key_len = PQCLEAN_MLKEM1024_CLEAN_CRYPTO_SECRETKEYBYTES,
        .ciphertext_len = PQCLEAN_MLKEM1024_CLEAN_CRYPTO_CIPHERTEXTBYTES,
        .shared_key_len = PQCLEAN_MLKEM1024_CLEAN_CRYPTO_BYTES,
        .signature_len = 0
    },
    {
        .type = SIGN_FALCONPADDED512,
        .name = "SIGN-Falcon-padded-512",
        .public_key_len = PQCLEAN_FALCONPADDED512_CLEAN_CRYPTO_PUBLICKEYBYTES,
        .private_key_len = PQCLEAN_FALCONPADDED512_CLEAN_CRYPTO_SECRETKEYBYTES,
        .ciphertext_len = 0,
        .shared_key_len = 0,
        .signature_len = PQCLEAN_FALCONPADDED512_CLEAN_CRYPTO_BYTES
    },
    {
        .type = SIGN_MLDSA87,
        .name = "SIGN-ML-DSA-87",
        .public_key_len = PQCLEAN_MLDSA87_CLEAN_CRYPTO_PUBLICKEYBYTES,
        .private_key_len = PQCLEAN_MLDSA87_CLEAN_CRYPTO_SECRETKEYBYTES,
        .ciphertext_len = 0,
        .shared_key_len = 0,
        .signature_len = PQCLEAN_MLDSA87_CLEAN_CRYPTO_BYTES
    }
};

const pqc_algo_info_t *get_pqc_info(algo_type_t algo) {
    for (size_t i = 0; i < sizeof(pqc_algos)/sizeof(pqc_algos[0]); ++i) {
        if (pqc_algos[i].type == algo)
            return &pqc_algos[i];
    }
    return NULL;
}

// =====================================================================
// KEM
// =====================================================================
status_t kem_generate_keypair(uint8_t *pk, uint8_t *sk, algo_type_t algo) {
    switch (algo) {
        case KEM_MLKEM1024:
            return PQCLEAN_MLKEM1024_CLEAN_crypto_kem_keypair(pk, sk) == 0 ? SUCCESS : FAILURE;
        default:
            return FAILURE_BAD_PROTOCOL;
    }
}

status_t kem_encode(uint8_t *ct, uint8_t *ss, const uint8_t *pk, algo_type_t algo) {
    switch (algo) {
        case KEM_MLKEM1024:
            return PQCLEAN_MLKEM1024_CLEAN_crypto_kem_enc(ct, ss, pk) == 0 ? SUCCESS : FAILURE;
        default:
            return FAILURE_BAD_PROTOCOL;
    }
}

status_t kem_decode(uint8_t *ss, const uint8_t *ct, const uint8_t *sk, algo_type_t algo) {
    switch (algo) {
        case KEM_MLKEM1024:
            return PQCLEAN_MLKEM1024_CLEAN_crypto_kem_dec(ss, ct, sk) == 0 ? SUCCESS : FAILURE;
        default:
            return FAILURE_BAD_PROTOCOL;
    }
}

// =====================================================================
// SIGN
// =====================================================================
status_t sgn_generate_keypair(uint8_t *pk, uint8_t *sk, algo_type_t algo) {
    switch (algo) {
        case SIGN_FALCONPADDED512:
            return PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_keypair(pk, sk) == 0 ? SUCCESS : FAILURE;
        case SIGN_MLDSA87:
            return PQCLEAN_MLDSA87_CLEAN_crypto_sign_keypair(pk, sk) == 0 ? SUCCESS : FAILURE;
        default:
            return FAILURE_BAD_PROTOCOL;
    }
}

status_t sgn_sign(uint8_t *sig, size_t *siglen, const uint8_t *msg, size_t msglen, const uint8_t *sk, algo_type_t algo) {
    switch (algo) {
        case SIGN_FALCONPADDED512:
            return PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_signature(sig, siglen, msg, msglen, sk) == 0 ? SUCCESS : FAILURE;
        case SIGN_MLDSA87:
            return PQCLEAN_MLDSA87_CLEAN_crypto_sign_signature(sig, siglen, msg, msglen, sk) == 0 ? SUCCESS : FAILURE;
        default:
            return FAILURE_BAD_PROTOCOL;
    }
}

status_t sgn_verify(const uint8_t *sig, size_t siglen, const uint8_t *msg, size_t msglen, const uint8_t *pk, algo_type_t algo) {
    switch (algo) {
        case SIGN_FALCONPADDED512:
            return PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_verify(sig, siglen, msg, msglen, pk) == 0 ? SUCCESS : FAILURE;
        case SIGN_MLDSA87:
            return PQCLEAN_MLDSA87_CLEAN_crypto_sign_verify(sig, siglen, msg, msglen, pk) == 0 ? SUCCESS : FAILURE;
        default:
            return FAILURE_BAD_PROTOCOL;
    }
}
