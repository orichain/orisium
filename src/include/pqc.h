#ifndef PQC_H
#define PQC_H

#include <stdint.h>
#include <stddef.h>
#include "types.h"

//======================================================================
// ALGORITHM ENUM
//======================================================================
typedef enum {
    // KEM
    KEM_MLKEM1024 = 0x01,
    
    // SIGN
    SIGN_FALCONPADDED512 = 0x11,
    SIGN_MLDSA87 = 0x12,
} algo_type_t;

//======================================================================
// INFO STRUCT
//======================================================================
typedef struct {
    algo_type_t type;
    const char *name;
    size_t public_key_len;
    size_t private_key_len;
    size_t ciphertext_len;   // For KEM
    size_t shared_key_len;   // For KEM
    size_t signature_len;    // For SIGN
} pqc_algo_info_t;

//======================================================================
// FUNCTION WRAPPERS
//======================================================================
// KEM
status_t kem_generate_keypair(uint8_t *pk, uint8_t *sk, algo_type_t algo);
status_t kem_encode(uint8_t *ct, uint8_t *ss, const uint8_t *pk, algo_type_t algo);
status_t kem_decode(uint8_t *ss, const uint8_t *ct, const uint8_t *sk, algo_type_t algo);

// SIGN
status_t sgn_generate_keypair(uint8_t *pk, uint8_t *sk, algo_type_t algo);
status_t sgn_sign(uint8_t *sig, size_t *siglen, const uint8_t *msg, size_t msglen, const uint8_t *sk, algo_type_t algo);
status_t sgn_verify(const uint8_t *sig, size_t siglen, const uint8_t *msg, size_t msglen, const uint8_t *pk, algo_type_t algo);

// Info
const pqc_algo_info_t *get_pqc_info(algo_type_t algo);

#endif
