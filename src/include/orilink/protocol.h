#ifndef ORILINK_PROTOCOL_H
#define ORILINK_PROTOCOL_H

#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "types.h"
#include "constants.h"
#include "pqc.h"
#include "kalman.h"
#include "ipc/protocol.h"

typedef enum {
    ORILINK_HELLO1 = (uint8_t)0x00,
    ORILINK_HELLO1_ACK = (uint8_t)0x01,
    ORILINK_HELLO2 = (uint8_t)0x02,
    ORILINK_HELLO2_ACK = (uint8_t)0x03,
    ORILINK_HELLO3 = (uint8_t)0x04,
    ORILINK_HELLO3_ACK = (uint8_t)0x05,
    ORILINK_HELLO4 = (uint8_t)0x06,
    ORILINK_HELLO4_ACK = (uint8_t)0x07
} orilink_protocol_type_t;

typedef struct {
    struct sockaddr_in6 remote_addr;
    worker_type_t remote_wot;
    uint8_t remote_index;
    uint8_t remote_session_index;
    uint64_t remote_id;
    worker_type_t local_wot;
    uint8_t local_index;
    uint8_t local_session_index;
    uint64_t local_id;
} orilink_identity_t;

typedef struct {
    uint8_t *kem_publickey;
    uint8_t *kem_ciphertext;
    uint8_t *kem_sharedsecret;
    uint8_t *aes_key;
    uint8_t *mac_key;
    uint8_t *local_nonce;
    uint32_t local_ctr;
    uint8_t *remote_nonce;
    uint32_t remote_ctr;
} orilink_security_t;

typedef struct {
    uint64_t local_id;
    uint8_t publickey1[KEM_PUBLICKEY_BYTES / 2];
    uint8_t trycount;
} orilink_hello1_t;

typedef struct {
    uint64_t remote_id;
    uint8_t trycount;
} orilink_hello1_ack_t;

typedef struct {
    uint64_t local_id;
    uint8_t publickey2[KEM_PUBLICKEY_BYTES / 2];
    uint8_t trycount;
} orilink_hello2_t;

typedef struct {
    uint64_t remote_id;
    uint8_t ciphertext1[KEM_CIPHERTEXT_BYTES / 2];
    uint8_t trycount;
} orilink_hello2_ack_t;

typedef struct {
    uint64_t local_id;
    uint8_t trycount;
} orilink_hello3_t;

typedef struct {
    uint64_t remote_id;
    uint8_t nonce[AES_NONCE_BYTES];
    uint8_t ciphertext2[KEM_CIPHERTEXT_BYTES / 2];
    uint8_t trycount;
} orilink_hello3_ack_t;

typedef struct {
    uint8_t encrypted_local_identity[
        AES_NONCE_BYTES +
        sizeof(uint8_t) +
        sizeof(uint8_t) +
        sizeof(uint8_t) +
        sizeof(uint64_t) +
        AES_TAG_BYTES
    ];
    uint8_t trycount;
} orilink_hello4_t;

typedef struct {
    uint8_t encrypted_remote_identity[
        sizeof(uint8_t) +
        sizeof(uint8_t) +
        sizeof(uint8_t) +
        sizeof(uint64_t) +
        AES_TAG_BYTES
    ];
    uint8_t encrypted_local_identity[
        sizeof(uint8_t) +
        sizeof(uint8_t) +
        sizeof(uint8_t) +
        sizeof(uint64_t) +
        AES_TAG_BYTES
    ];
    uint8_t trycount;
} orilink_hello4_ack_t;

typedef struct {
    uint8_t mac[AES_TAG_BYTES];
    uint32_t ctr;
	uint8_t version[ORILINK_VERSION_BYTES];
    uint8_t inc_ctr;
    worker_type_t remote_wot;
    uint8_t remote_index;
    uint8_t remote_session_index;
    worker_type_t local_wot;
    uint8_t local_index;
    uint8_t local_session_index;
	orilink_protocol_type_t type;
	union {
        orilink_hello1_t *orilink_hello1;
        orilink_hello1_ack_t *orilink_hello1_ack;
        orilink_hello2_t *orilink_hello2;
        orilink_hello2_ack_t *orilink_hello2_ack;
        orilink_hello3_t *orilink_hello3;
        orilink_hello3_ack_t *orilink_hello3_ack;
        orilink_hello4_t *orilink_hello4;
        orilink_hello4_ack_t *orilink_hello4_ack;
	} payload;
} orilink_protocol_t;
//Huruf_besar biar selalu ingat karena akan sering digunakan
static inline void CLOSE_ORILINK_PAYLOAD(void **ptr) {
    if (ptr != NULL && *ptr != NULL) {
        free(*ptr);
        *ptr = NULL;
    }
}
//Huruf_besar biar selalu ingat karena akan sering digunakan
static inline void CLOSE_ORILINK_PROTOCOL(orilink_protocol_t **protocol_ptr) {
    if (protocol_ptr != NULL && *protocol_ptr != NULL) {
        orilink_protocol_t *x = *protocol_ptr;
        if (x->type == ORILINK_HELLO1) {
            memset(x->payload.orilink_hello1->publickey1, 0, KEM_PUBLICKEY_BYTES / 2);
            CLOSE_ORILINK_PAYLOAD((void **)&x->payload.orilink_hello1);
        } else if (x->type == ORILINK_HELLO1_ACK) {
            CLOSE_ORILINK_PAYLOAD((void **)&x->payload.orilink_hello1_ack);
        } else if (x->type == ORILINK_HELLO2) {
            memset(x->payload.orilink_hello2->publickey2, 0, KEM_PUBLICKEY_BYTES / 2);
            CLOSE_ORILINK_PAYLOAD((void **)&x->payload.orilink_hello2);
        } else if (x->type == ORILINK_HELLO2_ACK) {
            memset(x->payload.orilink_hello2_ack->ciphertext1, 0, KEM_CIPHERTEXT_BYTES / 2);
            CLOSE_ORILINK_PAYLOAD((void **)&x->payload.orilink_hello2_ack);
        } else if (x->type == ORILINK_HELLO3) {
            CLOSE_ORILINK_PAYLOAD((void **)&x->payload.orilink_hello3);
        } else if (x->type == ORILINK_HELLO3_ACK) {
            memset(x->payload.orilink_hello3_ack->nonce, 0, AES_NONCE_BYTES);
            memset(x->payload.orilink_hello3_ack->ciphertext2, 0, KEM_CIPHERTEXT_BYTES / 2);
            CLOSE_ORILINK_PAYLOAD((void **)&x->payload.orilink_hello3_ack);
        } else if (x->type == ORILINK_HELLO4) {
            memset(x->payload.orilink_hello4->encrypted_local_identity, 0, 
                AES_NONCE_BYTES +
                sizeof(uint8_t) +
                sizeof(uint8_t) +
                sizeof(uint8_t) +
                sizeof(uint64_t) +
                AES_TAG_BYTES
            );
            CLOSE_ORILINK_PAYLOAD((void **)&x->payload.orilink_hello4);
        }  else if (x->type == ORILINK_HELLO4_ACK) {
            memset(x->payload.orilink_hello4_ack->encrypted_remote_identity, 0, 
                sizeof(uint8_t) +
                sizeof(uint8_t) +
                sizeof(uint8_t) +
                sizeof(uint64_t) +
                AES_TAG_BYTES
            );
            memset(x->payload.orilink_hello4_ack->encrypted_local_identity, 0, 
                sizeof(uint8_t) +
                sizeof(uint8_t) +
                sizeof(uint8_t) +
                sizeof(uint64_t) +
                AES_TAG_BYTES
            );
            CLOSE_ORILINK_PAYLOAD((void **)&x->payload.orilink_hello4_ack);
        }
        free(x);
        *protocol_ptr = NULL;
    }
}

typedef struct {
    uint8_t *recv_buffer;
    uint16_t n;
    uint8_t mac[AES_TAG_BYTES];
    uint32_t ctr;
    uint8_t version[ORILINK_VERSION_BYTES];
    uint8_t inc_ctr;
    worker_type_t remote_wot;
    uint8_t remote_index;
    uint8_t remote_session_index;
    worker_type_t local_wot;
    uint8_t local_index;
    uint8_t local_session_index;
	orilink_protocol_type_t type;
} orilink_raw_protocol_t;
//Huruf_besar biar selalu ingat karena akan sering digunakan
static inline void CLOSE_ORILINK_RAW_PAYLOAD(void **ptr) {
    if (ptr != NULL && *ptr != NULL) {
        free(*ptr);
        *ptr = NULL;
    }
}
//Huruf_besar biar selalu ingat karena akan sering digunakan
static inline void CLOSE_ORILINK_RAW_PROTOCOL(orilink_raw_protocol_t **protocol_ptr) {
    if (protocol_ptr != NULL && *protocol_ptr != NULL) {
        orilink_raw_protocol_t *x = *protocol_ptr;
        CLOSE_ORILINK_RAW_PAYLOAD((void **)&x->recv_buffer);
        free(x);
        *protocol_ptr = NULL;
    }
}

typedef struct {
	orilink_protocol_t *r_orilink_protocol_t;
    status_t status;
} orilink_protocol_t_status_t;

typedef struct {
	orilink_raw_protocol_t *r_orilink_raw_protocol_t;
    status_t status;
} orilink_raw_protocol_t_status_t;

puint8_t_size_t_status_t create_orilink_raw_protocol_packet(const char *label, uint8_t* key_aes, uint8_t* key_mac, uint8_t* nonce, uint32_t *ctr, const orilink_protocol_t* p);
ssize_t_status_t send_orilink_raw_protocol_packet(const char *label, puint8_t_size_t_status_t *r, int *sock_fd, const struct sockaddr_in6 *dest_addr);
orilink_raw_protocol_t_status_t receive_orilink_raw_protocol_packet(const char *label, int *sock_fd, struct sockaddr_in6 *source_addr);
void udp_data_to_orilink_raw_protocol_packet(ipc_udp_data_t *iudp_datai, orilink_raw_protocol_t *oudp_datao);
status_t orilink_check_mac_ctr(const char *label, uint8_t* key_aes, uint8_t* key_mac, uint32_t* ctr, orilink_raw_protocol_t *r);
orilink_protocol_t_status_t orilink_deserialize(const char *label, uint8_t *key_aes, uint8_t *nonce, uint32_t *ctr, uint8_t* buffer, size_t len);

#endif
