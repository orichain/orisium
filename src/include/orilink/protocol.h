#ifndef ORILINK_PROTOCOL_H
#define ORILINK_PROTOCOL_H

#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "constants.h"
#include "pqc.h"
#include "types.h"
#include "oritlsf.h"

typedef enum {
    ORILINK_HELLO1 = (uint8_t)0x00,
    ORILINK_HELLO1_ACK = (uint8_t)0x01,
    ORILINK_HELLO2 = (uint8_t)0x02,
    ORILINK_HELLO2_ACK = (uint8_t)0x03,
    ORILINK_HELLO3 = (uint8_t)0x04,
    ORILINK_HELLO3_ACK = (uint8_t)0x05,
    ORILINK_HELLO4 = (uint8_t)0x06,
    ORILINK_HELLO4_ACK = (uint8_t)0x07,
    
    ORILINK_INFO = (uint8_t)0xfc,
    ORILINK_INFO_ACK = (uint8_t)0xfd,
    ORILINK_HEARTBEAT = (uint8_t)0xfe,
    ORILINK_HEARTBEAT_ACK = (uint8_t)0xff
} orilink_protocol_type_t;

typedef struct {
    uint64_t id_connection;
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
    uint8_t *local_data_nonce[PARALLEL_DATA_WINDOW_SIZE];
    uint32_t local_data_ctr[PARALLEL_DATA_WINDOW_SIZE];
    uint8_t *remote_data_nonce[PARALLEL_DATA_WINDOW_SIZE];
    uint32_t remote_data_ctr[PARALLEL_DATA_WINDOW_SIZE];
} orilink_security_t;

typedef struct {
    uint64_t local_id;
    uint64_t remote_id;
    info_type_t flag;
} orilink_info_t;

typedef struct {
    uint64_t local_id;
    uint64_t remote_id;
} orilink_info_ack_t;

typedef struct {
    uint64_t local_id;
    uint64_t remote_id;
    double hb_interval;
} orilink_heartbeat_t;

typedef struct {
    uint64_t local_id;
    uint64_t remote_id;
} orilink_heartbeat_ack_t;

typedef struct {
    uint64_t local_id;
    uint8_t publickey1[KEM_PUBLICKEY_BYTES / 2];
} orilink_hello1_t;

typedef struct {
    uint64_t remote_id;
} orilink_hello1_ack_t;

typedef struct {
    uint64_t local_id;
    uint8_t publickey2[KEM_PUBLICKEY_BYTES / 2];
} orilink_hello2_t;

typedef struct {
    uint64_t remote_id;
    uint8_t ciphertext1[KEM_CIPHERTEXT_BYTES / 2];
} orilink_hello2_ack_t;

typedef struct {
    uint64_t local_id;
} orilink_hello3_t;

typedef struct {
    uint64_t remote_id;
    uint8_t nonce[AES_NONCE_BYTES];
    uint8_t ciphertext2[KEM_CIPHERTEXT_BYTES / 2];
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
} orilink_hello4_ack_t;

typedef struct {
    uint8_t mac[AES_TAG_BYTES];
    uint32_t ctr;
	uint8_t version[ORILINK_VERSION_BYTES];
    uint8_t inc_ctr;
    uint8_t local_index;
    uint8_t local_session_index;
    worker_type_t local_wot;
    
    uint64_t id_connection;
    
    worker_type_t remote_wot;
    uint8_t remote_index;
    uint8_t remote_session_index;
    orilink_protocol_type_t type;
    uint8_t trycount;
    
	union {
        orilink_hello1_t *orilink_hello1;
        orilink_hello1_ack_t *orilink_hello1_ack;
        orilink_hello2_t *orilink_hello2;
        orilink_hello2_ack_t *orilink_hello2_ack;
        orilink_hello3_t *orilink_hello3;
        orilink_hello3_ack_t *orilink_hello3_ack;
        orilink_hello4_t *orilink_hello4;
        orilink_hello4_ack_t *orilink_hello4_ack;
        orilink_heartbeat_t *orilink_heartbeat;
        orilink_heartbeat_ack_t *orilink_heartbeat_ack;
        orilink_info_t *orilink_info;
        orilink_info_ack_t *orilink_info_ack;
	} payload;
} orilink_protocol_t;
//Huruf_besar biar selalu ingat karena akan sering digunakan
static inline void CLOSE_ORILINK_PROTOCOL(oritlsf_pool_t *pool, orilink_protocol_t **protocol_ptr) {
    if (protocol_ptr != NULL && *protocol_ptr != NULL) {
        orilink_protocol_t *x = *protocol_ptr;
        if (x) {
			if (x->type == ORILINK_HELLO1) {
				memset(x->payload.orilink_hello1->publickey1, 0, KEM_PUBLICKEY_BYTES / 2);
				oritlsf_free(pool, (void **)&x->payload.orilink_hello1);
			} else if (x->type == ORILINK_HELLO1_ACK) {
				oritlsf_free(pool, (void **)&x->payload.orilink_hello1_ack);
			} else if (x->type == ORILINK_HELLO2) {
				memset(x->payload.orilink_hello2->publickey2, 0, KEM_PUBLICKEY_BYTES / 2);
				oritlsf_free(pool, (void **)&x->payload.orilink_hello2);
			} else if (x->type == ORILINK_HELLO2_ACK) {
				memset(x->payload.orilink_hello2_ack->ciphertext1, 0, KEM_CIPHERTEXT_BYTES / 2);
				oritlsf_free(pool, (void **)&x->payload.orilink_hello2_ack);
			} else if (x->type == ORILINK_HELLO3) {
				oritlsf_free(pool, (void **)&x->payload.orilink_hello3);
			} else if (x->type == ORILINK_HELLO3_ACK) {
				memset(x->payload.orilink_hello3_ack->nonce, 0, AES_NONCE_BYTES);
				memset(x->payload.orilink_hello3_ack->ciphertext2, 0, KEM_CIPHERTEXT_BYTES / 2);
				oritlsf_free(pool, (void **)&x->payload.orilink_hello3_ack);
			} else if (x->type == ORILINK_HELLO4) {
				memset(x->payload.orilink_hello4->encrypted_local_identity, 0, 
					AES_NONCE_BYTES +
					sizeof(uint8_t) +
					sizeof(uint8_t) +
					sizeof(uint8_t) +
					sizeof(uint64_t) +
					AES_TAG_BYTES
				);
				oritlsf_free(pool, (void **)&x->payload.orilink_hello4);
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
				oritlsf_free(pool, (void **)&x->payload.orilink_hello4_ack);
			} else if (x->type == ORILINK_HEARTBEAT) {
				oritlsf_free(pool, (void **)&x->payload.orilink_heartbeat);
			} else if (x->type == ORILINK_HEARTBEAT_ACK) {
				oritlsf_free(pool, (void **)&x->payload.orilink_heartbeat_ack);
			} else if (x->type == ORILINK_INFO) {
				oritlsf_free(pool, (void **)&x->payload.orilink_info);
			} else if (x->type == ORILINK_INFO_ACK) {
				oritlsf_free(pool, (void **)&x->payload.orilink_info_ack);
			}
		}
        oritlsf_free(pool, (void **)protocol_ptr);
    }
}

typedef struct orilink_raw_protocol_t {
    uint8_t *recv_buffer;
    uint16_t n;
    uint8_t mac[AES_TAG_BYTES];
    uint32_t ctr;
    uint8_t version[ORILINK_VERSION_BYTES];
    uint8_t inc_ctr;
    uint8_t local_index;
    uint8_t local_session_index;
    worker_type_t local_wot;
    
    uint64_t id_connection;
    
    worker_type_t remote_wot;
    uint8_t remote_index;
    uint8_t remote_session_index;
    orilink_protocol_type_t type;
    uint8_t trycount;
} orilink_raw_protocol_t;

//Huruf_besar biar selalu ingat karena akan sering digunakan
static inline void CLOSE_ORILINK_RAW_PROTOCOL(oritlsf_pool_t *pool, orilink_raw_protocol_t **protocol_ptr) {
    if (protocol_ptr != NULL && *protocol_ptr != NULL) {
		if (*protocol_ptr) oritlsf_free(pool, (void **)&((*protocol_ptr)->recv_buffer));
		oritlsf_free(pool, (void **)protocol_ptr);
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

#endif
