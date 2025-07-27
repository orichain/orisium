#ifndef ORILINK_PROTOCOL_H
#define ORILINK_PROTOCOL_H

#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "types.h"
#include "constants.h"
#include "pqc.h"
//======================================================================
// Desain protocol dengan kemampuan mengukur rtt di kedua sisi
//======================================================================
typedef enum {
//======================================================================
// Untuk pembentukan sock_fd baru
//======================================================================
    ORILINK_HELLO1 = (uint8_t)0x00,
    ORILINK_HELLO1_ACK = (uint8_t)0x01,
    ORILINK_HELLO2 = (uint8_t)0x02,
    ORILINK_HELLO2_ACK = (uint8_t)0x03,
    ORILINK_HELLO3 = (uint8_t)0x04,
    ORILINK_HELLO3_ACK = (uint8_t)0x05,
    ORILINK_HELLO_END = (uint8_t)0x06,
    ORILINK_SOCK_READY = (uint8_t)0x07,
//======================================================================    
    ORILINK_SYN = (uint8_t)0x08,
    ORILINK_SYN_ACK = (uint8_t)0x09,
    ORILINK_SYN_END = (uint8_t)0x0a,
    ORILINK_HEARTBEAT_PING = (uint8_t)0x0b,
    ORILINK_HEARTBEAT_PONG = (uint8_t)0x0c,
    ORILINK_HEARTBEAT_PONG_ACK = (uint8_t)0x0d,
    ORILINK_HEARTBEAT_PING_END = (uint8_t)0x0e,
    ORILINK_SYNDT = (uint8_t)0x0f,
    ORILINK_SYNDT_ACK = (uint8_t)0x10,
    ORILINK_SYNDT_END = (uint8_t)0x11,
    ORILINK_DATA = (uint8_t)0x12,
    ORILINK_DATA_ACK = (uint8_t)0x13,
    ORILINK_DATA_END = (uint8_t)0x14,
    ORILINK_FINDT = (uint8_t)0x15,
    ORILINK_FINDT_ACK = (uint8_t)0x16,
    ORILINK_FINDT_END = (uint8_t)0x17,
    ORILINK_FIN = (uint8_t)0x18,
    ORILINK_FIN_ACK = (uint8_t)0x19,
    ORILINK_FIN_END = (uint8_t)0x1a
} orilink_protocol_type_t;

typedef enum {
    ORILINK_RELIABLE = (uint8_t)0x00,
    ORILINK_STREAMING = (uint8_t)0x01
} orilink_mode_t;

typedef struct {
    uint64_t client_id;
    uint8_t kem_privatekey[KEM_PRIVATEKEY_BYTES];
    uint8_t kem_publickey[KEM_PUBLICKEY_BYTES];
    uint8_t kem_ciphertext[KEM_CIPHERTEXT_BYTES];
    uint8_t kem_sharedsecret[KEM_SHAREDSECRET_BYTES];
    uint64_t server_id;
    uint16_t port;
} orilink_identity_t;

typedef struct {
    uint64_t client_id;
    uint8_t publickey1[KEM_PUBLICKEY_BYTES / 2];
    uint8_t trycount;
} orilink_hello1_t;

typedef struct {
    uint64_t client_id;
    uint8_t trycount;
} orilink_hello1_ack_t;

typedef struct {
    uint64_t client_id;
    uint8_t publickey2[KEM_PUBLICKEY_BYTES / 2];
    uint8_t trycount;
} orilink_hello2_t;

typedef struct {
    uint64_t client_id;
    uint8_t ciphertext1[KEM_CIPHERTEXT_BYTES / 2];
    uint8_t trycount;
} orilink_hello2_ack_t;

typedef struct {
    uint64_t client_id;
    uint8_t trycount;
} orilink_hello3_t;

typedef struct {
    uint64_t client_id;
    uint8_t ciphertext2[KEM_CIPHERTEXT_BYTES / 2];
    uint8_t encrypted_server_id_port[AES_NONCE_BYTES + sizeof(uint64_t) + sizeof(uint16_t) + AES_TAG_BYTES];
    uint8_t trycount;
} orilink_hello3_ack_t;

typedef struct {
    uint64_t client_id;
    uint8_t nonce[AES_NONCE_BYTES];
    uint64_t server_id;
    uint16_t port;
    uint8_t trycount;
} orilink_hello_end_t;

typedef struct {
    uint64_t client_id;
    uint64_t server_id;
    uint16_t port;
    uint8_t trycount;
} orilink_sock_ready_t;

typedef struct {
    uint64_t id;
    uint8_t trycount;
} orilink_syn_t;

typedef struct {
    uint64_t id;
    uint8_t trycount;
} orilink_syn_ack_t;

typedef struct {
    uint64_t id;
    uint8_t trycount;
} orilink_syn_end_t;

typedef struct {
    uint64_t id;
//======================================================================
// id ping
//======================================================================        
    uint64_t pid;
    uint8_t trycount;
} orilink_heartbeat_ping_t;

typedef struct {
    uint64_t id;
//======================================================================
// id ping
//======================================================================      
    uint64_t pid;
    uint8_t trycount;
} orilink_heartbeat_pong_t;

typedef struct {
    uint64_t id;
//======================================================================
// id ping
//======================================================================      
    uint64_t pid;
    uint8_t trycount;
} orilink_heartbeat_pong_ack_t;

typedef struct {
    uint64_t id;
//======================================================================
// id ping
//======================================================================      
    uint64_t pid;
    uint8_t trycount;
} orilink_heartbeat_ping_end_t;

typedef struct {
    uint64_t id;
//======================================================================
// id stream
//======================================================================      
    uint64_t sid;
    uint8_t trycount;
    orilink_mode_t mode;
//======================================================================
// data size dalam byte
//======================================================================      
    uint16_t dtsize;
//======================================================================
// max buffer per 1 paket
//======================================================================      
    uint16_t mbpp;
} orilink_syndt_t;

typedef struct {
    uint64_t id;
    uint64_t sid;
    uint8_t trycount;
} orilink_syndt_ack_t;

typedef struct {
    uint64_t id;
    uint64_t sid;
    uint8_t trycount;
} orilink_syndt_end_t;

typedef struct {
    uint64_t id;
    uint64_t sid;
//======================================================================
// nomor paket  
//======================================================================      
    uint16_t spktnum;
//======================================================================
// retry count per nomor paket
//======================================================================          
    uint8_t trycount;
//======================================================================
// jumlah data per spktnum dalam byte
//======================================================================
    uint16_t len;
//======================================================================
// FAM data
//======================================================================
    uint8_t data[];
} orilink_data_t;

typedef struct {
    uint64_t id;
    uint64_t sid;
    uint16_t spktnum;
    uint8_t trycount;
} orilink_data_ack_t;

typedef struct {
    uint64_t id;
    uint64_t sid;
    uint16_t spktnum;
    uint8_t trycount;
} orilink_data_end_t;

typedef struct {
    uint64_t id;
    uint64_t sid;
    uint8_t trycount;
} orilink_findt_t;

typedef struct {
    uint64_t id;
    uint64_t sid;
    uint8_t trycount;
} orilink_findt_ack_t;

typedef struct {
    uint64_t id;
    uint64_t sid;
    uint8_t trycount;
} orilink_findt_end_t;

typedef struct {
    uint64_t id;
    uint8_t trycount;
} orilink_fin_t;

typedef struct {
    uint64_t id;
    uint8_t trycount;
} orilink_fin_ack_t;

typedef struct {
    uint64_t id;
    uint8_t trycount;
} orilink_fin_end_t;

typedef struct {
    uint8_t mac[AES_TAG_BYTES];
	uint8_t version[ORILINK_VERSION_BYTES];
	orilink_protocol_type_t type;
	union {
//======================================================================
// Untuk pembentukan sock_fd baru
//======================================================================        
        orilink_hello1_t *orilink_hello1;
        orilink_hello1_ack_t *orilink_hello1_ack;
        orilink_hello2_t *orilink_hello2;
        orilink_hello2_ack_t *orilink_hello2_ack;
        orilink_hello3_t *orilink_hello3;
        orilink_hello3_ack_t *orilink_hello3_ack;
        orilink_hello_end_t *orilink_hello_end;
        orilink_sock_ready_t *orilink_sock_ready;
//======================================================================        
		orilink_syn_t *orilink_syn;
		orilink_syn_ack_t *orilink_syn_ack;
        orilink_syn_end_t *orilink_syn_end;
        orilink_heartbeat_ping_t *orilink_heartbeat_ping;
        orilink_heartbeat_pong_t *orilink_heartbeat_pong;
        orilink_heartbeat_pong_ack_t *orilink_heartbeat_pong_ack;
        orilink_heartbeat_ping_end_t *orilink_heartbeat_ping_end;
        orilink_syndt_t *orilink_syndt;
        orilink_syndt_ack_t *orilink_syndt_ack;
        orilink_syndt_end_t *orilink_syndt_end;
        orilink_data_t *orilink_data;
        orilink_data_ack_t *orilink_data_ack;
        orilink_data_end_t *orilink_data_end;
        orilink_findt_t *orilink_findt;
        orilink_findt_ack_t *orilink_findt_ack;
        orilink_findt_end_t *orilink_findt_end;
        orilink_fin_t *orilink_fin;
        orilink_fin_ack_t *orilink_fin_ack;
        orilink_fin_end_t *orilink_fin_end;
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
//======================================================================
// Untuk pembentukan sock_fd baru
//======================================================================        
        if (x->type == ORILINK_HELLO1) {
            CLOSE_ORILINK_PAYLOAD((void **)&x->payload.orilink_hello1);
        } else if (x->type == ORILINK_HELLO1_ACK) {
            CLOSE_ORILINK_PAYLOAD((void **)&x->payload.orilink_hello1_ack);
        } else if (x->type == ORILINK_HELLO2) {
            CLOSE_ORILINK_PAYLOAD((void **)&x->payload.orilink_hello2);
        } else if (x->type == ORILINK_HELLO2_ACK) {
            CLOSE_ORILINK_PAYLOAD((void **)&x->payload.orilink_hello2_ack);
        } else if (x->type == ORILINK_HELLO3) {
            CLOSE_ORILINK_PAYLOAD((void **)&x->payload.orilink_hello3);
        } else if (x->type == ORILINK_HELLO3_ACK) {
            CLOSE_ORILINK_PAYLOAD((void **)&x->payload.orilink_hello3_ack);
        } else if (x->type == ORILINK_HELLO_END) {
            CLOSE_ORILINK_PAYLOAD((void **)&x->payload.orilink_hello_end);
        }  else if (x->type == ORILINK_SOCK_READY) {
            CLOSE_ORILINK_PAYLOAD((void **)&x->payload.orilink_sock_ready);
//======================================================================
        } else if (x->type == ORILINK_SYN) {
            CLOSE_ORILINK_PAYLOAD((void **)&x->payload.orilink_syn);
        } else if (x->type == ORILINK_SYN_ACK) {
            CLOSE_ORILINK_PAYLOAD((void **)&x->payload.orilink_syn_ack);
        } else if (x->type == ORILINK_SYN_END) {
            CLOSE_ORILINK_PAYLOAD((void **)&x->payload.orilink_syn_end);
        } else if (x->type == ORILINK_HEARTBEAT_PING) {
            CLOSE_ORILINK_PAYLOAD((void **)&x->payload.orilink_heartbeat_ping);
        } else if (x->type == ORILINK_HEARTBEAT_PONG) {
            CLOSE_ORILINK_PAYLOAD((void **)&x->payload.orilink_heartbeat_pong);
        } else if (x->type == ORILINK_HEARTBEAT_PONG_ACK) {
            CLOSE_ORILINK_PAYLOAD((void **)&x->payload.orilink_heartbeat_pong_ack);
        } else if (x->type == ORILINK_HEARTBEAT_PING_END) {
            CLOSE_ORILINK_PAYLOAD((void **)&x->payload.orilink_heartbeat_ping_end);
        } else if (x->type == ORILINK_SYNDT) {
            CLOSE_ORILINK_PAYLOAD((void **)&x->payload.orilink_syndt);
        } else if (x->type == ORILINK_SYNDT_ACK) {
            CLOSE_ORILINK_PAYLOAD((void **)&x->payload.orilink_syndt_ack);
        } else if (x->type == ORILINK_SYNDT_END) {
            CLOSE_ORILINK_PAYLOAD((void **)&x->payload.orilink_syndt_end);
        } else if (x->type == ORILINK_DATA) {
            CLOSE_ORILINK_PAYLOAD((void **)&x->payload.orilink_data);
        } else if (x->type == ORILINK_DATA_ACK) {
            CLOSE_ORILINK_PAYLOAD((void **)&x->payload.orilink_data_ack);
        } else if (x->type == ORILINK_DATA_END) {
            CLOSE_ORILINK_PAYLOAD((void **)&x->payload.orilink_data_end);
        } else if (x->type == ORILINK_FINDT) {
            CLOSE_ORILINK_PAYLOAD((void **)&x->payload.orilink_findt);
        } else if (x->type == ORILINK_FINDT_ACK) {
            CLOSE_ORILINK_PAYLOAD((void **)&x->payload.orilink_findt_ack);
        } else if (x->type == ORILINK_FINDT_END) {
            CLOSE_ORILINK_PAYLOAD((void **)&x->payload.orilink_findt_end);
        } else if (x->type == ORILINK_FIN) {
            CLOSE_ORILINK_PAYLOAD((void **)&x->payload.orilink_fin);
        } else if (x->type == ORILINK_FIN_ACK) {
            CLOSE_ORILINK_PAYLOAD((void **)&x->payload.orilink_fin_ack);
        } else if (x->type == ORILINK_FIN_END) {
            CLOSE_ORILINK_PAYLOAD((void **)&x->payload.orilink_fin_end);
        }
        free(x);
        *protocol_ptr = NULL;
    }
}

typedef struct {
    uint8_t *recv_buffer;
    uint16_t n;
    uint8_t version[ORILINK_VERSION_BYTES];
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

ssize_t_status_t send_orilink_protocol_packet(const char *label, uint8_t* key, uint8_t* nonce, uint32_t ctr, int *sock_fd, const struct sockaddr *dest_addr, const orilink_protocol_t* p);
orilink_raw_protocol_t_status_t receive_orilink_raw_protocol_packet(const char *label, int *sock_fd, struct sockaddr *source_addr);
orilink_protocol_t_status_t orilink_deserialize(const char *label, uint8_t* key, uint8_t* nonce, uint32_t ctr, const uint8_t* buffer, size_t len);

#endif
