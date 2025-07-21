#ifndef ORILINK_PROTOCOL_H
#define ORILINK_PROTOCOL_H

#include <stdlib.h>
#include <blake3.h>
#include "types.h"
#include "constants.h"
//======================================================================
// Desain protocol dengan kemampuan mengukur rtt di kedua sisi
//======================================================================
typedef enum {
    ORILINK_SYN = (uint8_t)0x00,
    ORILINK_SYN_ACK = (uint8_t)0x01,
    ORILINK_SYN_END = (uint8_t)0x02,
    ORILINK_HEARTBEAT_PING = (uint8_t)0x03,
    ORILINK_HEARTBEAT_PONG = (uint8_t)0x04,
    ORILINK_HEARTBEAT_PONG_ACK = (uint8_t)0x05,
    ORILINK_HEARTBEAT_PING_END = (uint8_t)0x06,
    ORILINK_SYNDT = (uint8_t)0x07,
    ORILINK_SYNDT_ACK = (uint8_t)0x08,
    ORILINK_SYNDT_END = (uint8_t)0x09,
    ORILINK_DATA = (uint8_t)0x0a,
    ORILINK_DATA_ACK = (uint8_t)0x0b,
    ORILINK_DATA_END = (uint8_t)0x0c,
    ORILINK_FINDT = (uint8_t)0x0d,
    ORILINK_FINDT_ACK = (uint8_t)0x0e,
    ORILINK_FINDT_END = (uint8_t)0x0f,
    ORILINK_FIN = (uint8_t)0x10,
    ORILINK_FIN_ACK = (uint8_t)0x11,
    ORILINK_FIN_END = (uint8_t)0x12
} orilink_protocol_type_t;

typedef enum {
    ORILINK_RELIABLE = (uint8_t)0x00,
    ORILINK_STREAMING = (uint8_t)0x01
} orilink_mode_t;

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
	uint8_t version[ORILINK_VERSION_BYTES];
	orilink_protocol_type_t type;
    uint32_t chksum;
	union {
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
        if (x->type == ORILINK_SYN) {
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

static inline uint32_t orilink_hash32(const void* data, size_t len) {
    uint8_t out[32]; // full BLAKE3 hash
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, data, len);
    blake3_hasher_finalize(&hasher, out, 32);

    // Ambil 4 byte pertama, perlakukan sebagai big-endian, dan konversi ke host byte order
    uint32_t hash_val_be;
    memcpy(&hash_val_be, out, sizeof(uint32_t)); // Salin 4 byte pertama dari output hash BLAKE3
    return be32toh(hash_val_be);                 // Konversi dari big-endian (network byte order) ke host byte order
}

typedef struct {
	orilink_protocol_t *r_orilink_protocol_t;
    status_t status;
} orilink_protocol_t_status_t;

ssize_t_status_t send_orilink_protocol_packet(const char *label, int *sock_fd, const struct sockaddr *dest_addr, socklen_t *dest_addr_len, const orilink_protocol_t* p);
orilink_protocol_t_status_t receive_and_deserialize_orilink_packet(const char *label, int *sock_fd, struct sockaddr *source_addr, socklen_t *source_addr_len);

#endif
