#ifndef ORILINK_PROTOCOL_H
#define ORILINK_PROTOCOL_H

#include <stdlib.h>
#include <blake3.h>
#include "types.h"
#include "constants.h"

typedef enum {
    ORILINK_SYN = (uint8_t)0x00,
    ORILINK_SYN_ACK = (uint8_t)0x01,
    ORILINK_HEARTBEAT = (uint8_t)0x02,
    ORILINK_HEARTBEAT_ACK = (uint8_t)0x03,
    ORILINK_STARTDT = (uint8_t)0x04,
    ORILINK_STARTDT_ACK = (uint8_t)0x05,    
    ORILINK_STATUSDT = (uint8_t)0x06,
    ORILINK_STATUSDT_NACK = (uint8_t)0x07,
    ORILINK_DATA = (uint8_t)0x08,
    ORILINK_DATA_SACK = (uint8_t)0x09,
    ORILINK_FINISHDT = (uint8_t)0x01,
    ORILINK_FINISHDT_ACK = (uint8_t)0x0b,
    ORILINK_FIN = (uint8_t)0x0c,
    ORILINK_FIN_ACK = (uint8_t)0x0d
} orilink_protocol_type_t;

typedef enum {
    ORILINK_RELIABLE = (uint8_t)0x00,
    ORILINK_STREAMING = (uint8_t)0x01
} orilink_mode_t;

typedef struct {
    uint64_t id;
} orilink_syn_t;

typedef struct {
    uint64_t id;
} orilink_syn_ack_t;

typedef struct {
    uint64_t id;
    uint32_t pktnum;
    uint16_t len;
    uint32_t data[];
} orilink_nack_t;

typedef struct {
    uint64_t id;
} orilink_ack_t;

typedef struct {
    uint64_t id;
    uint32_t seq;
    uint16_t sid;
    uint32_t sseq;
    uint16_t len;
    uint8_t data[];
} orilink_data_t;

typedef struct {
    uint64_t id;
} orilink_fin_t;

typedef struct {
    uint64_t id;
} orilink_heartbeat_t;

typedef struct {
    uint64_t id;
    uint32_t arw;
    uint32_t lackseq;
    uint16_t len;
    uint8_t data[];
} orilink_sack_t;

typedef struct {
	uint8_t version[ORILINK_VERSION_BYTES];
	orilink_protocol_type_t type;
    uint32_t chksum;
	union {
		orilink_syn_t *orilink_syn;
		orilink_syn_ack_t *orilink_syn_ack;
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
