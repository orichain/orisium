#ifndef ORILINK_PROTOCOL_H
#define ORILINK_PROTOCOL_H

#include <stdlib.h>
#include "types.h"
#include "constants.h"

typedef enum {
    ORILINK_SYN = (uint8_t)0x00,
    ORILINK_SYN_ACK = (uint8_t)0x02,
    ORILINK_REUSED_SYN_ACK = (uint8_t)0x03,
    ORILINK_ACK = (uint8_t)0x04,
    ORILINK_SACK = (uint8_t)0x05,
    ORILINK_HEARTBEAT = (uint8_t)0x06,
    ORILINK_DATA = (uint8_t)0x07,
    ORILINK_FIN = (uint8_t)0x08
} orilink_protocol_type_t;

typedef enum {
    ORILINK_RELIABLE = (uint8_t)0x00,
    ORILINK_STREAMING = (uint8_t)0x01
} orilink_mode_t;

typedef struct {
    uint32_t chksum;
    uint64_t id;
    uint32_t pktnum;
    orilink_mode_t mode;
} orilink_syn_t;

typedef struct {
    uint32_t chksum;
    uint64_t id;
} orilink_syn_ack_t;

typedef struct {
    uint32_t chksum;
    uint64_t id;
    uint32_t pktnum;
    uint32_t lackseq;
    orilink_mode_t mode;
    uint16_t len;
    uint8_t data[];
} orilink_reused_syn_ack_t;

typedef struct {
    uint32_t chksum;
    uint64_t id;
} orilink_ack_t;

typedef struct {
    uint32_t chksum;
    uint64_t id;
    uint32_t seq;
    uint16_t sid;
    uint32_t sseq;
    uint16_t len;
    uint8_t data[];
} orilink_data_t;

typedef struct {
    uint32_t chksum;
    uint64_t id;
} orilink_fin_t;

typedef struct {
    uint32_t chksum;
    uint64_t id;
} orilink_heartbeat_t;

typedef struct {
    uint32_t chksum;
    uint64_t id;
    uint32_t arw;
    uint32_t lackseq;
    uint16_t len;
    uint8_t data[];
} orilink_sack_t;

typedef struct {
	uint8_t version[ORILINK_VERSION_BYTES];
	orilink_protocol_type_t type;
	union {
		orilink_syn_t *orilink_syn;
		orilink_syn_ack_t *orilink_syn_ack;
		orilink_reused_syn_ack_t *orilink_reused_syn_ack;
        orilink_ack_t *orilink_ack;
        orilink_sack_t *orilink_sack;
        orilink_heartbeat_t *orilink_heartbeat;
        orilink_data_t *orilink_data;
        orilink_fin_t *orilink_fin;
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
        } else if (x->type == ORILINK_REUSED_SYN_ACK) {
            CLOSE_ORILINK_PAYLOAD((void **)&x->payload.orilink_reused_syn_ack);
        } else if (x->type == ORILINK_ACK) {
            CLOSE_ORILINK_PAYLOAD((void **)&x->payload.orilink_ack);
        } else if (x->type == ORILINK_SACK) {
            CLOSE_ORILINK_PAYLOAD((void **)&x->payload.orilink_sack);
        } else if (x->type == ORILINK_HEARTBEAT) {
            CLOSE_ORILINK_PAYLOAD((void **)&x->payload.orilink_heartbeat);
        } else if (x->type == ORILINK_DATA) {
            CLOSE_ORILINK_PAYLOAD((void **)&x->payload.orilink_data);
        } else if (x->type == ORILINK_FIN) {
            CLOSE_ORILINK_PAYLOAD((void **)&x->payload.orilink_fin);
        }
        free(x);
        *protocol_ptr = NULL;
    }
}

typedef struct {
	orilink_protocol_t *r_orilink_protocol_t;
    status_t status;
} orilink_protocol_t_status_t;

#include "orilink/syn.h"

ssize_t_status_t send_orilink_protocol_packet(const char *label, int *sock_fd, const struct sockaddr *dest_addr, socklen_t *dest_addr_len, const orilink_protocol_t* p);
orilink_protocol_t_status_t receive_and_deserialize_orilink_packet(const char *label, int *sock_fd, struct sockaddr *source_addr, socklen_t *source_addr_len);

#endif
