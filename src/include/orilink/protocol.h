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
        } else if (x->type == ORILINK_HEARTBEAT) {
            CLOSE_ORILINK_PAYLOAD((void **)&x->payload.orilink_heartbeat);
        } else if (x->type == ORILINK_HEARTBEAT_ACK) {
            CLOSE_ORILINK_PAYLOAD((void **)&x->payload.orilink_heartbeat_ack);
        } else if (x->type == ORILINK_INFO) {
            CLOSE_ORILINK_PAYLOAD((void **)&x->payload.orilink_info);
        } else if (x->type == ORILINK_INFO_ACK) {
            CLOSE_ORILINK_PAYLOAD((void **)&x->payload.orilink_info_ack);
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

static inline ssize_t_status_t send_orilink_raw_protocol_packet(const char *label, puint8_t_size_t_status_t *r, int *sock_fd, const struct sockaddr_in6 *dest_addr) {
	ssize_t_status_t result;
    result.r_ssize_t = 0;
    result.status = FAILURE;
    socklen_t dest_addr_len = sizeof(struct sockaddr_in6);
    result.r_ssize_t = sendto(*sock_fd, r->r_puint8_t, r->r_size_t, 0, (const struct sockaddr *)dest_addr, dest_addr_len);
    if (result.r_ssize_t != (ssize_t)r->r_size_t) {
        LOG_ERROR("%ssendto failed to send_orilink_protocol_packet. %s", label, strerror(errno));
        if (r->r_puint8_t) {
            free(r->r_puint8_t);
            r->r_puint8_t = NULL;
            r->r_size_t = 0;
        }
        result.status = FAILURE;
        return result;
    }
    if (r->r_puint8_t) {
        free(r->r_puint8_t);
        r->r_puint8_t = NULL;
        r->r_size_t = 0;
    }
    result.status = SUCCESS;
    return result;
}

static inline status_t orilink_check_mac(const char *label, uint8_t* key_mac, orilink_raw_protocol_t *r) {
    uint8_t *key0 = (uint8_t *)calloc(1, HASHES_BYTES * sizeof(uint8_t));
    if (memcmp(
            key_mac, 
            key0, 
            HASHES_BYTES
        ) != 0
    )
    {
        uint8_t *data_4mac = r->recv_buffer;
        const size_t data_offset = AES_TAG_BYTES;
        size_t data_len = r->n - AES_TAG_BYTES;
        uint8_t *data = r->recv_buffer + data_offset;
        if (compare_mac(
                key_mac,
                data,
                data_len,
                data_4mac
            ) != SUCCESS
        )
        {
            LOG_ERROR("%sOrilink Mac mismatch!", label);
            free(key0);
            return FAILURE_MACMSMTCH;
        }
    }
    free(key0);
    return SUCCESS;
}

static inline status_t orilink_read_header(
    const char *label,
    uint8_t* key_mac, 
    uint8_t* nonce,
    uint32_t* ctr,
    orilink_raw_protocol_t *r
)
{
    size_t current_offset = 0;
    size_t total_buffer_len = (size_t)r->n;
    uint8_t *cursor = r->recv_buffer + current_offset;
    #if defined(ORILINK_DECRYPT_HEADER)
        uint8_t *key0 = (uint8_t *)calloc(1, HASHES_BYTES * sizeof(uint8_t));
        if (memcmp(
                key_mac, 
                key0, 
                HASHES_BYTES
            ) != 0
        )
        {
            const size_t header_offset = AES_TAG_BYTES;
            const size_t header_len = sizeof(uint32_t) +
                                      ORILINK_VERSION_BYTES +
                                      sizeof(uint8_t) +
                                      sizeof(uint8_t) +
                                      sizeof(uint8_t);
            uint8_t *header = cursor + header_offset;
            uint8_t *decripted_header = cursor + header_offset;
            if (encrypt_decrypt_128(
                    label,
                    key_mac,
                    nonce,
                    ctr,
                    header,
                    decripted_header,
                    header_len
                ) != SUCCESS
            )
            {
                free(key0);
                return FAILURE;
            }
        }
        free(key0);
    #endif
//----------------------------------------------------------------------    
// Mac
//----------------------------------------------------------------------    
    if (current_offset + AES_TAG_BYTES > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading mac.", label);
        return FAILURE_OOBUF;
    }
    memcpy(r->mac, cursor, AES_TAG_BYTES);
    cursor += AES_TAG_BYTES;
    current_offset += AES_TAG_BYTES;
//----------------------------------------------------------------------    
// Ctr
//----------------------------------------------------------------------    
    if (current_offset + sizeof(uint32_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading ctr.", label);
        return FAILURE_OOBUF;
    }
    uint32_t ctr_be;
    memcpy(&ctr_be, cursor, sizeof(uint32_t));
    r->ctr = be32toh(ctr_be);
    cursor += sizeof(uint32_t);
    current_offset += sizeof(uint32_t);
//----------------------------------------------------------------------    
// Version
//----------------------------------------------------------------------    
    if (current_offset + ORILINK_VERSION_BYTES > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading version.", label);
        return FAILURE_OOBUF;
    }
    memcpy(r->version, cursor, ORILINK_VERSION_BYTES);
    cursor += ORILINK_VERSION_BYTES;
    current_offset += ORILINK_VERSION_BYTES;
//----------------------------------------------------------------------    
// Inc Ctr
//----------------------------------------------------------------------    
    if (current_offset + sizeof(uint8_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading inc_ctr.", label);
        return FAILURE_OOBUF;
    }
    memcpy(&r->inc_ctr, cursor, sizeof(uint8_t));
    cursor += sizeof(uint8_t);
    current_offset += sizeof(uint8_t);
//----------------------------------------------------------------------    
// Local Index
//----------------------------------------------------------------------    
    if (current_offset + sizeof(uint8_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading local_index.", label);
        return FAILURE_OOBUF;
    }
    memcpy(&r->local_index, cursor, sizeof(uint8_t));
    cursor += sizeof(uint8_t);
    current_offset += sizeof(uint8_t);
//----------------------------------------------------------------------    
// Local Session Index
//----------------------------------------------------------------------    
    if (current_offset + sizeof(uint8_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading local_session_index.", label);
        return FAILURE_OOBUF;
    }
    memcpy(&r->local_session_index, cursor, sizeof(uint8_t));
    cursor += sizeof(uint8_t);
    current_offset += sizeof(uint8_t);
//----------------------------------------------------------------------    
// Local Wot
//----------------------------------------------------------------------    
    if (current_offset + sizeof(uint8_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading local_wot.", label);
        return FAILURE_OOBUF;
    }
    memcpy((uint8_t *)&r->local_wot, cursor, sizeof(uint8_t));
    cursor += sizeof(uint8_t);
    current_offset += sizeof(uint8_t);
//----------------------------------------------------------------------    
// Id Connection
//----------------------------------------------------------------------    
    if (current_offset + sizeof(uint64_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading id_connection.", label);
        return FAILURE_OOBUF;
    }
    uint64_t id_connection_be;
    memcpy(&id_connection_be, cursor, sizeof(uint64_t));
    r->id_connection = be64toh(id_connection_be);
    cursor += sizeof(uint64_t);
    current_offset += sizeof(uint64_t);
//----------------------------------------------------------------------    
// Remote Wot
//----------------------------------------------------------------------    
    if (current_offset + sizeof(uint8_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading remote_wot.", label);
        return FAILURE_OOBUF;
    }
    memcpy((uint8_t *)&r->remote_wot, cursor, sizeof(uint8_t));
    cursor += sizeof(uint8_t);
    current_offset += sizeof(uint8_t);
//----------------------------------------------------------------------    
// Remote Index
//----------------------------------------------------------------------    
    if (current_offset + sizeof(uint8_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading remote_index.", label);
        return FAILURE_OOBUF;
    }
    memcpy(&r->remote_index, cursor, sizeof(uint8_t));
    cursor += sizeof(uint8_t);
    current_offset += sizeof(uint8_t);
//----------------------------------------------------------------------    
// Remote Session Index
//----------------------------------------------------------------------    
    if (current_offset + sizeof(uint8_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading remote_session_index.", label);
        return FAILURE_OOBUF;
    }
    memcpy(&r->remote_session_index, cursor, sizeof(uint8_t));
    cursor += sizeof(uint8_t);
    current_offset += sizeof(uint8_t);
//----------------------------------------------------------------------    
// Type
//----------------------------------------------------------------------    
    if (current_offset + sizeof(uint8_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading type.", label);
        return FAILURE_OOBUF;
    }
    memcpy((uint8_t *)&r->type, cursor, sizeof(uint8_t));
    cursor += sizeof(uint8_t);
    current_offset += sizeof(uint8_t);
//----------------------------------------------------------------------    
// Trycount
//---------------------------------------------------------------------- 
    if (current_offset + sizeof(uint8_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading trycount.", label);
        return FAILURE_OOBUF;
    }
    memcpy(&r->trycount, cursor, sizeof(uint8_t));
//---------------------------------------------------------------------- 
    return SUCCESS;
}

static inline status_t orilink_read_cleartext_header(
    const char *label, 
    orilink_raw_protocol_t *r
)
{
    size_t current_offset = 0;
    size_t total_buffer_len = (size_t)r->n;
    uint8_t *cursor = r->recv_buffer + current_offset;
//----------------------------------------------------------------------    
// Mac
//----------------------------------------------------------------------    
    if (current_offset + AES_TAG_BYTES > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading mac.", label);
        return FAILURE_OOBUF;
    }
    cursor += AES_TAG_BYTES;
    current_offset += AES_TAG_BYTES;
//----------------------------------------------------------------------    
// Ctr
//----------------------------------------------------------------------    
    if (current_offset + sizeof(uint32_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading ctr.", label);
        return FAILURE_OOBUF;
    }
    cursor += sizeof(uint32_t);
    current_offset += sizeof(uint32_t);
//----------------------------------------------------------------------    
// Version
//----------------------------------------------------------------------    
    if (current_offset + ORILINK_VERSION_BYTES > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading version.", label);
        return FAILURE_OOBUF;
    }
    cursor += ORILINK_VERSION_BYTES;
    current_offset += ORILINK_VERSION_BYTES;
//----------------------------------------------------------------------    
// Inc Ctr
//----------------------------------------------------------------------    
    if (current_offset + sizeof(uint8_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading inc_ctr.", label);
        return FAILURE_OOBUF;
    }
    cursor += sizeof(uint8_t);
    current_offset += sizeof(uint8_t);
//----------------------------------------------------------------------    
// Local Index
//----------------------------------------------------------------------    
    if (current_offset + sizeof(uint8_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading local_index.", label);
        return FAILURE_OOBUF;
    }
    cursor += sizeof(uint8_t);
    current_offset += sizeof(uint8_t);
//----------------------------------------------------------------------    
// Local Session Index
//----------------------------------------------------------------------    
    if (current_offset + sizeof(uint8_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading local_session_index.", label);
        return FAILURE_OOBUF;
    }
    cursor += sizeof(uint8_t);
    current_offset += sizeof(uint8_t);
//----------------------------------------------------------------------    
// Local Wot
//----------------------------------------------------------------------    
    if (current_offset + sizeof(uint8_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading local_wot.", label);
        return FAILURE_OOBUF;
    }
    memcpy((uint8_t *)&r->local_wot, cursor, sizeof(uint8_t));
    cursor += sizeof(uint8_t);
    current_offset += sizeof(uint8_t);
//----------------------------------------------------------------------    
// Id Connection
//----------------------------------------------------------------------    
    if (current_offset + sizeof(uint64_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading id_connection.", label);
        return FAILURE_OOBUF;
    }
    uint64_t id_connection_be;
    memcpy(&id_connection_be, cursor, sizeof(uint64_t));
    r->id_connection = be64toh(id_connection_be);
    cursor += sizeof(uint64_t);
    current_offset += sizeof(uint64_t);
//----------------------------------------------------------------------    
// Remote Wot
//----------------------------------------------------------------------    
    if (current_offset + sizeof(uint8_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading remote_wot.", label);
        return FAILURE_OOBUF;
    }
    memcpy((uint8_t *)&r->remote_wot, cursor, sizeof(uint8_t));
    cursor += sizeof(uint8_t);
    current_offset += sizeof(uint8_t);
//----------------------------------------------------------------------    
// Remote Index
//----------------------------------------------------------------------    
    if (current_offset + sizeof(uint8_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading remote_index.", label);
        return FAILURE_OOBUF;
    }
    memcpy(&r->remote_index, cursor, sizeof(uint8_t));
    cursor += sizeof(uint8_t);
    current_offset += sizeof(uint8_t);
//----------------------------------------------------------------------    
// Remote Session Index
//----------------------------------------------------------------------    
    if (current_offset + sizeof(uint8_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading remote_session_index.", label);
        return FAILURE_OOBUF;
    }
    memcpy(&r->remote_session_index, cursor, sizeof(uint8_t));
    cursor += sizeof(uint8_t);
    current_offset += sizeof(uint8_t);
//----------------------------------------------------------------------    
// Type
//----------------------------------------------------------------------    
    if (current_offset + sizeof(uint8_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading type.", label);
        return FAILURE_OOBUF;
    }
    memcpy((uint8_t *)&r->type, cursor, sizeof(uint8_t));
    cursor += sizeof(uint8_t);
    current_offset += sizeof(uint8_t);
//----------------------------------------------------------------------    
// Trycount
//---------------------------------------------------------------------- 
    if (current_offset + sizeof(uint8_t) > total_buffer_len) {
        LOG_ERROR("%sOut of bounds reading trycount.", label);
        return FAILURE_OOBUF;
    }
    memcpy(&r->trycount, cursor, sizeof(uint8_t));
//----------------------------------------------------------------------
    return SUCCESS;
}

static inline orilink_raw_protocol_t_status_t receive_orilink_raw_protocol_packet(const char *label, int *sock_fd, struct sockaddr_in6 *source_addr) {
    orilink_raw_protocol_t_status_t result;
    result.status = FAILURE;
    result.r_orilink_raw_protocol_t = NULL;
    uint8_t *full_orilink_payload_buffer = (uint8_t *)calloc(1, ORILINK_MAX_PACKET_SIZE * sizeof(uint8_t));
    socklen_t source_addr_len = sizeof(struct sockaddr_in6);
    ssize_t bytes_read_payload = recvfrom(*sock_fd, full_orilink_payload_buffer, ORILINK_MAX_PACKET_SIZE, 0, (struct sockaddr * restrict)source_addr, &source_addr_len);
    const size_t min_size = AES_TAG_BYTES + 
                            sizeof(uint32_t) + 
                            ORILINK_VERSION_BYTES + 
                            sizeof(uint8_t) + 
                            sizeof(uint8_t) + 
                            sizeof(uint8_t) + 
                            sizeof(uint8_t) + 
                            
                            sizeof(uint64_t) + 
                            
                            sizeof(uint8_t) + 
                            sizeof(uint8_t) + 
                            sizeof(uint8_t) + 
                            sizeof(uint8_t) + 
                            sizeof(uint8_t);
    if (bytes_read_payload < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
			LOG_ERROR("%sreceive_orilink_raw_protocol_packet failed: %s", label, strerror(errno));
			free(full_orilink_payload_buffer);
            result.status = FAILURE_EAGNEWBLK;
            return result;
        } else {
            LOG_ERROR("%sreceive_orilink_raw_protocol_packet failed: %s", label, strerror(errno));
            free(full_orilink_payload_buffer);
            result.status = FAILURE;
            return result;
        }
    } else if (bytes_read_payload < (ssize_t)min_size) {
        LOG_ERROR("%sreceive_orilink_raw_protocol_packet received invalid size(min size) orilink packet.", label);
        free(full_orilink_payload_buffer);
        result.status = FAILURE_OOBUF;
        return result;
    } else if (bytes_read_payload > (ssize_t)ORILINK_MAX_PACKET_SIZE) {
        LOG_ERROR("%sreceive_orilink_raw_protocol_packet received invalid size(max size) orilink packet.", label);
        free(full_orilink_payload_buffer);
        result.status = FAILURE_OOBUF;
        return result;
    }
    orilink_raw_protocol_t *r = (orilink_raw_protocol_t*)calloc(1, sizeof(orilink_raw_protocol_t));
    if (!r) {
        LOG_ERROR("%sFailed to allocate orilink_raw_protocol_t. %s", label, strerror(errno));
        free(full_orilink_payload_buffer);
        result.status = FAILURE_NOMEM;
        return result;
    }
    r->recv_buffer = full_orilink_payload_buffer;
    r->n = (uint16_t)bytes_read_payload;
    full_orilink_payload_buffer = NULL;
    bytes_read_payload = 0;
    if (orilink_read_cleartext_header(label, r) != SUCCESS) {
        free(r->recv_buffer);
        r->n = (uint16_t)0;
        result.status = FAILURE;
        return result;
    }
    result.r_orilink_raw_protocol_t = r;
    result.status = SUCCESS;
    return result;
}

static inline status_t udp_data_to_orilink_raw_protocol_packet(const char *label, ipc_udp_data_t *iudp_datai, orilink_raw_protocol_t *oudp_datao) {
    oudp_datao->recv_buffer = (uint8_t *)calloc(1, iudp_datai->len);
    if (!oudp_datao->recv_buffer) {
        LOG_ERROR("%sFailed to allocate orilink_raw_protocol_t buffer. %s", label, strerror(errno));
        return FAILURE_NOMEM;
    }
    memcpy(oudp_datao->recv_buffer, iudp_datai->data, iudp_datai->len);
    oudp_datao->n = iudp_datai->len;
    if (orilink_read_cleartext_header(label, oudp_datao) != SUCCESS) {
        free(oudp_datao->recv_buffer);
        oudp_datao->n = (uint16_t)0;
        return FAILURE;
    }
    return SUCCESS;
}

orilink_protocol_t_status_t orilink_deserialize(const char *label, uint8_t *key_aes, uint8_t *nonce, uint32_t *ctr, uint8_t* buffer, size_t len);
puint8_t_size_t_status_t create_orilink_raw_protocol_packet(const char *label, uint8_t* key_aes, uint8_t* key_mac, uint8_t* nonce, uint32_t *ctr, const orilink_protocol_t* p);

#endif
