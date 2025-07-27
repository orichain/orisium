#ifndef SESSIONS_WORKERS_SESSION_H
#define SESSIONS_WORKERS_SESSION_H

#include <netinet/in.h>
#include <stdint.h>

#include "kalman.h"
#include "pqc.h"
#include "orilink/protocol.h"
#include "async.h"
#include "stdbool.h"
#include "constants.h"

typedef struct {
    bool in_use;
    struct sockaddr_in6 old_client_addr;
    struct sockaddr_in6 client_addr;
    int sock_fd;
//======================================================================
// IDENTITY
//======================================================================    
	orilink_identity_t identity;
    uint8_t local_nonce[AES_NONCE_BYTES];
    uint32_t local_ctr;
    uint8_t remote_nonce[AES_NONCE_BYTES];
    uint32_t remote_ctr;
    uint8_t encrypted_server_id_port[AES_NONCE_BYTES + sizeof(uint64_t) + sizeof(uint16_t) + AES_TAG_BYTES];
    uint8_t temp_kem_sharedsecret[KEM_SHAREDSECRET_BYTES];
//======================================================================
// ORICLE
//======================================================================    
    oricle_double_t rtt;
    oricle_double_t retry;
} sio_c_session_t; //Server

typedef struct {
    bool sent;
    int sent_try_count;
    uint64_t sent_time;
    int timer_fd;
    double interval_timer_fd;
    bool ack_rcvd;
    uint64_t ack_rcvd_time;
} hello_t;

typedef struct {
    bool in_use;
    struct sockaddr_in6 old_server_addr;
    struct sockaddr_in6 server_addr;
    int sock_fd;
//======================================================================
// IDENTITY
//======================================================================    
	orilink_identity_t identity;
    uint8_t local_nonce[AES_NONCE_BYTES];
    uint32_t local_ctr;
    uint8_t remote_nonce[AES_NONCE_BYTES];
    uint32_t remote_ctr;
    uint8_t encrypted_server_id_port[AES_NONCE_BYTES + sizeof(uint64_t) + sizeof(uint16_t) + AES_TAG_BYTES];
    uint8_t temp_kem_sharedsecret[KEM_SHAREDSECRET_BYTES];
    uint64_t new_client_id;
//======================================================================
// HELLO SOCK
//======================================================================
    hello_t hello1;
    hello_t hello2;
    hello_t hello3;
    hello_t hello_end;
//======================================================================
// ORICLE
//======================================================================    
    oricle_double_t rtt;
    oricle_double_t retry;
} cow_c_session_t; //Client

void cleanup_hello(const char *label, async_type_t *async, hello_t *h);
void setup_hello(hello_t *h);

#endif
