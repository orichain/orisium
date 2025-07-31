#ifndef SESSIONS_WORKERS_SESSION_H
#define SESSIONS_WORKERS_SESSION_H

#include "kalman.h"
#include "orilink/protocol.h"
#include "async.h"

typedef struct {
    bool in_use;
    int sock_fd;
//======================================================================
// IDENTITY
//======================================================================    
	orilink_identity_t identity;
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
    int sock_fd;
//======================================================================
// IDENTITY
//======================================================================    
	orilink_identity_t identity;
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
} cow_c_session_t; //Client

void cleanup_hello(const char *label, async_type_t *async, hello_t *h);
void setup_hello(hello_t *h);

#endif
