#ifndef WORKERS_WORKERS_H
#define WORKERS_WORKERS_H

#include <sys/types.h>
#include <bits/types/sig_atomic_t.h>

#include "async.h"
#include "constants.h"
#include "types.h"
#include "node.h"
#include "pqc.h"
#include "kalman.h"
#include "orilink/protocol.h"

typedef struct {
    bool rcvd;
    uint64_t rcvd_time;
    bool ack_sent;
    int ack_sent_try_count;
    uint64_t ack_sent_time;
    int ack_timer_fd;
    double interval_ack_timer_fd;
} hello_ack_t;

typedef struct {
    bool in_use;
//======================================================================
// IDENTITY & SECURITY
//======================================================================    
	orilink_identity_t identity;
	orilink_security_t security;
//======================================================================
// HELLO SOCK
//======================================================================
    hello_ack_t hello1_ack;
    hello_ack_t hello2_ack;
    hello_ack_t hello3_ack;
    hello_ack_t sock_ready;	
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
//======================================================================
// IDENTITY & SECURITY
//======================================================================    
	orilink_identity_t identity;
	uint8_t *kem_privatekey;
	orilink_security_t security;
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

typedef struct {
    int pid;
    worker_type_t *wot;
    uint8_t *index;
    int *master_uds_fd;
    sig_atomic_t shutdown_requested;
    async_type_t async;
    int heartbeat_timer_fd;
    char *label;
    uint8_t *kem_privatekey;
    uint8_t *kem_publickey;
    uint8_t *kem_ciphertext;
    uint8_t *kem_sharedsecret;
    uint8_t *aes_key;
    uint8_t *mac_key;
    uint8_t *local_nonce;
    uint32_t local_ctr;
    uint8_t *remote_nonce;
    uint32_t remote_ctr;
    bool hello1_sent;
    bool hello1_ack_rcvd;
    bool hello2_sent;
    bool hello2_ack_rcvd;
} worker_context_t;

status_t setup_worker(worker_context_t *ctx, const char *woname, worker_type_t *wot, uint8_t *index, int *master_uds_fd);
void cleanup_worker(worker_context_t *ctx);
void run_sio_worker(worker_type_t *wot, uint8_t *index, double *initial_delay_ms, int *master_uds_fd);
void run_logic_worker(worker_type_t *wot, uint8_t *index, double *initial_delay_ms, int *master_uds_fd);
void run_cow_worker(worker_type_t *wot, uint8_t *index, double *initial_delay_ms, int *master_uds_fd);
void run_dbr_worker(worker_type_t *wot, uint8_t *index, double *initial_delay_ms, int *master_uds_fd);
void run_dbw_worker(worker_type_t *wot, uint8_t *index, double *initial_delay_ms, int *master_uds_fd);
void cleanup_hello(const char *label, async_type_t *async, hello_t *h);
void setup_hello(hello_t *h);

#endif
