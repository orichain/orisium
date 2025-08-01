#ifndef WORKERS_WORKER_H
#define WORKERS_WORKER_H

#include <sys/types.h>
#include <bits/types/sig_atomic_t.h>

#include "async.h"
#include "constants.h"
#include "types.h"
#include "node.h"
#include "pqc.h"
#include "sessions/workers_session.h"

typedef struct {
    int pid;
    worker_type_t wot;
    uint16_t idx;
    int master_uds_fd;
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

typedef struct {
    worker_context_t worker;
    sio_c_session_t sio_c_session[MAX_CONNECTION_PER_SIO_WORKER];
} sio_context_t;

typedef struct {
    worker_context_t worker;
} logic_context_t;

typedef struct {
    worker_context_t worker;
    cow_c_session_t cow_c_session[MAX_CONNECTION_PER_COW_WORKER];
} cow_context_t;

typedef struct {
    worker_context_t worker;
} dbr_context_t;

typedef struct {
    worker_context_t worker;
} dbw_context_t;

status_t setup_worker(worker_context_t *ctx, const char *worker_name, worker_type_t wot, uint8_t worker_idx, int master_uds_fd);
void cleanup_worker(worker_context_t *ctx);
void run_sio_worker(worker_type_t wot, uint8_t worker_idx, long initial_delay_ms, int master_uds_fd);
void run_logic_worker(worker_type_t wot, uint8_t worker_idx, long initial_delay_ms, int master_uds_fd);
void run_cow_worker(worker_type_t wot, uint8_t worker_idx, long initial_delay_ms, int master_uds_fd);
void run_dbr_worker(worker_type_t wot, uint8_t worker_idx, long initial_delay_ms, int master_uds_fd);
void run_dbw_worker(worker_type_t wot, uint8_t worker_idx, long initial_delay_ms, int master_uds_fd);

#endif
