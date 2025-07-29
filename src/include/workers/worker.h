#ifndef WORKERS_WORKER_H
#define WORKERS_WORKER_H

#include <sys/types.h>

#include "async.h"
#include "constants.h"
#include "types.h"
#include "node.h"

typedef struct {
    int worker_pid;
    worker_type_t wot;
    int worker_idx;
    long initial_delay_ms;
    int master_uds_fd
    
	int master_pid;
    int listen_sock;
    int master_timer_fd;
    int shutdown_event_fd;
    async_type_t master_async;
    int last_sio_rr_idx;
    int last_cow_rr_idx;
    uint8_t kem_privatekey[KEM_PRIVATEKEY_BYTES];
    uint8_t kem_publickey[KEM_PUBLICKEY_BYTES];
    master_sio_session_t sio_session[MAX_SIO_WORKERS];
    master_logic_session_t logic_session[MAX_LOGIC_WORKERS];
    master_cow_session_t cow_session[MAX_COW_WORKERS];
    master_dbr_session_t dbr_session[MAX_DBR_WORKERS];
    master_dbw_session_t dbw_session[MAX_DBW_WORKERS];    
} cow_context;

//void run_cow_worker(worker_context *worker_ctx, uint16_t *listen_port, bootstrap_nodes_t *bootstrap_nodes);

#endif
