#ifndef MASTER_PROCESS_H
#define MASTER_PROCESS_H

#include <sys/types.h>

#include "async.h"
#include "constants.h"
#include "types.h"
#include "node.h"
#include "sessions/master_session.h"

typedef int uds_pair[2];

typedef struct {
	uds_pair uds;
	pid_t pid;
} uds_pair_pid_t;

typedef struct {
	int master_pid;
    int listen_sock;
    int master_timer_fd;
    int shutdown_event_fd;
    async_type_t master_async;
    uds_pair_pid_t sio[MAX_SIO_WORKERS];
    master_sio_c_session_t sio_c_session[MAX_MASTER_CONCURRENT_SESSIONS];
    master_sio_dc_session_t *sio_dc_session;
    int last_sio_rr_idx;
    uds_pair_pid_t logic[MAX_LOGIC_WORKERS];
    int last_cow_rr_idx;
    uds_pair_pid_t cow[MAX_COW_WORKERS];
    uds_pair_pid_t dbr[MAX_DBR_WORKERS];
    uds_pair_pid_t dbw[MAX_DBW_WORKERS];
    master_sio_state_t sio_state[MAX_SIO_WORKERS];
    master_logic_state_t logic_state[MAX_LOGIC_WORKERS];
    master_cow_state_t cow_state[MAX_COW_WORKERS];
    master_dbr_state_t dbr_state[MAX_DBR_WORKERS];
    master_dbw_state_t dbw_state[MAX_DBW_WORKERS];    
} master_context;

void run_master_process(master_context *master_ctx, uint16_t *listen_port, bootstrap_nodes_t *bootstrap_nodes);
status_t setup_master(master_context *master_ctx, uint16_t *listen_port);

#endif
