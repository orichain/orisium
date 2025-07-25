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
    master_sio_c_session_t sio_c_session[MAX_MASTER_SIO_SESSIONS];
    master_sio_dc_session_t *sio_dc_session;
    master_cow_c_session_t cow_c_session[MAX_MASTER_COW_SESSIONS];
    int last_sio_rr_idx;
    uds_pair_pid_t logic[MAX_LOGIC_WORKERS];
    int last_cow_rr_idx;
    uds_pair_pid_t cow[MAX_COW_WORKERS];
    uds_pair_pid_t dbr[MAX_DBR_WORKERS];
    uds_pair_pid_t dbw[MAX_DBW_WORKERS];
    master_sio_session_t sio_session[MAX_SIO_WORKERS];
    master_logic_session_t logic_session[MAX_LOGIC_WORKERS];
    master_cow_session_t cow_session[MAX_COW_WORKERS];
    master_dbr_session_t dbr_session[MAX_DBR_WORKERS];
    master_dbw_session_t dbw_session[MAX_DBW_WORKERS];    
} master_context;

void sigint_handler(int signum);
void run_master_process(master_context *master_ctx, uint16_t *listen_port, bootstrap_nodes_t *bootstrap_nodes);

#endif
