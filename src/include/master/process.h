#ifndef MASTER_PROCESS_H
#define MASTER_PROCESS_H

#include <sys/types.h>
#include <stdbool.h>

#include "async.h"
#include "constants.h"
#include "types.h"
#include "node.h"
#include "sessions/master_session.h"

typedef struct {
//----------------------------------------------------------------------
	int master_pid;
    int listen_sock;
    int heartbeat_timer_fd;
    int shutdown_event_fd;
    async_type_t master_async;
//----------------------------------------------------------------------
    int last_sio_rr_idx;
    int last_cow_rr_idx;
//----------------------------------------------------------------------
    uint16_t listen_port;
    bootstrap_nodes_t bootstrap_nodes;
//----------------------------------------------------------------------
    bool all_workers_is_ready;
    bool is_rekeying;
//----------------------------------------------------------------------
    uint8_t *kem_privatekey;
    uint8_t *kem_publickey;
//----------------------------------------------------------------------    
    master_sio_session_t *sio_session;
    master_logic_session_t *logic_session;
    master_cow_session_t *cow_session;
    master_dbr_session_t *dbr_session;
    master_dbw_session_t *dbw_session;    
//----------------------------------------------------------------------
    master_sio_c_session_t *sio_c_session;
    master_cow_c_session_t *cow_c_session;
//----------------------------------------------------------------------
} master_context_t;

void sigint_handler(int signum);
void run_master_process(master_context_t *master_ctx);
void cleanup_master_sio_session(const char *label, async_type_t *master_async, master_sio_c_session_t *session);
void cleanup_master_cow_session(master_cow_c_session_t *session);

#endif
