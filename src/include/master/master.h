#ifndef MASTER_MASTER_H
#define MASTER_MASTER_H

#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "async.h"
#include "ipc/protocol.h"
#include "kalman.h"
#include "node.h"
#include "types.h" 
#include "timer.h" 

typedef struct {
    double hb_interval;
    double sum_hb_interval;
    double count_ack;
    uint64_t last_ack;
    uint64_t last_checkhealthy;
    uint64_t last_task_started;
    uint64_t last_task_finished;
    uint64_t longest_task_time;
} worker_metrics_t;

typedef int uds_pair[2];

typedef struct {
	uds_pair uds;
	pid_t pid;
} uds_pair_pid_t;

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
    bool hello1_rcvd;
    bool hello1_ack_sent;
    bool hello2_rcvd;
    bool hello2_ack_sent;
} worker_security_t;

typedef struct {
    bool is_rekeying;
    ipc_protocol_queue_t *rekeying_queue;
} worker_rekeying_t;

typedef struct {
    bool isactive;
    bool ishealthy;
    bool isready;
    uint16_t task_count;
    uds_pair_pid_t upp;
	worker_metrics_t metrics;
    oricle_double_t healthy;
    oricle_long_double_t avgtt;
    worker_security_t security;
    worker_rekeying_t rekeying;
} master_worker_session_t;

typedef struct {
	uint8_t sio_index;
    bool in_use;
    bool in_secure;
    uint64_t id_connection;
    struct sockaddr_in6 remote_addr;
} master_sio_c_session_t;

typedef struct {
	uint8_t cow_index;
    bool in_use;
    bool in_secure;
    uint64_t id_connection;
    struct sockaddr_in6 remote_addr;
} master_cow_c_session_t;

typedef struct {
//----------------------------------------------------------------------
	int master_pid;
    int udp_sock;
    uint64_t check_healthy_timer_id;
    int shutdown_event_fd;
    async_type_t master_async;
//----------------------------------------------------------------------
    uint8_t last_sio_rr_idx;
    uint8_t last_cow_rr_idx;
//----------------------------------------------------------------------
    uint16_t listen_port;
    bootstrap_nodes_t bootstrap_nodes;
    sig_atomic_t shutdown_requested;
    uint16_t hb_check_times;
//----------------------------------------------------------------------
    bool all_workers_is_ready;
    bool is_rekeying;
//----------------------------------------------------------------------    
    master_worker_session_t *sio_session;
    master_worker_session_t *logic_session;
    master_worker_session_t *cow_session;
    master_worker_session_t *dbr_session;
    master_worker_session_t *dbw_session;    
//----------------------------------------------------------------------
    master_sio_c_session_t *sio_c_session;
    master_cow_c_session_t *cow_c_session;
//----------------------------------------------------------------------
    hierarchical_timer_wheel_t timer;
} master_context_t;

static inline master_worker_session_t *get_master_worker_session(master_context_t *master_context, worker_type_t wot, uint8_t index) {
    switch (wot) {
        case SIO: {
            return &master_context->sio_session[index];
        }
        case LOGIC: {
            return &master_context->logic_session[index];
        }
        case COW: {
            return &master_context->cow_session[index];
        }
        case DBR: {
            return &master_context->dbr_session[index];
        }
        case DBW: {
            return &master_context->dbw_session[index];
        }
        default:
            return NULL;
    }
}

static inline const char *get_master_worker_name(worker_type_t wot) {
    switch (wot) {
        case SIO: {
            return "SIO";
        }
        case LOGIC: {
            return "LOGIC";
        }
        case COW: {
            return "COW";
        }
        case DBR: {
            return "DBR";
        }
        case DBW: {
            return "DBW";
        }
        default:
            return "UNKNOWN";
    }
}

//----------------------------------------------------------------------
void sigint_handler(int signum);
//----------------------------------------------------------------------
status_t setup_master(const char *label, master_context_t *master_ctx);
void cleanup_master(const char *label, master_context_t *master_ctx);
void run_master(const char *label, master_context_t *master_ctx);
//----------------------------------------------------------------------

#endif
