#ifndef MASTER_MASTER_H
#define MASTER_MASTER_H

#include <sys/types.h>
#include <stdbool.h>
#include <signal.h>

#include "async.h"
#include "constants.h"
#include "types.h"
#include "node.h"
#include "kalman.h"
#include "orilink/protocol.h"
#include "pqc.h"

typedef struct {
    double hbtime;
    double sum_hbtime;
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
    bool isactive;
    bool ishealthy;
    bool isready;
    uint16_t task_count;
    uds_pair_pid_t upp;
	worker_metrics_t metrics;
    oricle_double_t healthy;
    oricle_long_double_t avgtt;
    worker_security_t security;
} master_sio_session_t;

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
} master_logic_session_t;

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
} master_cow_session_t;

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
} master_dbr_session_t;
//======================================================================
// hanya ada 1 writer
// LMDB tidak bisa multi writer
// Master harus punya write cache dalam bentuk linked list
// dbwriter memberi signal write complete dan akan mentrigger in_use=false dan flush cache 1 per satu sampai kosong
// untuk memastikan penulisan ditangani
//======================================================================
typedef struct {
	bool in_use;
    bool isactive;
    bool ishealthy;
    bool isready;
    uds_pair_pid_t upp;
	worker_metrics_t metrics;
    oricle_double_t healthy;
    oricle_long_double_t avgtt;
    worker_security_t security;
} master_dbw_session_t;

typedef struct {
	int sio_index;
    bool in_use;
} master_sio_c_session_t;

typedef struct {
	int cow_index;
    bool in_use;
} master_cow_c_session_t;

typedef struct {
//----------------------------------------------------------------------
	int master_pid;
    int udp_sock;
    int heartbeat_timer_fd;
    int shutdown_event_fd;
    async_type_t master_async;
//----------------------------------------------------------------------
    int last_sio_rr_idx;
    int last_cow_rr_idx;
//----------------------------------------------------------------------
    uint16_t listen_port;
    bootstrap_nodes_t bootstrap_nodes;
    sig_atomic_t shutdown_requested;
    uint16_t hb_check_times;
//----------------------------------------------------------------------
    bool all_workers_is_ready;
    bool is_rekeying;
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

//----------------------------------------------------------------------
void sigint_handler(int signum);
//----------------------------------------------------------------------
status_t setup_master(const char *label, master_context_t *master_ctx);
void cleanup_master(const char *label, master_context_t *master_ctx);
void run_master(const char *label, master_context_t *master_ctx);
//----------------------------------------------------------------------

#endif
