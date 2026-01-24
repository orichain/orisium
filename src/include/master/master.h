#ifndef MASTER_MASTER_H
#define MASTER_MASTER_H

#include "async.h"
#include "ipc/protocol.h"
#include "kalman.h"
#include "oritw.h"
#include "oritw/timer_id.h"
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

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
    ipc_protocol_queue_t *rekeying_queue_head;
    ipc_protocol_queue_t *rekeying_queue_tail;
} worker_rekeying_t;

typedef struct {
    bool isactive;
    bool ishealthy;
    bool isready;
    uint16_t task_count;
    uds_pair_pid_t *upp;
    worker_metrics_t *metrics;
    oricle_double_t *healthy;
    oricle_long_double_t *avgtt;
    worker_security_t *security;
    worker_rekeying_t *rekeying;
    et_buffer_t *buffer;
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
    int ipv6_udp;
    int ipv4_udp;
    timer_id_t check_healthy_timer_id;
    et_buffered_event_id_t *shutdown_event_fd;
    async_type_t master_async;
    //----------------------------------------------------------------------
    uint8_t last_sio_rr_idx;
    uint8_t last_logic_rr_idx;
    uint8_t last_cow_rr_idx;
    uint8_t last_dbr_rr_idx;
    uint8_t last_dbw_rr_idx;
    //----------------------------------------------------------------------
    uint16_t listen_port;
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
    ori_timer_wheels_t timer;
    //----------------------------------------------------------------------
    uint8_t *arena_buffer;
    oritlsf_pool_t oritlsf_pool;
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

//----------------------------------------------------------------------
void sigint_handler(int signum);
//----------------------------------------------------------------------
status_t setup_master(const char *label, master_context_t *master_ctx);
void cleanup_master(const char *label, master_context_t *master_ctx);
void run_master(const char *label, master_context_t *master_ctx);
//----------------------------------------------------------------------
double initialize_metrics(const char *label, worker_metrics_t* metrics, worker_type_t wot, uint8_t index);
status_t new_task_metrics(const char *label, master_context_t *master_ctx, worker_type_t wot, uint8_t index);
uint8_t select_best_worker(const char *label, master_context_t *master_ctx, worker_type_t wot);
status_t close_worker(const char *label, master_context_t *master_ctx, worker_type_t wot, uint8_t index);
status_t create_socket_pair(const char *label, master_context_t *master_ctx, worker_type_t wot, uint8_t index);
status_t setup_fork_worker(const char* label, master_context_t *master_ctx, worker_type_t wot, uint8_t index);
status_t setup_workers(const char *label, master_context_t *master_ctx);
void cleanup_workers(const char *label, master_context_t *master_ctx);
status_t calculate_avgtt(const char *label, master_context_t *master_ctx, worker_type_t wot, uint8_t index);
status_t check_workers_healthy(const char *label, master_context_t *master_ctx);
status_t recreate_worker(const char *label, master_context_t *master_ctx, worker_type_t wot, uint8_t index);
status_t handle_master_ipc_hello1(const char *label, master_context_t *master_ctx, worker_type_t rcvd_wot, uint8_t rcvd_index, worker_security_t *security, const char *worker_name, int *worker_uds_fd, ipc_raw_protocol_t_status_t *ircvdi);
status_t handle_master_ipc_hello2(const char *label, master_context_t *master_ctx, worker_type_t rcvd_wot, uint8_t rcvd_index, worker_security_t *security, worker_rekeying_t *rekeying, const char *worker_name, int *worker_uds_fd, ipc_raw_protocol_t_status_t *ircvdi);
status_t handle_master_ipc_heartbeat(const char *label, master_context_t *master_ctx, worker_type_t rcvd_wot, uint8_t rcvd_index, worker_security_t *security, ipc_raw_protocol_t_status_t *ircvdi);
status_t handle_master_ipc_udp_data(const char *label, master_context_t *master_ctx, worker_security_t *security, ipc_raw_protocol_t_status_t *ircvdi);
status_t handle_master_ipc_info(const char *label, master_context_t *master_ctx, worker_type_t rcvd_wot, uint8_t rcvd_index, worker_security_t *security, ipc_raw_protocol_t_status_t *ircvdi);
status_t handle_worker_ipc_info(const char *label, master_context_t *master_ctx, worker_type_t rcvd_wot, uint8_t rcvd_index, worker_security_t *security, ipc_raw_protocol_t_status_t *ircvdi);
status_t handle_master_ipc_event(const char *label, master_context_t *master_ctx, int *file_descriptor, et_buffer_t *buffer);
status_t handle_master_ipc_closed_event(const char *label, master_context_t *master_ctx, worker_type_t wot, uint8_t index, int *file_descriptor);
status_t handle_master_ipv4_udp_sock_event(const char *label, master_context_t *master_ctx);
status_t handle_master_ipv6_udp_sock_event(const char *label, master_context_t *master_ctx);
status_t setup_master_socket_udp(const char *label, master_context_t *master_ctx);

#endif
