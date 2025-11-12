#ifndef WORKERS_WORKERS_H
#define WORKERS_WORKERS_H

#include <netinet/in.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "async.h"
#include "constants.h"
#include "ipc/protocol.h"
#include "kalman.h"
#include "log.h"
#include "orilink/protocol.h"
#include "pqc.h"
#include "stdbool.h"
#include "utilities.h"
#include "types.h"
#include "oritw.h"

typedef struct {
    double hb_interval;
    double sum_hb_interval;
    double count_ack;
    uint64_t last_ack;
    uint64_t last_checkhealthy;
    uint64_t last_task_started;
    uint64_t last_task_finished;
    uint64_t longest_task_time;
} node_metrics_t;

typedef struct {
    bool sent;
    uint8_t sent_try_count;
    uint64_t sent_time;
    timer_id_t retry_timer_id;
    bool ack_rcvd;
    uint64_t ack_rcvd_time;
    puint8_t_size_t_status_t udp_data;
} packet_t;

typedef struct {
    bool rcvd;
    uint64_t rcvd_time;
    bool ack_sent;
    uint8_t ack_sent_try_count;
    uint64_t ack_sent_time;
    uint8_t last_trycount;
    puint8_t_size_t_status_t udp_data;
} packet_ack_t;

typedef struct {
    packet_t heartbeat;
    packet_ack_t heartbeat_ack;
    double heartbeat_interval;
    double last_send_heartbeat_interval;
    uint8_t heartbeat_cnt;
    timer_id_t heartbeat_sender_timer_id;
    #if defined(ACCRCY_TEST)
    timer_id_t heartbeat_openner_timer_id;
    #endif
} packet_heartbeat_t;

typedef struct {
    packet_t data;
    packet_ack_t clrbuff_ack;
    double interval;
    double last_send_interval;
    timer_id_t data_sender_timer_id;
} packet_data_sender_t;

typedef struct {
    packet_t clrbuff;
    packet_ack_t data_ack;
    double interval;
    double last_send_interval;
    timer_id_t clrbuff_sender_timer_id;
} packet_data_receiver_t;

typedef struct {
    packet_data_sender_t sender;
    packet_data_receiver_t receiver;
} packet_data_t;

typedef packet_data_t packet_datas_t[PARALLEL_DATA_WINDOW_SIZE];

typedef struct {
//======================================================================
// IDENTITY & SECURITY
//======================================================================    
	orilink_identity_t identity;
	orilink_security_t security;
//======================================================================
// HELLO
//======================================================================
    packet_ack_t hello1_ack;
    packet_ack_t hello2_ack;
    packet_ack_t hello3_ack;
    packet_ack_t hello4_ack;
//======================================================================
// HEARTBEAT
//======================================================================
    packet_heartbeat_t heartbeat;
//======================================================================
// DATA
//======================================================================
    packet_datas_t data;
//----------------------------------------------------------------------
    node_metrics_t metrics;
//======================================================================
// ORICLE
//======================================================================
	oricle_double_t rtt;
    oricle_double_t retry;
    oricle_double_t healthy;
//----------------------------------------------------------------------
    orilink_raw_protocol_pool_t orilink_raw_protocol_pool;
} sio_c_session_t; //Server

typedef struct {
//======================================================================
// IDENTITY & SECURITY
//======================================================================    
	orilink_identity_t identity;
	uint8_t *kem_privatekey;
	orilink_security_t security;
//======================================================================
// HELLO
//======================================================================
    packet_t hello1;
    packet_t hello2;
    packet_t hello3;
    packet_t hello4;
//======================================================================
// HEARTBEAT
//======================================================================
    packet_heartbeat_t heartbeat;
//======================================================================
// DATA
//======================================================================
    packet_datas_t data;
//----------------------------------------------------------------------
    node_metrics_t metrics;
//======================================================================
// ORICLE
//======================================================================
	oricle_double_t rtt;
    oricle_double_t retry;
    oricle_double_t healthy;
    oricle_long_double_t avgtt;
//----------------------------------------------------------------------
    orilink_raw_protocol_pool_t orilink_raw_protocol_pool;
} cow_c_session_t; //Client

typedef struct {
    int pid;
    worker_type_t *wot;
    uint8_t *index;
    int *master_uds_fd;
    sig_atomic_t shutdown_requested;
    async_type_t async;
    timer_id_t heartbeat_timer_id;
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
    bool is_rekeying;
    ipc_protocol_queue_t *rekeying_queue_head;
    ipc_protocol_queue_t *rekeying_queue_tail;
    ori_timer_wheels_t timer;
} worker_context_t;

status_t setup_worker(worker_context_t *ctx, const char *woname, worker_type_t *wot, uint8_t *index, int *master_uds_fd);
void cleanup_worker(worker_context_t *ctx);
void run_sio_worker(worker_type_t *wot, uint8_t *index, double *initial_delay_ms, int *master_uds_fd);
void run_logic_worker(worker_type_t *wot, uint8_t *index, double *initial_delay_ms, int *master_uds_fd);
void run_cow_worker(worker_type_t *wot, uint8_t *index, double *initial_delay_ms, int *master_uds_fd);
void run_dbr_worker(worker_type_t *wot, uint8_t *index, double *initial_delay_ms, int *master_uds_fd);
void run_dbw_worker(worker_type_t *wot, uint8_t *index, double *initial_delay_ms, int *master_uds_fd);

static inline void initialize_node_metrics(const char *label, node_metrics_t* metrics) {
    uint64_t_status_t rt = get_monotonic_time_ns(label);
    metrics->sum_hb_interval = (double)0;
    metrics->hb_interval = (double)0;
    metrics->count_ack = (double)0;
    metrics->last_ack = rt.r_uint64_t;
    metrics->last_checkhealthy = rt.r_uint64_t;
    metrics->last_task_started = rt.r_uint64_t;
    metrics->last_task_finished = rt.r_uint64_t;
    metrics->longest_task_time = 0ULL;
    metrics->hb_interval = (double)NODE_HEARTBEAT_INTERVAL;
    metrics->sum_hb_interval = metrics->hb_interval;
    metrics->count_ack = (double)0;
}

static inline void calculate_retry(const char *label, void *void_session, worker_type_t wot, double try_count) {
    switch (wot) {
        case COW: {
            cow_c_session_t *session = (cow_c_session_t *)void_session;
            char *desc;
            int needed = snprintf(NULL, 0, "[RETRY %d]: ", session->identity.local_session_index);
            desc = malloc(needed + 1);
            snprintf(desc, needed + 1, "[RETRY %d]: ", session->identity.local_session_index);
            calculate_oricle_double(label, desc, &session->retry, try_count, ((double)MAX_RETRY_CNT * (double)2));
            //printf("%s%s Value Prediction: %f\n", label, desc, session->retry.value_prediction);
            free(desc);
            break;
        }
        case SIO: {
            sio_c_session_t *session = (sio_c_session_t *)void_session;
            char *desc;
            int needed = snprintf(NULL, 0, "[RETRY %d]: ", session->identity.local_session_index);
            desc = malloc(needed + 1);
            snprintf(desc, needed + 1, "[RETRY %d]: ", session->identity.local_session_index);
            calculate_oricle_double(label, desc, &session->retry, try_count, ((double)MAX_RETRY_CNT * (double)2));
            //printf("%s%s Value Prediction: %f\n", label, desc, session->retry.value_prediction);
            free(desc);
            break;
        }
        default:
            
    }
}

static inline void calculate_rtt(const char *label, void *void_session, worker_type_t wot, double rtt_value) {
    switch (wot) {
        case COW: {
            cow_c_session_t *session = (cow_c_session_t *)void_session;
            char *desc;
            int needed = snprintf(NULL, 0, "[RTT %d]: ", session->identity.local_session_index);
            desc = malloc(needed + 1);
            snprintf(desc, needed + 1, "[RTT %d]: ", session->identity.local_session_index);
            calculate_oricle_double(label, desc, &session->rtt, rtt_value, ((double)MAX_RTT_SEC * (double)1e9 * (double)2));
            //printf("%s%s Value Prediction: %f\n", label, desc, session->rtt.value_prediction);
            free(desc);
            break;
        }
        case SIO: {
            sio_c_session_t *session = (sio_c_session_t *)void_session;
            char *desc;
            int needed = snprintf(NULL, 0, "[RTT %d]: ", session->identity.local_session_index);
            desc = malloc(needed + 1);
            snprintf(desc, needed + 1, "[RTT %d]: ", session->identity.local_session_index);
            calculate_oricle_double(label, desc, &session->rtt, rtt_value, ((double)MAX_RTT_SEC * (double)1e9 * (double)2));
            //printf("%s%s Value Prediction: %f\n", label, desc, session->rtt.value_prediction);
            free(desc);
            break;
        }
        default:
            
    }
}

static inline void cleanup_control_packet(worker_context_t *ctx, packet_t *h, bool clean_state, clean_data_type_t clean_data) {
    if (clean_state) {
        h->sent = false;
        h->sent_time = (uint64_t)0;
        h->ack_rcvd_time = (uint64_t)0;
        h->ack_rcvd = false;
    }
    switch (clean_data) {
        case CDT_RESET: {
            memset(h->udp_data.r_puint8_t, 0, h->udp_data.r_size_t);
            h->udp_data.r_size_t = (size_t)0;
            break;
        }
        case CDT_FREE: {
            if (h->udp_data.r_puint8_t) {
                memset(h->udp_data.r_puint8_t, 0, h->udp_data.r_size_t);
                free(h->udp_data.r_puint8_t);
                h->udp_data.r_puint8_t = NULL;
            }
            h->udp_data.r_size_t = (size_t)0;
            break;
        }
        default:
    }
    h->sent_try_count = 0x00;
    if (h->retry_timer_id.event) {
        oritw_remove_event(ctx->label, &ctx->async, &ctx->timer, h->retry_timer_id.event);
        h->retry_timer_id.event = NULL;
        h->retry_timer_id.delay_us = 0.0;
//----------------------------------------------------------------------
// Reuse Old Id
//----------------------------------------------------------------------
        //h->retry_timer_id.id = 0ULL;
//----------------------------------------------------------------------
    }
}

static inline void setup_control_packet(const char *label, uint8_t session_index, packet_t *h) {
    h->sent = false;
    h->sent_time = (uint64_t)0;
    h->ack_rcvd_time = (uint64_t)0;
    h->ack_rcvd = false;
    h->sent_try_count = 0x00;
    h->udp_data.r_puint8_t = NULL;
    h->udp_data.r_size_t = (size_t)0;
    generate_si_id(label, session_index, &h->retry_timer_id.id);
    h->retry_timer_id.delay_us = 0.0;
    h->retry_timer_id.event = NULL;
}

static inline void cleanup_control_packet_ack(packet_ack_t *h, bool clean_state, clean_data_type_t clean_data) {
    if (clean_state) {
        h->rcvd = false;
        h->rcvd_time = (uint64_t)0;
        h->ack_sent_time = (uint64_t)0;
        h->ack_sent = false;
    }
    //----------------------------------------------------------------------
    switch (clean_data) {
        case CDT_RESET: {
            memset(h->udp_data.r_puint8_t, 0, h->udp_data.r_size_t);
            h->udp_data.r_size_t = (size_t)0;
            break;
        }
        case CDT_FREE: {
            if (h->udp_data.r_puint8_t) {
                memset(h->udp_data.r_puint8_t, 0, h->udp_data.r_size_t);
                free(h->udp_data.r_puint8_t);
                h->udp_data.r_puint8_t = NULL;
            }
            h->udp_data.r_size_t = (size_t)0;
            break;
        }
        default:
    }
    h->ack_sent_try_count = 0x00;
    h->last_trycount = (uint8_t)0;
}

static inline void setup_control_packet_ack(packet_ack_t *h) {
    h->rcvd = false;
    h->rcvd_time = (uint64_t)0;
    h->ack_sent_time = (uint64_t)0;
    h->ack_sent = false;
    h->ack_sent_try_count = 0x00;
    h->udp_data.r_puint8_t = NULL;
    h->udp_data.r_size_t = (size_t)0;
    h->last_trycount = (uint8_t)0;
}

static inline status_t setup_cow_session(const char *label, cow_c_session_t *single_session, worker_type_t wot, uint8_t index, uint8_t session_index) {
//----------------------------------------------------------------------
    initialize_node_metrics(label, &single_session->metrics);
//----------------------------------------------------------------------
    setup_control_packet(label, session_index, &single_session->hello1);
    setup_control_packet(label, session_index, &single_session->hello2);
    setup_control_packet(label, session_index, &single_session->hello3);
    setup_control_packet(label, session_index, &single_session->hello4);
//----------------------------------------------------------------------
    setup_control_packet(label, session_index, &single_session->heartbeat.heartbeat);
    setup_control_packet_ack(&single_session->heartbeat.heartbeat_ack);
    single_session->heartbeat.heartbeat_interval = (double)0;
    single_session->heartbeat.last_send_heartbeat_interval = (double)0;
    single_session->heartbeat.heartbeat_cnt = 0x00;
    generate_si_id(label, session_index, &single_session->heartbeat.heartbeat_sender_timer_id.id);
    single_session->heartbeat.heartbeat_sender_timer_id.event = NULL;
    single_session->heartbeat.heartbeat_sender_timer_id.delay_us = 0.0;
    #if defined(ACCRCY_TEST)
    generate_si_id(label, session_index, &single_session->heartbeat.heartbeat_openner_timer_id.id);
    single_session->heartbeat.heartbeat_openner_timer_id.event = NULL;
    single_session->heartbeat.heartbeat_openner_timer_id.delay_us = 0.0;
    #endif
//----------------------------------------------------------------------
    setup_oricle_double(&single_session->retry, (double)0);
    setup_oricle_double(&single_session->rtt, (double)0);
    setup_oricle_long_double(&single_session->avgtt, (long double)0);
    setup_oricle_double(&single_session->healthy, (double)100);
    orilink_identity_t *identity = &single_session->identity;
    orilink_security_t *security = &single_session->security;
    identity->id_connection = 0xffffffffffffffff;
    memset(&identity->remote_addr, 0, sizeof(struct sockaddr_in6));
    identity->remote_wot = UNKNOWN;
    identity->remote_index = 0xFF;
    identity->remote_session_index = 0xFF;
    identity->remote_id = 0xffffffffffffffff;
    identity->local_wot = wot;
    identity->local_index = index;
    identity->local_session_index = session_index;
    if (generate_uint64_t_id(label, &identity->local_id) != SUCCESS) return FAILURE;
    single_session->kem_privatekey = (uint8_t *)calloc(1, KEM_PRIVATEKEY_BYTES);
    security->kem_publickey = (uint8_t *)calloc(1, KEM_PUBLICKEY_BYTES);
    security->kem_ciphertext = (uint8_t *)calloc(1, KEM_CIPHERTEXT_BYTES);
    security->kem_sharedsecret = (uint8_t *)calloc(1, KEM_SHAREDSECRET_BYTES);
    security->aes_key = (uint8_t *)calloc(1, HASHES_BYTES);
    security->mac_key = (uint8_t *)calloc(1, HASHES_BYTES);
    security->local_nonce = (uint8_t *)calloc(1, AES_NONCE_BYTES);
    security->remote_nonce = (uint8_t *)calloc(1, AES_NONCE_BYTES);
    security->local_ctr = (uint32_t)0;
    security->remote_ctr = (uint32_t)0;
    if (KEM_GENERATE_KEYPAIR(security->kem_publickey, single_session->kem_privatekey) != 0) {
        LOG_ERROR("%sFailed to KEM_GENERATE_KEYPAIR.", label);
        return FAILURE;
    }
    single_session->orilink_raw_protocol_pool.head = NULL;
    return SUCCESS;
}

static inline void cleanup_cow_session(worker_context_t *ctx, cow_c_session_t *single_session) {
//----------------------------------------------------------------------
    cleanup_control_packet(ctx, &single_session->hello1, true, CDT_FREE);
    cleanup_control_packet(ctx, &single_session->hello2, true, CDT_FREE);
    cleanup_control_packet(ctx, &single_session->hello3, true, CDT_FREE);
    cleanup_control_packet(ctx, &single_session->hello4, true, CDT_FREE);
//----------------------------------------------------------------------
    cleanup_control_packet(ctx, &single_session->heartbeat.heartbeat, true, CDT_FREE);
    cleanup_control_packet_ack(&single_session->heartbeat.heartbeat_ack, true, CDT_FREE);
    single_session->heartbeat.heartbeat_interval = (double)0;
    single_session->heartbeat.last_send_heartbeat_interval = (double)0;
    single_session->heartbeat.heartbeat_cnt = 0x00;
    if (single_session->heartbeat.heartbeat_sender_timer_id.event) {
        oritw_remove_event(ctx->label, &ctx->async, &ctx->timer, single_session->heartbeat.heartbeat_sender_timer_id.event);
        single_session->heartbeat.heartbeat_sender_timer_id.event = NULL;
        single_session->heartbeat.heartbeat_sender_timer_id.id = 0ULL;
        single_session->heartbeat.heartbeat_sender_timer_id.delay_us = 0.0;
    }
    #if defined(ACCRCY_TEST)
    if (single_session->heartbeat.heartbeat_openner_timer_id.event) {
        oritw_remove_event(ctx->label, &ctx->async, &ctx->timer, single_session->heartbeat.heartbeat_openner_timer_id.event);
        single_session->heartbeat.heartbeat_openner_timer_id.event = NULL;
        single_session->heartbeat.heartbeat_openner_timer_id.id = 0ULL;
        single_session->heartbeat.heartbeat_openner_timer_id.delay_us = 0.0;
    }
    #endif
//----------------------------------------------------------------------
    cleanup_oricle_double(&single_session->retry);
    cleanup_oricle_double(&single_session->rtt);
    cleanup_oricle_long_double(&single_session->avgtt);
    cleanup_oricle_double(&single_session->healthy);
    orilink_identity_t *identity = &single_session->identity;
    orilink_security_t *security = &single_session->security;
    identity->id_connection = 0xffffffffffffffff;
    memset(&identity->remote_addr, 0, sizeof(struct sockaddr_in6));
    identity->remote_wot = UNKNOWN;
    identity->remote_index = 0xFF;
    identity->remote_session_index = 0xFF;
    identity->remote_id = 0xffffffffffffffff;
    identity->local_wot = UNKNOWN;
    identity->local_index = 0xFF;
    identity->local_session_index = 0xFF;
    identity->local_id = 0xffffffffffffffff;
    memset(single_session->kem_privatekey, 0, KEM_PRIVATEKEY_BYTES);
    memset(security->kem_publickey, 0, KEM_PUBLICKEY_BYTES);
    memset(security->kem_ciphertext, 0, KEM_CIPHERTEXT_BYTES);
    memset(security->kem_sharedsecret, 0, KEM_SHAREDSECRET_BYTES);
    memset(security->aes_key, 0, HASHES_BYTES);
    memset(security->mac_key, 0, HASHES_BYTES);
    memset(security->local_nonce, 0, AES_NONCE_BYTES);
    security->local_ctr = (uint32_t)0;
    memset(security->remote_nonce, 0, AES_NONCE_BYTES);
    security->remote_ctr = (uint32_t)0;
    free(single_session->kem_privatekey);
    free(security->kem_publickey);
    free(security->kem_ciphertext);
    free(security->kem_sharedsecret);
    free(security->aes_key);
    free(security->mac_key);
    free(security->local_nonce);
    free(security->remote_nonce);
//----------------------------------------------------------------------
    orilink_raw_protocol_free(&single_session->orilink_raw_protocol_pool.head);
//----------------------------------------------------------------------
}

static inline status_t setup_sio_session(const char *label, sio_c_session_t *single_session, worker_type_t wot, uint8_t index, uint8_t session_index) {
//----------------------------------------------------------------------
    initialize_node_metrics(label, &single_session->metrics);
//----------------------------------------------------------------------
    setup_control_packet_ack(&single_session->hello1_ack);
    setup_control_packet_ack(&single_session->hello2_ack);
    setup_control_packet_ack(&single_session->hello3_ack);
    setup_control_packet_ack(&single_session->hello4_ack);
//----------------------------------------------------------------------
    setup_control_packet(label, session_index, &single_session->heartbeat.heartbeat);
    setup_control_packet_ack(&single_session->heartbeat.heartbeat_ack);
    single_session->heartbeat.heartbeat_interval = (double)0;
    single_session->heartbeat.last_send_heartbeat_interval = (double)0;
    single_session->heartbeat.heartbeat_cnt = 0x00;
    generate_si_id(label, session_index, &single_session->heartbeat.heartbeat_sender_timer_id.id);
    single_session->heartbeat.heartbeat_sender_timer_id.event = NULL;
    single_session->heartbeat.heartbeat_sender_timer_id.delay_us = 0.0;
    #if defined(ACCRCY_TEST)
    generate_si_id(label, session_index, &single_session->heartbeat.heartbeat_openner_timer_id.id);
    single_session->heartbeat.heartbeat_openner_timer_id.event = NULL;
    single_session->heartbeat.heartbeat_openner_timer_id.delay_us = 0.0;
    #endif
//----------------------------------------------------------------------
    setup_oricle_double(&single_session->retry, (double)0);
    setup_oricle_double(&single_session->rtt, (double)0);
    setup_oricle_double(&single_session->healthy, (double)100);
    orilink_identity_t *identity = &single_session->identity;
    orilink_security_t *security = &single_session->security;
    identity->id_connection = 0xffffffffffffffff;
    memset(&identity->remote_addr, 0, sizeof(struct sockaddr_in6));
    identity->remote_wot = UNKNOWN;
    identity->remote_index = 0xFF;
    identity->remote_session_index = 0xFF;
    identity->remote_id = 0xffffffffffffffff;
    identity->local_wot = wot;
    identity->local_index = index;
    identity->local_session_index = session_index;
    if (generate_uint64_t_id(label, &identity->local_id) != SUCCESS) return FAILURE;
    security->kem_publickey = (uint8_t *)calloc(1, KEM_PUBLICKEY_BYTES);
    security->kem_ciphertext = (uint8_t *)calloc(1, KEM_CIPHERTEXT_BYTES);
    security->kem_sharedsecret = (uint8_t *)calloc(1, KEM_SHAREDSECRET_BYTES);
    security->aes_key = (uint8_t *)calloc(1, HASHES_BYTES);
    security->mac_key = (uint8_t *)calloc(1, HASHES_BYTES);
    security->local_nonce = (uint8_t *)calloc(1, AES_NONCE_BYTES);
    security->remote_nonce = (uint8_t *)calloc(1, AES_NONCE_BYTES);
    security->local_ctr = (uint32_t)0;
    security->remote_ctr = (uint32_t)0;
    single_session->orilink_raw_protocol_pool.head = NULL;
    return SUCCESS;
}

static inline void cleanup_sio_session(worker_context_t *ctx, sio_c_session_t *single_session) {
//----------------------------------------------------------------------
    cleanup_control_packet_ack(&single_session->hello1_ack, true, CDT_FREE);
    cleanup_control_packet_ack(&single_session->hello2_ack, true, CDT_FREE);
    cleanup_control_packet_ack(&single_session->hello3_ack, true, CDT_FREE);
    cleanup_control_packet_ack(&single_session->hello4_ack, true, CDT_FREE);
//----------------------------------------------------------------------
    cleanup_control_packet(ctx, &single_session->heartbeat.heartbeat, true, CDT_FREE);
    cleanup_control_packet_ack(&single_session->heartbeat.heartbeat_ack, true, CDT_FREE);
    single_session->heartbeat.heartbeat_interval = (double)0;
    single_session->heartbeat.last_send_heartbeat_interval = (double)0;
    single_session->heartbeat.heartbeat_cnt = 0x00;
    if (single_session->heartbeat.heartbeat_sender_timer_id.event) {
        oritw_remove_event(ctx->label, &ctx->async, &ctx->timer, single_session->heartbeat.heartbeat_sender_timer_id.event);
        single_session->heartbeat.heartbeat_sender_timer_id.event = NULL;
        single_session->heartbeat.heartbeat_sender_timer_id.id = 0ULL;
        single_session->heartbeat.heartbeat_sender_timer_id.delay_us = 0.0;
    }
    #if defined(ACCRCY_TEST)
    if (single_session->heartbeat.heartbeat_openner_timer_id.event) {
        oritw_remove_event(ctx->label, &ctx->async, &ctx->timer, single_session->heartbeat.heartbeat_openner_timer_id.event);
        single_session->heartbeat.heartbeat_openner_timer_id.event = NULL;
        single_session->heartbeat.heartbeat_openner_timer_id.id = 0ULL;
        single_session->heartbeat.heartbeat_openner_timer_id.delay_us = 0.0;
    }
    #endif
//----------------------------------------------------------------------
    cleanup_oricle_double(&single_session->retry);
    cleanup_oricle_double(&single_session->rtt);
    cleanup_oricle_double(&single_session->healthy);
    orilink_identity_t *identity = &single_session->identity;
    orilink_security_t *security = &single_session->security;
    identity->id_connection = 0xffffffffffffffff;
    memset(&identity->remote_addr, 0, sizeof(struct sockaddr_in6));
    identity->remote_wot = UNKNOWN;
    identity->remote_index = 0xFF;
    identity->remote_session_index = 0xFF;
    identity->remote_id = 0xffffffffffffffff;
    identity->local_wot = UNKNOWN;
    identity->local_index = 0xFF;
    identity->local_session_index = 0xFF;
    identity->local_id = 0xffffffffffffffff;
    memset(security->kem_publickey, 0, KEM_PUBLICKEY_BYTES);
    memset(security->kem_ciphertext, 0, KEM_CIPHERTEXT_BYTES);
    memset(security->kem_sharedsecret, 0, KEM_SHAREDSECRET_BYTES);
    memset(security->aes_key, 0, HASHES_BYTES);
    memset(security->mac_key, 0, HASHES_BYTES);
    memset(security->local_nonce, 0, AES_NONCE_BYTES);
    security->local_ctr = (uint32_t)0;
    memset(security->remote_nonce, 0, AES_NONCE_BYTES);
    security->remote_ctr = (uint32_t)0;
    free(security->kem_publickey);
    free(security->kem_ciphertext);
    free(security->kem_sharedsecret);
    free(security->aes_key);
    free(security->mac_key);
    free(security->local_nonce);
    free(security->remote_nonce);
//----------------------------------------------------------------------
    orilink_raw_protocol_free(&single_session->orilink_raw_protocol_pool.head);
//----------------------------------------------------------------------
}

#endif
