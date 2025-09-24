#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>

#include "log.h"
#include "async.h"
#include "types.h"
#include "constants.h"
#include "workers/workers.h"
#include "workers/ipc/handlers.h"
#include "workers/ipc/master_ipc_cmds.h"
#include "orilink/protocol.h"
#include "stdbool.h"
#include "utilities.h"
#include "pqc.h"
#include "kalman.h"

static inline void cleanup_hello_ack(const char *label, async_type_t *async, hello_ack_t *h) {
    h->rcvd = false;
    h->rcvd_time = (uint64_t)0;
    h->ack_sent_time = (uint64_t)0;
    h->ack_sent = false;
    h->interval_ack_timer_fd = (double)1;
    h->ack_sent_try_count = 0x00;
    h->len = (uint16_t)0;
    if (h->data) {
        free(h->data);
        h->data = NULL;
    }
    async_delete_event(label, async, &h->ack_timer_fd);
    CLOSE_FD(&h->ack_timer_fd);
}

static inline void setup_hello_ack(hello_ack_t *h) {
    h->rcvd = false;
    h->rcvd_time = (uint64_t)0;
    h->ack_sent_time = (uint64_t)0;
    h->ack_sent = false;
    h->interval_ack_timer_fd = (double)1;
    h->ack_sent_try_count = 0x00;
    h->len = (uint16_t)0;
    h->data = NULL;
    h->ack_timer_fd = -1;
}

static inline status_t setup_sio_session(const char *label, sio_c_session_t *single_session, worker_type_t wot, uint8_t index, uint8_t session_index) {
    setup_hello_ack(&single_session->hello1_ack);
    setup_hello_ack(&single_session->hello2_ack);
    setup_hello_ack(&single_session->hello3_ack);
    setup_hello_ack(&single_session->hello4_ack);
    setup_oricle_double(&single_session->retry, (double)1);
    setup_oricle_double(&single_session->rtt, (double)0);
    orilink_identity_t *identity = &single_session->identity;
    orilink_security_t *security = &single_session->security;
    memset(&identity->remote_addr, 0, sizeof(struct sockaddr_in6));
    identity->remote_wot = UNKNOWN;
    identity->remote_index = 0xFF;
    identity->remote_session_index = 0xFF;
    identity->remote_id = 0xFFFFFFFF;
    identity->local_wot = wot;
    identity->local_index = index;
    identity->local_session_index = session_index;
    if (generate_connection_id(label, &identity->local_id) != SUCCESS) return FAILURE;
    security->kem_publickey = (uint8_t *)calloc(1, KEM_PUBLICKEY_BYTES);
    security->kem_ciphertext = (uint8_t *)calloc(1, KEM_CIPHERTEXT_BYTES);
    security->kem_sharedsecret = (uint8_t *)calloc(1, KEM_SHAREDSECRET_BYTES);
    security->aes_key = (uint8_t *)calloc(1, HASHES_BYTES);
    security->mac_key = (uint8_t *)calloc(1, HASHES_BYTES);
    security->local_nonce = (uint8_t *)calloc(1, AES_NONCE_BYTES);
    security->remote_nonce = (uint8_t *)calloc(1, AES_NONCE_BYTES);
    security->local_ctr = (uint32_t)0;
    security->remote_ctr = (uint32_t)0;
    return SUCCESS;
}

static inline void cleanup_sio_session(const char *label, async_type_t *sio_async, sio_c_session_t *single_session) {
    cleanup_hello_ack(label, sio_async, &single_session->hello1_ack);
    cleanup_hello_ack(label, sio_async, &single_session->hello2_ack);
    cleanup_hello_ack(label, sio_async, &single_session->hello3_ack);
    cleanup_hello_ack(label, sio_async, &single_session->hello4_ack);
    cleanup_oricle_double(&single_session->retry);
    cleanup_oricle_double(&single_session->rtt);
    orilink_identity_t *identity = &single_session->identity;
    orilink_security_t *security = &single_session->security;
    memset(&identity->remote_addr, 0, sizeof(struct sockaddr_in6));
    identity->remote_wot = UNKNOWN;
    identity->remote_index = 0xFF;
    identity->remote_session_index = 0xFF;
    identity->remote_id = 0xFFFFFFFF;
    identity->local_wot = UNKNOWN;
    identity->local_index = 0xFF;
    identity->local_session_index = 0xFF;
    identity->local_id = 0xFFFFFFFF;
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
}

void cleanup_sio_worker(worker_context_t *worker_ctx, sio_c_session_t *sessions) {
    for (uint8_t i = 0; i < MAX_CONNECTION_PER_SIO_WORKER; ++i) {
        sio_c_session_t *single_session;
        single_session = &sessions[i];
        cleanup_sio_session(worker_ctx->label, &worker_ctx->async, single_session);
    }
	cleanup_worker(worker_ctx);
}

status_t setup_sio_worker(worker_context_t *worker_ctx, sio_c_session_t *sessions, worker_type_t *wot, uint8_t *index, int *master_uds_fd) {
    if (setup_worker(worker_ctx, "SIO", wot, index, master_uds_fd) != SUCCESS) return FAILURE;
    for (uint8_t i = 0; i < MAX_CONNECTION_PER_SIO_WORKER; ++i) {
        sio_c_session_t *single_session;
        single_session = &sessions[i];
        if (setup_sio_session(worker_ctx->label, single_session, *wot, *index, i) != SUCCESS) {
            return FAILURE;
        }
    }
    return SUCCESS;
}

void run_sio_worker(worker_type_t *wot, uint8_t *index, double *initial_delay_ms, int *master_uds_fd) {
    worker_context_t x_ctx;
    worker_context_t *worker_ctx = &x_ctx;
    sio_c_session_t sessions[MAX_CONNECTION_PER_SIO_WORKER];
    if (setup_sio_worker(worker_ctx, sessions, wot, index, master_uds_fd) != SUCCESS) goto exit;
    while (!worker_ctx->shutdown_requested) {
        int_status_t snfds = async_wait(worker_ctx->label, &worker_ctx->async);
		if (snfds.status != SUCCESS) {
            if (snfds.status == FAILURE_EBADF) {
                worker_ctx->shutdown_requested = 1;
            }
            continue;
        }
        for (int n = 0; n < snfds.r_int; ++n) {
            if (worker_ctx->shutdown_requested) {
				break;
			}
			int_status_t fd_status = async_getfd(worker_ctx->label, &worker_ctx->async, n);
			if (fd_status.status != SUCCESS) continue;
			int current_fd = fd_status.r_int;
			uint32_t_status_t events_status = async_getevents(worker_ctx->label, &worker_ctx->async, n);
			if (events_status.status != SUCCESS) continue;
			uint32_t current_events = events_status.r_uint32_t;
            if (current_fd == worker_ctx->heartbeat_timer_fd) {
				uint64_t u;
				read(worker_ctx->heartbeat_timer_fd, &u, sizeof(u)); //Jangan lupa read event timer
//----------------------------------------------------------------------
// Heartbeat dengan jitter
//----------------------------------------------------------------------
				double jitter_amount = ((double)random() / RAND_MAX_DOUBLE * HEARTBEAT_JITTER_PERCENTAGE * 2) - HEARTBEAT_JITTER_PERCENTAGE;
                double new_heartbeat_interval_double = WORKER_HEARTBEATSEC_NODE_HEARTBEATSEC_TIMEOUT * (1.0 + jitter_amount);
                if (new_heartbeat_interval_double < 0.1) {
                    new_heartbeat_interval_double = 0.1;
                }
                if (async_set_timerfd_time(worker_ctx->label, &worker_ctx->heartbeat_timer_fd,
					(time_t)new_heartbeat_interval_double,
                    (long)((new_heartbeat_interval_double - (time_t)new_heartbeat_interval_double) * 1e9),
                    (time_t)new_heartbeat_interval_double,
                    (long)((new_heartbeat_interval_double - (time_t)new_heartbeat_interval_double) * 1e9)) != SUCCESS)
                {
                    worker_ctx->shutdown_requested = 1;
					LOG_INFO("%sGagal set timer. Initiating graceful shutdown...", worker_ctx->label);
					continue;
                }
                if (worker_master_heartbeat(worker_ctx, new_heartbeat_interval_double) != SUCCESS) {
                    continue;
                } else {
                    continue;
                }
//----------------------------------------------------------------------
			} else if (current_fd == *worker_ctx->master_uds_fd) {
                if (async_event_is_EPOLLHUP(current_events) ||
                    async_event_is_EPOLLERR(current_events) ||
                    async_event_is_EPOLLRDHUP(current_events))
                {
                    handle_workers_ipc_closed_event(worker_ctx);
                    continue;
                } else {
                    handle_workers_ipc_event(worker_ctx, sessions, initial_delay_ms);
                    continue;
                }
            } else {
//======================================================================
// Event yang belum ditangkap
//======================================================================                 
                LOG_ERROR("%sUnknown FD event %d.", worker_ctx->label, current_fd);
//======================================================================
            }
        }
    }

exit:    
    cleanup_sio_worker(worker_ctx, sessions);
}
