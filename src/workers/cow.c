#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>

#include "pqc.h"
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

static inline void cleanup_hello(const char *label, async_type_t *async, hello_t *h) {
    h->sent = false;
    h->sent_time = (uint64_t)0;
    h->ack_rcvd_time = (uint64_t)0;
    h->ack_rcvd = false;
    h->interval_timer_fd = (double)1;
    h->sent_try_count = 0x00;
    h->len = (uint16_t)0;
    if (h->data) {
        free(h->data);
        h->data = NULL;
    }
    async_delete_event(label, async, &h->timer_fd);
    CLOSE_FD(&h->timer_fd);
}

static inline void setup_hello(hello_t *h) {
    h->sent = false;
    h->sent_time = (uint64_t)0;
    h->ack_rcvd_time = (uint64_t)0;
    h->ack_rcvd = false;
    h->interval_timer_fd = (double)1;
    h->sent_try_count = 0x00;
    h->len = (uint16_t)0;
    h->data = NULL;
    h->timer_fd = -1;
}

static inline status_t setup_cow_session(const char *label, cow_c_session_t *single_session, worker_type_t wot, uint8_t index, uint8_t session_index) {
    setup_hello(&single_session->hello1);
    setup_hello(&single_session->hello2);
    setup_hello(&single_session->hello3);
    setup_hello(&single_session->hello4);
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
    return SUCCESS;
}

static inline void cleanup_cow_session(const char *label, async_type_t *cow_async, cow_c_session_t *single_session) {
    cleanup_hello(label, cow_async, &single_session->hello1);
    cleanup_hello(label, cow_async, &single_session->hello2);
    cleanup_hello(label, cow_async, &single_session->hello3);
    cleanup_hello(label, cow_async, &single_session->hello4);
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
}

static inline void cleanup_cow_worker(worker_context_t *worker_ctx, cow_c_session_t *sessions) {
    for (uint8_t i = 0; i < MAX_CONNECTION_PER_COW_WORKER; ++i) {
        cow_c_session_t *single_session;
        single_session = &sessions[i];
        cleanup_cow_session(worker_ctx->label, &worker_ctx->async, single_session);
    }
	cleanup_worker(worker_ctx);
}

static inline status_t setup_cow_worker(worker_context_t *worker_ctx, cow_c_session_t *sessions, worker_type_t *wot, uint8_t *index, int *master_uds_fd) {
    if (setup_worker(worker_ctx, "COW", wot, index, master_uds_fd) != SUCCESS) return FAILURE;
    for (uint8_t i = 0; i < MAX_CONNECTION_PER_COW_WORKER; ++i) {
        cow_c_session_t *single_session;
        single_session = &sessions[i];
        if (setup_cow_session(worker_ctx->label, single_session, *wot, *index, i) != SUCCESS) {
            return FAILURE;
        }
    }
    return SUCCESS;
}

void run_cow_worker(worker_type_t *wot, uint8_t *index, double *initial_delay_ms, int *master_uds_fd) {
    worker_context_t x_ctx;
    worker_context_t *worker_ctx = &x_ctx;
    cow_c_session_t sessions[MAX_CONNECTION_PER_COW_WORKER];
    if (setup_cow_worker(worker_ctx, sessions, wot, index, master_uds_fd) != SUCCESS) goto exit;
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
            }
        }
    }

exit:    
    cleanup_cow_worker(worker_ctx, sessions);
}
