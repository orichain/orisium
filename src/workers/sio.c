#include <stdint.h>
#include <unistd.h>

#include "log.h"
#include "async.h"
#include "types.h"
#include "constants.h"
#include "workers/workers.h"
#include "workers/timers.h"
#include "workers/worker_ipc.h"
#include "utilities.h"

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
				double new_heartbeat_interval_double = worker_hb_interval_with_jitter();
                status_t uhst = update_timer_oneshot(worker_ctx->label, &worker_ctx->heartbeat_timer_fd, new_heartbeat_interval_double);
                if (uhst != SUCCESS) {
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
                status_t event_founded = handle_workers_timer_event(worker_ctx, sessions, &current_fd);
                if (event_founded == SUCCESS) continue;
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
