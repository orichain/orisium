#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include "log.h"
#include "async.h"
#include "types.h"
#include "constants.h"
#include "workers/workers.h"
#include "workers/ipc/handlers.h"
#include "workers/ipc/master_ipc_cmds.h"

void cleanup_logic_worker(worker_context_t *worker_ctx) {
	cleanup_worker(worker_ctx);
}

status_t setup_logic_worker(worker_context_t *worker_ctx, worker_type_t *wot, uint8_t *index, int *master_uds_fd) {
    if (setup_worker(worker_ctx, "Logic", wot, index, master_uds_fd) != SUCCESS) return FAILURE;
    return SUCCESS;
}

void run_logic_worker(worker_type_t *wot, uint8_t *index, double *initial_delay_ms, int *master_uds_fd) {
    worker_context_t x_ctx;
    worker_context_t *worker_ctx = &x_ctx;
    if (setup_logic_worker(worker_ctx, wot, index, master_uds_fd) != SUCCESS) goto exit;
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
                double new_heartbeat_interval_double = WORKER_HEARTBEAT_INTERVAL * (1.0 + jitter_amount);
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
                    handle_workers_ipc_event(worker_ctx, NULL, initial_delay_ms);
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
    cleanup_logic_worker(worker_ctx);
}
