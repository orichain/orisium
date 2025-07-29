#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <time.h>

#include "log.h"
#include "ipc/protocol.h"
#include "async.h"
#include "types.h"
#include "constants.h"
#include "workers/master_ipc_cmds.h"
#include "workers/worker.h"

void cleanup_logic_worker(logic_context_t *logic_ctx) {
	cleanup_worker(&logic_ctx->worker);
}

status_t setup_logic_worker(logic_context_t *logic_ctx, worker_type_t wot, int worker_idx, long initial_delay_ms, int master_uds_fd) {
    if (setup_worker(&logic_ctx->worker, "Logic", wot, worker_idx, initial_delay_ms, master_uds_fd) != SUCCESS) return FAILURE;
    return SUCCESS;
}

void run_logic_worker(worker_type_t wot, int worker_idx, long initial_delay_ms, int master_uds_fd) {
    logic_context_t logic_ctx;
    if (setup_logic_worker(&logic_ctx, wot, worker_idx, initial_delay_ms, master_uds_fd) != SUCCESS) goto exit;	    
    while (!logic_ctx.worker.shutdown_requested) {
        int_status_t snfds = async_wait(logic_ctx.worker.label, &logic_ctx.worker.async);
		if (snfds.status != SUCCESS) continue;
        for (int n = 0; n < snfds.r_int; ++n) {
			if (logic_ctx.worker.shutdown_requested) {
				break;
			}
			int_status_t fd_status = async_getfd(logic_ctx.worker.label, &logic_ctx.worker.async, n);
			if (fd_status.status != SUCCESS) continue;
			int current_fd = fd_status.r_int;
			uint32_t_status_t events_status = async_getevents(logic_ctx.worker.label, &logic_ctx.worker.async, n);
			if (events_status.status != SUCCESS) continue;
			uint32_t current_events = events_status.r_uint32_t;
			if (current_fd == logic_ctx.worker.heartbeat_timer_fd) {
				uint64_t u;
				read(logic_ctx.worker.heartbeat_timer_fd, &u, sizeof(u)); //Jangan lupa read event timer
//----------------------------------------------------------------------
// Heartbeat dengan jitter
//----------------------------------------------------------------------
				double jitter_amount = ((double)random() / RAND_MAX_DOUBLE * HEARTBEAT_JITTER_PERCENTAGE * 2) - HEARTBEAT_JITTER_PERCENTAGE;
                double new_heartbeat_interval_double = WORKER_HEARTBEATSEC_NODE_HEARTBEATSEC_TIMEOUT * (1.0 + jitter_amount);
                if (new_heartbeat_interval_double < 0.1) {
                    new_heartbeat_interval_double = 0.1;
                }
                if (async_set_timerfd_time(logic_ctx.worker.label, &logic_ctx.worker.heartbeat_timer_fd,
					(time_t)new_heartbeat_interval_double,
                    (long)((new_heartbeat_interval_double - (time_t)new_heartbeat_interval_double) * 1e9),
                    (time_t)new_heartbeat_interval_double,
                    (long)((new_heartbeat_interval_double - (time_t)new_heartbeat_interval_double) * 1e9)) != SUCCESS)
                {
                    logic_ctx.worker.shutdown_requested = 1;
					LOG_INFO("%sGagal set timer. Initiating graceful shutdown...", logic_ctx.worker.label);
					continue;
                }
                if (worker_master_heartbeat(&logic_ctx.worker, new_heartbeat_interval_double) != SUCCESS) {
                    continue;
                } else {
                    continue;
                }
//----------------------------------------------------------------------
			} else if (current_fd == master_uds_fd) {
                if (async_event_is_EPOLLHUP(current_events) ||
                    async_event_is_EPOLLERR(current_events) ||
                    async_event_is_EPOLLRDHUP(current_events))
                {
                    logic_ctx.worker.shutdown_requested = 1;
                    LOG_INFO("%sMaster disconnected. Initiating graceful shutdown...", logic_ctx.worker.label);
                    continue;
                }
				ipc_raw_protocol_t_status_t ircvdi = receive_ipc_raw_protocol_message(logic_ctx.worker.label, &master_uds_fd);
				if (ircvdi.status != SUCCESS) {
					LOG_ERROR("%sError receiving or deserializing IPC message from Master: %d", logic_ctx.worker.label, ircvdi.status);
					continue;
				}
				if (ircvdi.r_ipc_raw_protocol_t->type == IPC_MASTER_WORKER_SHUTDOWN) {
					LOG_INFO("%sSIGINT received. Initiating graceful shutdown...", logic_ctx.worker.label);
                    CLOSE_IPC_RAW_PROTOCOL(&ircvdi.r_ipc_raw_protocol_t);
					logic_ctx.worker.shutdown_requested = 1;
					continue;
				} else {
                    LOG_ERROR("%sUnknown protocol type %d from Master. Ignoring.", logic_ctx.worker.label, ircvdi.r_ipc_raw_protocol_t->type);
                    CLOSE_IPC_RAW_PROTOCOL(&ircvdi.r_ipc_raw_protocol_t);
                    continue;
                }
            } else {
                LOG_ERROR("%sUnknown FD event %d.", logic_ctx.worker.label, current_fd);
            }
        }
    }

//======================================================================
// Logic Cleanup
//======================================================================    
exit:    
	cleanup_logic_worker(&logic_ctx);
}
