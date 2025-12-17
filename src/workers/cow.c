#include <stdint.h>
#include <stddef.h>

#include "async.h"
#include "types.h"
#include "constants.h"
#include "workers/workers.h"
#include "workers/worker_timer.h"
#include "workers/worker_ipc.h"
#include "oritlsf.h"
#include "ipc.h"
#include "stdbool.h"

void run_cow_worker(worker_type_t *wot, uint8_t *index, double *initial_delay_ms, int *master_uds_fd) {
    worker_context_t x_ctx;
    worker_context_t *worker_ctx = &x_ctx;
    cow_c_session_t *sessions[MAX_CONNECTION_PER_COW_WORKER];
    if (setup_worker(worker_ctx, "COW", wot, index, master_uds_fd) != SUCCESS) goto exit2;
    for (uint8_t i = 0; i < MAX_CONNECTION_PER_COW_WORKER; ++i) {
        sessions[i] = (cow_c_session_t *)oritlsf_calloc(__FILE__, __LINE__, 
            &worker_ctx->oritlsf_pool,
            1,
            sizeof(cow_c_session_t)
        );
        if (setup_cow_session(worker_ctx, sessions[i], *wot, *index, i) != SUCCESS) {
            goto exit1;
        }
    }
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
            if (current_fd == *worker_ctx->master_uds_fd) {
                if (async_event_is_HUP(current_events) ||
                    async_event_is_ERR(current_events) ||
                    async_event_is_RDHUP(current_events))
                {
                    handle_workers_ipc_closed_event(worker_ctx);
                    continue;
                } else {
                    if (async_event_is_IN(current_events)) {
                        handle_workers_ipc_event(worker_ctx, (void **)sessions, initial_delay_ms);
                    }
                    if (async_event_is_OUT(current_events)) {
                        et_result_t wetr = write_ipc_protocol_message(
                            &worker_ctx->oritlsf_pool, 
                            &current_fd,
                            worker_ctx->buffer, 
                            0,
                            NULL,
                            true
                        );
                        if (!wetr.failure) {
                            if (!wetr.partial) {
                                oritlsf_free(&worker_ctx->oritlsf_pool, (void **)&worker_ctx->buffer->buffer_out);
                                worker_ctx->buffer->out_size_tb = 0;
                                worker_ctx->buffer->out_size_c = 0;
                            }
                        }
                    }
                    continue;
                }
            } else {
                handle_worker_timer_event(worker_ctx, (void **)sessions, &current_fd, &current_events);
                continue;
            }
        }
    }

exit1:   
    for (uint8_t i = 0; i < MAX_CONNECTION_PER_COW_WORKER; ++i) {
        cleanup_cow_session(worker_ctx, sessions[i]);
        oritlsf_free(&worker_ctx->oritlsf_pool, (void **)&(sessions[i]));
    }
exit2:
    cleanup_worker(worker_ctx);
}
