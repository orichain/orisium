#include "ipc.h"
#include "types.h"
#include "workers/worker_ipc.h"
#include "workers/worker_timer.h"
#include "workers/workers.h"

void run_dbw_worker(worker_type_t *wot, uint8_t *index, double *initial_delay_ms, int *master_uds_fd) {
    worker_context_t x_ctx;
    worker_context_t *worker_ctx = &x_ctx;
    if (setup_worker(worker_ctx, "DBW", wot, index, master_uds_fd) != SUCCESS) goto exit;
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
                        handle_workers_ipc_event(worker_ctx, NULL, initial_delay_ms);
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
                handle_worker_timer_event(worker_ctx, NULL, &current_fd, &current_events);
                continue;
            }
        }
    }

exit:
    cleanup_worker(worker_ctx);
}
