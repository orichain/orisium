#include <stdbool.h>
#include <unistd.h>
#include <stdint.h>
#include <netinet/in.h>
#include <string.h>
#include <bits/types/sig_atomic_t.h>

#include "log.h"
#include "constants.h"
#include "async.h"
#include "utilities.h"
#include "types.h"
#include "master/socket_listenner.h"
#include "master/ipc.h"
#include "master/workers.h"
#include "master/process.h"
#include "master/worker_metrics.h"
#include "master/worker_ipc_cmds.h"
#include "master/worker_selector.h"
#include "node.h"

status_t setup_master(master_context *master_ctx, uint16_t *listen_port) {
    const char *label = "[Master]: ";
    for (int i = 0; i < MAX_MASTER_SIO_SESSIONS; ++i) {
        master_ctx->sio_c_session[i].sio_index = -1;
        master_ctx->sio_c_session[i].in_use = false;
        memset(&master_ctx->sio_c_session[i].client_addr, 0, sizeof(struct sockaddr_in6));
    }
    for (int i = 0; i < MAX_MASTER_COW_SESSIONS; ++i) {
        master_ctx->cow_c_session[i].cow_index = -1;
        master_ctx->cow_c_session[i].in_use = false;
        memset(&master_ctx->cow_c_session[i].server_addr, 0, sizeof(struct sockaddr_in6));
    }
    master_ctx->last_sio_rr_idx = 0;
    master_ctx->last_cow_rr_idx = 0;
	master_ctx->master_pid = -1;
	master_ctx->shutdown_event_fd = -1;
    master_ctx->listen_sock = -1;
    master_ctx->master_timer_fd = -1;
    master_ctx->master_async.async_fd = -1;
    master_ctx->master_pid = getpid();
//======================================================================
// Master setup socket listenner & timer heartbeat
//======================================================================
	if (async_create(label, &master_ctx->master_async) != SUCCESS) {
		return FAILURE;
	}
	if (async_create_eventfd_nonblock_close_after_exec(label, &master_ctx->shutdown_event_fd) != SUCCESS) {
		return FAILURE;
	}
	if (async_create_incoming_event(label, &master_ctx->master_async, &master_ctx->shutdown_event_fd) != SUCCESS) {
		return FAILURE;
	}
//======================================================================	
    if (setup_socket_listenner(label, master_ctx, listen_port) != SUCCESS) {
		return FAILURE; 
	}	
    if (async_create_incoming_event(label, &master_ctx->master_async, &master_ctx->listen_sock) != SUCCESS) {
		return FAILURE;
	}
    return SUCCESS;
}

void run_master_process(master_context *master_ctx, uint16_t *listen_port, bootstrap_nodes_t *bootstrap_nodes) {
	const char *label = "[Master]: ";
	volatile sig_atomic_t master_shutdown_requested = 0;
    
    if (setup_workers(master_ctx) != SUCCESS) goto exit;
    if (sleep_s(1) != SUCCESS) goto exit;
    for (int ic = 0; ic < bootstrap_nodes->len; ic++) {
        int cow_worker_idx = select_best_worker(label, master_ctx, COW);
        if (cow_worker_idx == -1) {
            LOG_ERROR("%sFailed to select an COW worker for new task.", label);
            goto exit;
        }
        int slot_found = -1;
        for(int i = 0; i < MAX_MASTER_COW_SESSIONS; ++i) {
            if(!master_ctx->cow_c_session[i].in_use) {
                master_ctx->cow_c_session[i].cow_index = cow_worker_idx;
                master_ctx->cow_c_session[i].in_use = true;
                memcpy(&master_ctx->cow_c_session[i].server_addr, &bootstrap_nodes->addr[ic], sizeof(bootstrap_nodes->addr[ic]));
                slot_found = i;
                break;
            }
        }
        if (slot_found == -1) {
            LOG_ERROR("%sWARNING: No free session slots in master_ctx->cow_c_session.", label);
            goto exit;
        }
        if (cow_connect(master_ctx, &bootstrap_nodes->addr[ic], cow_worker_idx) != SUCCESS) goto exit;
    }
    LOG_INFO("%sPID %d UDP Server listening on port %d.", label, master_ctx->master_pid, *listen_port);
    while (!master_shutdown_requested) {
		int_status_t snfds = async_wait(label, &master_ctx->master_async);
		if (snfds.status != SUCCESS) continue;
		for (int n = 0; n < snfds.r_int; ++n) {		
			if (master_shutdown_requested) {
				break;
			}
			int_status_t fd_status = async_getfd(label, &master_ctx->master_async, n);
			if (fd_status.status != SUCCESS) continue;
			int current_fd = fd_status.r_int;
			uint32_t_status_t events_status = async_getevents(label, &master_ctx->master_async, n);
			if (events_status.status != SUCCESS) continue;
			uint32_t current_events = events_status.r_uint32_t;	
			if (current_fd == master_ctx->master_timer_fd) {
				uint64_t u;
				read(master_ctx->master_timer_fd, &u, sizeof(u)); //Jangan lupa read event timer
                if (async_set_timerfd_time(label, &master_ctx->master_timer_fd,
                    WORKER_HEARTBEATSEC_TIMEOUT,
                    0,
                    WORKER_HEARTBEATSEC_TIMEOUT,
                    0) != SUCCESS)
                {
                    LOG_INFO("%sGagal set timer. Initiating graceful shutdown...", label);
                    master_shutdown_requested = 1;
                    broadcast_shutdown(master_ctx);
                    continue;
                }
                if (check_workers_healthy(master_ctx) != SUCCESS) continue;
			} else if (current_fd == master_ctx->shutdown_event_fd) {
				uint64_t u;
				read(master_ctx->shutdown_event_fd, &u, sizeof(u));
				LOG_INFO("%sSIGINT received. Initiating graceful shutdown...", label);
				master_shutdown_requested = 1;
				broadcast_shutdown(master_ctx);
				continue;
			} else if (current_fd == master_ctx->listen_sock) {
				if (async_event_is_EPOLLIN(current_events)) {
					if (handle_listen_sock_event(label, master_ctx) != SUCCESS) {
						continue;
					}
				} else {
					CLOSE_FD(&current_fd);
				}
            } else {
				if (async_event_is_EPOLLHUP(current_events) ||
					async_event_is_EPOLLERR(current_events) ||
					async_event_is_EPOLLRDHUP(current_events))
				{
					worker_type_t_status_t worker_closed = handle_ipc_closed_event(label, master_ctx, &current_fd);
					if (worker_closed.status != SUCCESS) {
						continue;
					}
//======================================================================
// Cleanup and recreate worker
//======================================================================
					if (close_worker(label, master_ctx, worker_closed.r_worker_type_t, worker_closed.index) != SUCCESS) {
						continue;
					}
					if (create_socket_pair(label, master_ctx, worker_closed.r_worker_type_t, worker_closed.index) != SUCCESS) {
						continue;
					}
					if (setup_fork_worker(label, master_ctx, worker_closed.r_worker_type_t, worker_closed.index) != SUCCESS) {
						continue;
					}
//======================================================================
				} else {
					if (handle_ipc_event(label, master_ctx, &current_fd) != SUCCESS) {
						continue;
					}
				}
            }
        }
    }
//======================================================================
// Cleanup
// event shutdown tidak di close karena
// async_create_eventfd_nonblock_close_after_exec <= close after exec/read
//======================================================================
exit:
    workers_cleanup(master_ctx);
    CLOSE_FD(&master_ctx->listen_sock);
    async_delete_event(label, &master_ctx->master_async, &master_ctx->master_timer_fd);
    CLOSE_FD(&master_ctx->master_timer_fd);
    CLOSE_FD(&master_ctx->master_async.async_fd);
}
