#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <bits/types/sig_atomic_t.h>

#include "log.h"
#include "constants.h"
#include "node.h"
#include "async.h"
#include "globals.h"
#include "utilities.h"
#include "types.h"
#include "master/socket_listenner.h"
#include "master/ipc.h"
#include "master/workers.h"
#include "master/process.h"
#include "ipc/protocol.h"
#include "ipc/shutdown.h"
#include "sessions/master_session.h"

status_t setup_master(master_context *master_ctx) {
	master_ctx->master_pid = -1;
	master_ctx->shutdown_event_fd = -1;
    master_ctx->listen_sock = -1;
    master_ctx->master_timer_fd = -1;
    master_ctx->master_async.async_fd = -1;
    master_ctx->master_pid = getpid();
    const char *label = "[Master]: ";
    LOG_INFO("%sPID %d TCP Server listening on port %d.", label, master_ctx->master_pid, node_config.listen_port);
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
	if (async_create_timerfd(label, &master_ctx->master_timer_fd, WORKER_HEARTBEATSEC_TIMEOUT) != SUCCESS) {
		return FAILURE;
	}
	if (async_create_incoming_event(label, &master_ctx->master_async, &master_ctx->master_timer_fd) != SUCCESS) {
		return FAILURE;
	}
    if (setup_socket_listenner(label, master_ctx) != SUCCESS) {
		return FAILURE; 
	}	
    if (async_create_incoming_event(label, &master_ctx->master_async, &master_ctx->listen_sock) != SUCCESS) {
		return FAILURE;
	}
//======================================================================
// Setup uds and socketpair for workers
//======================================================================
    for (int i = 0; i < MAX_SIO_WORKERS; ++i) { 
		master_ctx->master_uds_sio_fds[i] = 0; 
		master_ctx->worker_uds_sio_fds[i] = 0; 
	}
    for (int i = 0; i < MAX_LOGIC_WORKERS; ++i) { 
		master_ctx->master_uds_logic_fds[i] = 0; 
		master_ctx->worker_uds_logic_fds[i] = 0; 
	}
    for (int i = 0; i < MAX_COW_WORKERS; ++i) { 
		master_ctx->master_uds_cow_fds[i] = 0; 
		master_ctx->worker_uds_cow_fds[i] = 0; 
	}
    for (int i = 0; i < MAX_SIO_WORKERS; ++i) {
		if (create_socket_pair(label, master_ctx, SIO, i) != SUCCESS) return FAILURE;
    }
    for (int i = 0; i < MAX_LOGIC_WORKERS; ++i) {
		if (create_socket_pair(label, master_ctx, LOGIC, i) != SUCCESS) return FAILURE;
    }
    for (int i = 0; i < MAX_COW_WORKERS; ++i) {
		if (create_socket_pair(label, master_ctx, COW, i) != SUCCESS) return FAILURE;
    }
    return SUCCESS;
}

status_t setup_workers(master_context *master_ctx) {
	const char *label = "[Master]: ";
	for (int i = 0; i < MAX_SIO_WORKERS; ++i) {
		if (setup_fork_worker(label, master_ctx,	SIO, i) != SUCCESS) {
			return FAILURE;
		}
    }
    for (int i = 0; i < MAX_LOGIC_WORKERS; ++i) {
		if (setup_fork_worker(label, master_ctx,	LOGIC, i) != SUCCESS) {
			return FAILURE;
		}
    }
    for (int i = 0; i < MAX_COW_WORKERS; ++i) {
		if (setup_fork_worker(label, master_ctx,	COW, i) != SUCCESS) {
			return FAILURE;
		}
    }
    LOG_INFO("%sStarting main event loop. Waiting for clients and worker communications...", label);
    return SUCCESS;
}

static inline status_t broadcast_shutdown(master_context *master_ctx) {
	const char *label = "[Master]: ";
	int not_used_fd = -1;
	for (int i = 0; i < MAX_SIO_WORKERS; ++i) { 
		ipc_protocol_t_status_t cmd_result = ipc_prepare_cmd_shutdown(&not_used_fd);
		if (cmd_result.status != SUCCESS) {
			return FAILURE;
		}
		ssize_t_status_t send_result = send_ipc_protocol_message(&master_ctx->master_uds_sio_fds[i], cmd_result.r_ipc_protocol_t, &not_used_fd);
		if (send_result.status != SUCCESS) {
			LOG_INFO("%sFailed to sent shutdown to SIO %ld.", label, i);
		} else {
			LOG_INFO("%sSent shutdown to SIO %ld.", label, i);
		}
		CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t); 
	}
	for (int i = 0; i < MAX_LOGIC_WORKERS; ++i) {
		ipc_protocol_t_status_t cmd_result = ipc_prepare_cmd_shutdown(&not_used_fd);
		if (cmd_result.status != SUCCESS) {
			return FAILURE;
		}	
		ssize_t_status_t send_result = send_ipc_protocol_message(&master_ctx->master_uds_logic_fds[i], cmd_result.r_ipc_protocol_t, &not_used_fd);
		if (send_result.status != SUCCESS) {
			LOG_INFO("%sFailed to sent shutdown to Logic %ld.", label, i);
		} else {
			LOG_INFO("%sSent shutdown to Logic %ld.", label, i);
		}
		CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
	}
	for (int i = 0; i < MAX_COW_WORKERS; ++i) { 
		ipc_protocol_t_status_t cmd_result = ipc_prepare_cmd_shutdown(&not_used_fd);
		if (cmd_result.status != SUCCESS) {
			return FAILURE;
		}	
		ssize_t_status_t send_result = send_ipc_protocol_message(&master_ctx->master_uds_cow_fds[i], cmd_result.r_ipc_protocol_t, &not_used_fd);
		if (send_result.status != SUCCESS) {
			LOG_INFO("%sFailed to sent shutdown to COW %ld.", label, i);
		} else {
			LOG_INFO("%sSent shutdown to COW %ld.", label, i);
		}
		CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
	}
	return SUCCESS;
}

void run_master_process(master_context *master_ctx) {
	const char *label = "[Master]: ";
	volatile sig_atomic_t master_shutdown_requested = 0;
	master_sio_c_session_t master_sio_c_session[MAX_MASTER_CONCURRENT_SESSIONS];
	uint64_t client_num = 1ULL;
	//double_t avg_connection = 0.0;
	//double_t cnt_connection = 0.0;
	//double_t sio_worker = (double_t)MAX_SIO_WORKERS;
	
	for (int i = 0; i < MAX_MASTER_CONCURRENT_SESSIONS; ++i) {
        master_sio_c_session[i].in_use = false;
        memset(master_sio_c_session[i].ip, 0, IP_ADDRESS_LEN);
    }
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
//======================================================
// 1. Tutup worker yang tidak ada aktifitas > WORKER_HEARTBEATSEC_TIMEOUT detik
// 2. Jika yang ditutup adalah sio masukkan correlation id milik sio tersebut ke list diskonnected correlation id
// 3. Buat ulang worker dengan tipe dan index sesuai diatas
//======================================================
			} else if (current_fd == master_ctx->shutdown_event_fd) {
				uint64_t u;
				read(master_ctx->shutdown_event_fd, &u, sizeof(u));
				LOG_INFO("%sSIGINT received. Initiating graceful shutdown...", label);
				master_shutdown_requested = 1;
				broadcast_shutdown(master_ctx);
				continue;
			} else if (current_fd == master_ctx->listen_sock) {
				if (async_event_is_EPOLLIN(current_events)) {
					if (handle_listen_sock_event(label, master_ctx, master_sio_c_session, &client_num) != SUCCESS) {
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
					if (setup_fork_worker(label, master_ctx,	worker_closed.r_worker_type_t, worker_closed.index) != SUCCESS) {
						continue;
					}
//======================================================================
				} else {
					if (handle_ipc_event(label, master_ctx, master_sio_c_session, &current_fd) != SUCCESS) {
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
    workers_cleanup(master_ctx);
    memset(&node_config, 0, sizeof(node_config_t));
    CLOSE_FD(&master_ctx->listen_sock);
    async_delete_event(label, &master_ctx->master_async, &master_ctx->master_timer_fd);
    CLOSE_FD(&master_ctx->master_async.async_fd);
}
