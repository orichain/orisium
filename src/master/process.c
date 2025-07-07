#include <netinet/in.h>
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
#include "commons.h"
#include "sessions/master_client_session.h"
#include "types.h"
#include "master/socket_listenner.h"
#include "master/ipc.h"
#include "master/workers.h"
#include "master/process.h"
#include "ipc/protocol.h"
#include "ipc/shutdown.h"

status_t setup_master(master_context *master_ctx) {
	master_ctx->master_pid = -1;
	master_ctx->shutdown_event_fd = -1;
    master_ctx->listen_sock = -1;
    master_ctx->master_async.async_fd = -1;
    master_ctx->master_pid = getpid();
    LOG_INFO("[Master]: PID %d TCP Server listening on port %d.", master_ctx->master_pid, node_config.listen_port);
//======================================================================
// Master setup socket listenner
//======================================================================
	if (async_create("[Master]: ", &master_ctx->master_async) != SUCCESS) {
		return FAILURE;
	}
	if (async_create_eventfd("[Master]: ", &master_ctx->shutdown_event_fd) != SUCCESS) {
		return FAILURE;
	}
	if (async_create_incoming_event("[Master]: ", &master_ctx->master_async, &master_ctx->shutdown_event_fd) != SUCCESS) {
		return FAILURE;
	}	
    if (setup_socket_listenner("[Master]: ", master_ctx) != SUCCESS) {
		return FAILURE; 
	}	
    if (async_create_incoming_event("[Master]: ", &master_ctx->master_async, &master_ctx->listen_sock) != SUCCESS) {
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
		if (create_socket_pair("[Master]: ", master_ctx, SIO, i) != SUCCESS) return FAILURE;
    }
    for (int i = 0; i < MAX_LOGIC_WORKERS; ++i) {
		if (create_socket_pair("[Master]: ", master_ctx, LOGIC, i) != SUCCESS) return FAILURE;
    }
    for (int i = 0; i < MAX_COW_WORKERS; ++i) {
		if (create_socket_pair("[Master]: ", master_ctx, COW, i) != SUCCESS) return FAILURE;
    }
    return SUCCESS;
}

status_t setup_workers(master_context *master_ctx) {
	for (int i = 0; i < MAX_SIO_WORKERS; ++i) {
		if (setup_fork_worker("[Master]: ", master_ctx,	SIO, i) != SUCCESS) {
			return FAILURE;
		}
    }
    for (int i = 0; i < MAX_LOGIC_WORKERS; ++i) {
		if (setup_fork_worker("[Master]: ", master_ctx,	LOGIC, i) != SUCCESS) {
			return FAILURE;
		}
    }
    for (int i = 0; i < MAX_COW_WORKERS; ++i) {
		if (setup_fork_worker("[Master]: ", master_ctx,	COW, i) != SUCCESS) {
			return FAILURE;
		}
    }
    LOG_INFO("[Master]: Starting main event loop. Waiting for clients and worker communications...");
    return SUCCESS;
}

void run_master_process(master_context *master_ctx) {
	volatile sig_atomic_t master_shutdown_requested = 0;
	master_client_session_t master_client_sessions[MAX_MASTER_CONCURRENT_SESSIONS];
	uint64_t next_client_id = 1ULL;
	//double_t avg_connection = 0.0;
	//double_t cnt_connection = 0.0;
	//double_t sio_worker = (double_t)MAX_SIO_WORKERS;
	
	for (int i = 0; i < MAX_MASTER_CONCURRENT_SESSIONS; ++i) {
        master_client_sessions[i].in_use = false;
        memset(master_client_sessions[i].ip, 0, INET6_ADDRSTRLEN);
    }
    while (!master_shutdown_requested) {
		int_status_t snfds = async_wait("[Master]: ", &master_ctx->master_async);
		if (snfds.status != SUCCESS) continue;
		for (int n = 0; n < snfds.r_int; ++n) {		
			if (master_shutdown_requested) {
				break;
			}
			int_status_t fd_status = async_getfd("[Master]: ", &master_ctx->master_async, n);
			if (fd_status.status != SUCCESS) continue;
			int current_fd = fd_status.r_int;
			uint32_t_status_t events_status = async_getevents("[Master]: ", &master_ctx->master_async, n);
			if (events_status.status != SUCCESS) continue;
			uint32_t current_events = events_status.r_uint32_t;			
			if (current_fd == master_ctx->shutdown_event_fd) {
				uint64_t u;
				read(master_ctx->shutdown_event_fd, &u, sizeof(u));
				LOG_INFO("[Master]: SIGINT received. Initiating graceful shutdown...");
				master_shutdown_requested = 1;
				int not_used_fd = -1;
				for (int i = 0; i < MAX_SIO_WORKERS; ++i) { 
					ipc_protocol_t_status_t cmd_result = ipc_prepare_cmd_shutdown(&not_used_fd);
					if (cmd_result.status != SUCCESS) {
						continue;
					}
					ssize_t_status_t send_result = send_ipc_protocol_message(&master_ctx->master_uds_sio_fds[i], cmd_result.r_ipc_protocol_t, &not_used_fd);
					if (send_result.status != SUCCESS) {
						LOG_INFO("[Master]: Failed to sent shutdown (ID %ld) to SIO.", i);
					} else {
						LOG_INFO("[Master]: Sent shutdown (ID %ld) to SIO.", i);
					}
					CLOSE_IPC_PROTOCOL(cmd_result.r_ipc_protocol_t); 
				}
				/*
				for (int i = 0; i < MAX_LOGIC_WORKERS; ++i) {
					ipc_protocol_t_status_t cmd_result = ipc_prepare_cmd_shutdown(&not_used_fd);
					if (cmd_result.status != SUCCESS) {
						continue;
					}	
					ssize_t_status_t send_result = send_ipc_protocol_message(&master_ctx->worker_uds_logic_fds[i], cmd_result.r_ipc_protocol_t, &not_used_fd);
					if (send_result.status != SUCCESS) {
						LOG_INFO("[Master]: Failed to sent shutdown (ID %ld) to Logic.", i);
					} else {
						LOG_INFO("[Server IO Worker %d]: Sent shutdown (ID %ld) to Logic.", i);
					}
					CLOSE_IPC_PROTOCOL(cmd_result.r_ipc_protocol_t);
				}
				for (int i = 0; i < MAX_COW_WORKERS; ++i) { 
					ipc_protocol_t_status_t cmd_result = ipc_prepare_cmd_shutdown(&not_used_fd);
					if (cmd_result.status != SUCCESS) {
						continue;
					}	
					ssize_t_status_t send_result = send_ipc_protocol_message(&master_ctx->worker_uds_cow_fds[i], cmd_result.r_ipc_protocol_t, &not_used_fd);
					if (send_result.status != SUCCESS) {
						LOG_INFO("[Master]: Failed to sent shutdown (ID %ld) to COW.", i);
					} else {
						LOG_INFO("[Server IO Worker %d]: Sent shutdown (ID %ld) to COW.", i);
					}
					CLOSE_IPC_PROTOCOL(cmd_result.r_ipc_protocol_t);
				}
				*/
				continue;
			} else if (current_fd == master_ctx->listen_sock) {
				if (async_event_is_EPOLLIN(current_events)) {
					if (handle_listen_sock_event("[Master]: ", master_ctx, master_client_sessions, &next_client_id) != SUCCESS) {
						continue;
					}
				} else {
					CLOSE_FD(current_fd);
				}
            } else {
				if (async_event_is_EPOLLHUP(current_events) ||
					async_event_is_EPOLLERR(current_events) ||
					async_event_is_EPOLLRDHUP(current_events))
				{
					worker_type_t_status_t worker_closed = handle_ipc_closed_event("[Master]: ", master_ctx, &current_fd);
					if (worker_closed.status != SUCCESS) {
						continue;
					}
//======================================================================
// Cleanup and recreate worker
//======================================================================
					if (close_worker("[Master]: ", master_ctx, worker_closed.r_worker_type_t, worker_closed.index) != SUCCESS) {
						continue;
					}
					if (create_socket_pair("[Master]: ", master_ctx, worker_closed.r_worker_type_t, worker_closed.index) != SUCCESS) {
						continue;
					}
					if (setup_fork_worker("[Master]: ", master_ctx,	worker_closed.r_worker_type_t, worker_closed.index) != SUCCESS) {
						continue;
					}
//======================================================================
				} else {
					if (handle_ipc_event("[Master]: ", master_ctx, master_client_sessions, &current_fd) != SUCCESS) {
						continue;
					}
				}
            }
        }
    }
//======================================================================
// Cleanup
//======================================================================
    workers_cleanup(master_ctx);
    memset(&node_config, 0, sizeof(node_config_t));
    CLOSE_FD(master_ctx->listen_sock);
    CLOSE_FD(master_ctx->master_async.async_fd);
}
