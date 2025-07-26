#include <stdbool.h>
#include <unistd.h>
#include <stdint.h>
#include <netinet/in.h>
#include <string.h>
#include <bits/types/sig_atomic_t.h>
#include <math.h>
#include <stdio.h>

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
#include "master/worker_selector.h"
#include "master/worker_ipc_cmds.h"
#include "master/server_orilink.h"
#include "node.h"
#include "pqc.h"
#include "kalman.h"
#include "sessions/master_session.h"

volatile sig_atomic_t shutdown_requested = 0;
int *shutdown_event_fd = NULL;

void sigint_handler(int signum) {
    shutdown_requested = 1ULL;
    //LOG_INFO("[Orisium]: SIGINT received. Initiating graceful shutdown...");
    if (shutdown_event_fd && *shutdown_event_fd != -1) {
        static const uint64_t u = 1ULL;
        write(*shutdown_event_fd, &u, sizeof(uint64_t));
    }
}

status_t setup_master(const char *label, master_context *master_ctx, uint16_t *listen_port) {
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

void setup_master_cow_session(master_cow_c_session_t *session) {
    session->cow_index = -1;
    session->in_use = false;
    memset(&session->server_addr, 0, sizeof(struct sockaddr_in6));
}

void cleanup_master_cow_session(master_cow_c_session_t *session) {
    session->cow_index = -1;
    session->in_use = false;
    memset(&session->server_addr, 0, sizeof(struct sockaddr_in6));
}

void setup_master_sio_session(master_sio_c_session_t *session) {
    session->sio_index = -1;
    session->in_use = false;    
    memset(&session->old_client_addr, 0, sizeof(struct sockaddr_in6));
    memset(&session->client_addr, 0, sizeof(struct sockaddr_in6));
    memset(session->identity.kem_privatekey, 0, KEM_PRIVATEKEY_BYTES);
    memset(session->identity.kem_publickey, 0, KEM_PUBLICKEY_BYTES);
    memset(session->identity.kem_ciphertext, 0, KEM_CIPHERTEXT_BYTES);
    memset(session->identity.kem_sharedsecret, 0, KEM_SHAREDSECRET_BYTES);
    session->identity.client_id = 0ULL;
    session->identity.server_id = 0ULL;
    session->identity.port = 0x0000;
    setup_oricle_double(&session->rtt, (double)0);
    setup_oricle_double(&session->retry, (double)0);
    CLOSE_FD(&session->sock_fd);
    setup_hello_ack(&session->hello1_ack);
    setup_hello_ack(&session->hello2_ack);
    setup_hello_ack(&session->hello3_ack);
    setup_hello_ack(&session->sock_ready);
}

void cleanup_master_sio_session(const char *label, async_type_t *master_async, master_sio_c_session_t *session) {
    session->sio_index = -1;
    session->in_use = false;    
    memset(&session->old_client_addr, 0, sizeof(struct sockaddr_in6));
    memset(&session->client_addr, 0, sizeof(struct sockaddr_in6));
    memset(session->identity.kem_privatekey, 0, KEM_PRIVATEKEY_BYTES);
    memset(session->identity.kem_publickey, 0, KEM_PUBLICKEY_BYTES);
    memset(session->identity.kem_ciphertext, 0, KEM_CIPHERTEXT_BYTES);
    memset(session->identity.kem_sharedsecret, 0, KEM_SHAREDSECRET_BYTES);
    session->identity.client_id = 0ULL;
    session->identity.server_id = 0ULL;
    session->identity.port = 0x0000;
    cleanup_oricle_double(&session->rtt);
    cleanup_oricle_double(&session->retry);
    async_delete_event(label, master_async, &session->sock_fd);
    CLOSE_FD(&session->sock_fd);
    cleanup_hello_ack(label, master_async, &session->hello1_ack);
    cleanup_hello_ack(label, master_async, &session->hello2_ack);
    cleanup_hello_ack(label, master_async, &session->hello3_ack);
    cleanup_hello_ack(label, master_async, &session->sock_ready);
}

bool client_disconnected(const char *label, int session_index, async_type_t *master_async, master_sio_c_session_t *session, uint8_t try_count) {
    if (try_count > (uint8_t)MAX_RETRY) {
        LOG_DEVEL_DEBUG("%s session %d: disconnect => try count %d.", label, session_index, try_count);
        cleanup_master_sio_session(label, master_async, session);
        return true;
    }
    return false;
}

void run_master_process(master_context *master_ctx, uint16_t *listen_port, bootstrap_nodes_t *bootstrap_nodes) {
	const char *label = "[Master]: ";
	volatile sig_atomic_t master_shutdown_requested = 0;
    if (setup_master(label, master_ctx, listen_port) != SUCCESS) goto exit;
    shutdown_event_fd = &master_ctx->shutdown_event_fd;
    if (setup_workers(master_ctx) != SUCCESS) goto exit;
    
    
	if (async_create_timerfd(label, &master_ctx->master_timer_fd) != SUCCESS) {
		goto exit;
	}
	if (async_set_timerfd_time(label, &master_ctx->master_timer_fd,
		WORKER_HEARTBEATSEC_TIMEOUT, 0,
        WORKER_HEARTBEATSEC_TIMEOUT, 0) != SUCCESS)
    {
		goto exit;
	}
    if (async_create_incoming_event(label, &master_ctx->master_async, &master_ctx->master_timer_fd) != SUCCESS) {
		goto exit;
	}

    if (sleep_s(1) != SUCCESS) goto exit;   
    for (int i = 0; i < MAX_MASTER_SIO_SESSIONS; ++i) {
        master_sio_c_session_t *session;
        session = &master_ctx->sio_c_session[i];
        setup_master_sio_session(session);
    }
    for (int i = 0; i < MAX_MASTER_COW_SESSIONS; ++i) {
        master_cow_c_session_t *session;
        session = &master_ctx->cow_c_session[i];
        setup_master_cow_session(session);
    }
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
        if (new_task_metrics(label, master_ctx, COW, cow_worker_idx) != SUCCESS) {
            LOG_ERROR("%sFailed to input new task in COW %d metrics.", label, cow_worker_idx);
            goto exit;
        }
        if (master_cow_connect(master_ctx, &bootstrap_nodes->addr[ic], cow_worker_idx) != SUCCESS) goto exit;
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
                    master_workers_shutdown(master_ctx, IMMEDIATELY);
                    continue;
                }
                if (check_workers_healthy(master_ctx) != SUCCESS) continue;
			} else if (current_fd == master_ctx->shutdown_event_fd) {
				uint64_t u;
				read(master_ctx->shutdown_event_fd, &u, sizeof(u));
				LOG_INFO("%sSIGINT received. Initiating graceful shutdown...", label);
				master_shutdown_requested = 1;
				master_workers_shutdown(master_ctx, IMMEDIATELY);
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
                bool event_founded_in_uds = false;
                for (int i = 0; i < MAX_SIO_WORKERS; ++i) {
                    if (current_fd == master_ctx->sio_session[i].upp.uds[0]) {
                        event_founded_in_uds = true;
                        break;
                    }
                }
                if (!event_founded_in_uds) {
                    for (int i = 0; i < MAX_LOGIC_WORKERS; ++i) { 
                        if (current_fd == master_ctx->logic_session[i].upp.uds[0]) {
                            event_founded_in_uds = true;
                            break;
                        }
                    }
                }
                if (!event_founded_in_uds) {
                    for (int i = 0; i < MAX_COW_WORKERS; ++i) { 
                        if (current_fd == master_ctx->cow_session[i].upp.uds[0]) {
                            event_founded_in_uds = true;
                            break;
                        }
                    }
                }
                if (!event_founded_in_uds) {
                    for (int i = 0; i < MAX_DBR_WORKERS; ++i) { 
                        if (current_fd == master_ctx->dbr_session[i].upp.uds[0]) {
                            event_founded_in_uds = true;
                            break;
                        }
                    }
                }                
                if (!event_founded_in_uds) {
                    for (int i = 0; i < MAX_DBW_WORKERS; ++i) { 
                        if (current_fd == master_ctx->dbw_session[i].upp.uds[0]) {
                            event_founded_in_uds = true;
                            break;
                        }
                    }
                }
                if (event_founded_in_uds) {
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
                    continue;
                }
                bool event_founded_in_sio_c_session = false;
                for (int i = 0; i < MAX_MASTER_SIO_SESSIONS; ++i) {
                    master_sio_c_session_t *session;
                    session = &master_ctx->sio_c_session[i];
                    if (session->in_use) {
                        if (current_fd == session->hello1_ack.ack_timer_fd) {
                            uint64_t u;
                            read(session->hello1_ack.ack_timer_fd, &u, sizeof(u)); //Jangan lupa read event timer
                            if (client_disconnected(label, i, &master_ctx->master_async, session, session->hello1_ack.ack_sent_try_count)) {
                                event_founded_in_sio_c_session = true;
                                break;
                            }
                            LOG_DEVEL_DEBUG("%s session %d: interval = %lf.", label, i, session->hello1_ack.interval_ack_timer_fd);
                            double try_count = (double)session->hello1_ack.ack_sent_try_count;
                            sio_c_calculate_retry(label, session, i, try_count);
                            session->hello1_ack.interval_ack_timer_fd = pow((double)2, (double)session->retry.value_prediction);
                            send_hello1_ack(label, &master_ctx->listen_sock, session);
                            event_founded_in_sio_c_session = true;
                            break;
                        }
                    }
                }
                if (event_founded_in_sio_c_session) continue;
//======================================================================
// Event yang belum ditangkap
//======================================================================                 
                LOG_ERROR("%sUnknown FD event %d.", label, current_fd);
//======================================================================
            }
        }
    }
//======================================================================
// Cleanup
// event shutdown tidak di close karena
// async_create_eventfd_nonblock_close_after_exec <= close after exec/read
//======================================================================
exit:
    for (int i = 0; i < MAX_MASTER_SIO_SESSIONS; ++i) {
        master_sio_c_session_t *session;
        session = &master_ctx->sio_c_session[i];
        if (session->in_use) {
            cleanup_master_sio_session(label, &master_ctx->master_async, session);
        }
    }
    for (int i = 0; i < MAX_MASTER_COW_SESSIONS; ++i) {
        master_cow_c_session_t *session;
        session = &master_ctx->cow_c_session[i];
        if (session->in_use) {
            cleanup_master_cow_session(session);
        }
    }
    workers_cleanup(master_ctx);
    CLOSE_FD(&master_ctx->listen_sock);
    async_delete_event(label, &master_ctx->master_async, &master_ctx->master_timer_fd);
    CLOSE_FD(&master_ctx->master_timer_fd);
    CLOSE_FD(&master_ctx->master_async.async_fd);
}
