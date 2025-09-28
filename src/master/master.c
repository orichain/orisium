#include <stdbool.h>
#include <unistd.h>
#include <stdint.h>
#include <netinet/in.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

#include "log.h"
#include "constants.h"
#include "async.h"
#include "utilities.h"
#include "types.h"
#include "master/udp/socket_udp.h"
#include "master/udp/handlers.h"
#include "master/ipc/handlers.h"
#include "master/workers.h"
#include "master/master.h"
#include "master/ipc/worker_ipc_cmds.h"
#include "master/worker_metrics.h"
#include "master/worker_selector.h"
#include "node.h"

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

status_t setup_master(const char *label, master_context_t *master_ctx) {
    master_ctx->sio_session = (master_sio_session_t *)calloc(1, MAX_SIO_WORKERS * sizeof(master_sio_session_t));
    master_ctx->logic_session = (master_logic_session_t *)calloc(1, MAX_LOGIC_WORKERS * sizeof(master_logic_session_t));
    master_ctx->cow_session = (master_cow_session_t *)calloc(1, MAX_COW_WORKERS * sizeof(master_cow_session_t));
    master_ctx->dbr_session = (master_dbr_session_t *)calloc(1, MAX_DBR_WORKERS * sizeof(master_dbr_session_t));
    master_ctx->dbw_session = (master_dbw_session_t *)calloc(1, MAX_DBW_WORKERS * sizeof(master_dbw_session_t));
    master_ctx->sio_c_session = (master_sio_c_session_t *)calloc(1, MAX_MASTER_SIO_SESSIONS * sizeof(master_sio_c_session_t));
    master_ctx->cow_c_session = (master_cow_c_session_t *)calloc(1, MAX_MASTER_COW_SESSIONS * sizeof(master_cow_c_session_t));
//----------------------------------------------------------------------
    for (uint8_t sio_worker_idx=0;sio_worker_idx<MAX_SIO_WORKERS; ++sio_worker_idx) {
        for(uint8_t i = 0; i < MAX_CONNECTION_PER_SIO_WORKER; ++i) {
            master_ctx->sio_c_session[(sio_worker_idx * MAX_CONNECTION_PER_SIO_WORKER) + i].in_use = false;
            master_ctx->sio_c_session[(sio_worker_idx * MAX_CONNECTION_PER_SIO_WORKER) + i].sio_index = 0xff;
            memset(&master_ctx->sio_c_session[(sio_worker_idx * MAX_CONNECTION_PER_SIO_WORKER) + i].remote_addr, 0, sizeof(struct sockaddr_in6));
            master_ctx->sio_c_session[(sio_worker_idx * MAX_CONNECTION_PER_SIO_WORKER) + i].id_connection = 0xffffffffffffffff;
        }
    }
    for (uint8_t cow_worker_idx=0;cow_worker_idx<MAX_COW_WORKERS; ++cow_worker_idx) {
        for(uint8_t i = 0; i < MAX_CONNECTION_PER_COW_WORKER; ++i) {
            master_ctx->cow_c_session[(cow_worker_idx * MAX_CONNECTION_PER_COW_WORKER) + i].in_use = false;
            master_ctx->cow_c_session[(cow_worker_idx * MAX_CONNECTION_PER_COW_WORKER) + i].cow_index = 0xff;
            memset(&master_ctx->cow_c_session[(cow_worker_idx * MAX_CONNECTION_PER_COW_WORKER) + i].remote_addr, 0, sizeof(struct sockaddr_in6));
            master_ctx->cow_c_session[(cow_worker_idx * MAX_CONNECTION_PER_COW_WORKER) + i].id_connection = 0xffffffffffffffff;
        }
    }
    master_ctx->shutdown_requested = 0;
    master_ctx->hb_check_times = (uint16_t)0;
    master_ctx->is_rekeying = false;
    master_ctx->all_workers_is_ready = false;
    master_ctx->last_sio_rr_idx = 0;
    master_ctx->last_cow_rr_idx = 0;
	master_ctx->master_pid = 0;
	master_ctx->shutdown_event_fd = -1;
    master_ctx->udp_sock = -1;
    master_ctx->check_healthy_timer_fd = -1;
    master_ctx->master_async.async_fd = -1;
    master_ctx->master_pid = getpid();
//======================================================================
// Master setup socket udp & timer heartbeat
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
    shutdown_event_fd = &master_ctx->shutdown_event_fd;
    return SUCCESS;
}

void cleanup_master(const char *label, master_context_t *master_ctx) {
    free(master_ctx->sio_session);
    free(master_ctx->logic_session);
    free(master_ctx->cow_session);
    free(master_ctx->dbr_session);
    free(master_ctx->dbw_session);
    for (uint8_t sio_worker_idx=0;sio_worker_idx<MAX_SIO_WORKERS; ++sio_worker_idx) {
        for(uint8_t i = 0; i < MAX_CONNECTION_PER_SIO_WORKER; ++i) {
            master_ctx->sio_c_session[(sio_worker_idx * MAX_CONNECTION_PER_SIO_WORKER) + i].in_use = false;
            master_ctx->sio_c_session[(sio_worker_idx * MAX_CONNECTION_PER_SIO_WORKER) + i].sio_index = 0xff;
            memset(&master_ctx->sio_c_session[(sio_worker_idx * MAX_CONNECTION_PER_SIO_WORKER) + i].remote_addr, 0, sizeof(struct sockaddr_in6));
            master_ctx->sio_c_session[(sio_worker_idx * MAX_CONNECTION_PER_SIO_WORKER) + i].id_connection = 0xffffffffffffffff;
        }
    }
    for (uint8_t cow_worker_idx=0;cow_worker_idx<MAX_COW_WORKERS; ++cow_worker_idx) {
        for(uint8_t i = 0; i < MAX_CONNECTION_PER_COW_WORKER; ++i) {
            master_ctx->cow_c_session[(cow_worker_idx * MAX_CONNECTION_PER_COW_WORKER) + i].in_use = false;
            master_ctx->cow_c_session[(cow_worker_idx * MAX_CONNECTION_PER_COW_WORKER) + i].cow_index = 0xff;
            memset(&master_ctx->cow_c_session[(cow_worker_idx * MAX_CONNECTION_PER_COW_WORKER) + i].remote_addr, 0, sizeof(struct sockaddr_in6));
            master_ctx->cow_c_session[(cow_worker_idx * MAX_CONNECTION_PER_COW_WORKER) + i].id_connection = 0xffffffffffffffff;
        }
    }
    free(master_ctx->sio_c_session);
    free(master_ctx->cow_c_session);
    master_ctx->shutdown_requested = 0;
    master_ctx->hb_check_times = (uint16_t)0;
    master_ctx->is_rekeying = false;
    master_ctx->all_workers_is_ready = false;
    master_ctx->last_sio_rr_idx = 0;
    master_ctx->last_cow_rr_idx = 0;
    CLOSE_FD(&master_ctx->udp_sock);
    async_delete_event(label, &master_ctx->master_async, &master_ctx->check_healthy_timer_fd);
    CLOSE_FD(&master_ctx->check_healthy_timer_fd);
    CLOSE_FD(&master_ctx->master_async.async_fd);
    master_ctx->listen_port = (uint16_t)0;
    memset(&master_ctx->bootstrap_nodes, 0, sizeof(bootstrap_nodes_t));
}

void run_master(const char *label, master_context_t *master_ctx) {
    if (setup_workers(label, master_ctx) != SUCCESS) goto exit;
    master_workers_info(label, master_ctx, IT_READY);
    while (!master_ctx->shutdown_requested) {
		int_status_t snfds = async_wait(label, &master_ctx->master_async);
		if (snfds.status != SUCCESS) {
            if (snfds.status == FAILURE_EBADF) {
                master_ctx->shutdown_requested = 1;
            }
            continue;
        }
		for (int n = 0; n < snfds.r_int; ++n) {		
			if (master_ctx->shutdown_requested) {
				break;
			}
			int_status_t fd_status = async_getfd(label, &master_ctx->master_async, n);
			if (fd_status.status != SUCCESS) continue;
			int current_fd = fd_status.r_int;
			uint32_t_status_t events_status = async_getevents(label, &master_ctx->master_async, n);
			if (events_status.status != SUCCESS) continue;
			uint32_t current_events = events_status.r_uint32_t;	
			if (current_fd == master_ctx->check_healthy_timer_fd) {
				uint64_t u;
				read(master_ctx->check_healthy_timer_fd, &u, sizeof(u)); //Jangan lupa read event timer
                if (async_set_timerfd_time(label, &master_ctx->check_healthy_timer_fd,
                    WORKER_CHECK_HEALTHY,
                    0,
                    WORKER_CHECK_HEALTHY,
                    0) != SUCCESS)
                {
                    LOG_INFO("%sGagal set timer. Initiating graceful shutdown...", label);
                    master_ctx->shutdown_requested = 1;
                    master_workers_info(label, master_ctx, IT_SHUTDOWN);
                    continue;
                }
                master_ctx->hb_check_times++;
                if (master_ctx->hb_check_times >= REKEYING_HB_TIMES) {
                    master_ctx->hb_check_times = (uint16_t)0;
                    master_ctx->is_rekeying = true;
                    master_ctx->all_workers_is_ready = false;
                    master_workers_info(label, master_ctx, IT_REKEYING);
                } else {
                    if (check_workers_healthy(label, master_ctx) != SUCCESS) continue;
                }
			} else if (current_fd == master_ctx->shutdown_event_fd) {
				uint64_t u;
				read(master_ctx->shutdown_event_fd, &u, sizeof(u));
				LOG_INFO("%sSIGINT received. Initiating graceful shutdown...", label);
				master_ctx->shutdown_requested = 1;
				master_workers_info(label, master_ctx,IT_SHUTDOWN);
				continue;
			} else if (current_fd == master_ctx->udp_sock) {
				if (async_event_is_EPOLLIN(current_events)) {
					if (handle_master_udp_sock_event(label, master_ctx) != SUCCESS) {
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
                        worker_type_t_status_t worker_closed = handle_master_ipc_closed_event(label, master_ctx, &current_fd);
                        if (worker_closed.status != SUCCESS) {
                            continue;
                        }
//----------------------------------------------------------------------
// Recreate Worker                        
//----------------------------------------------------------------------
                        if (close_worker(label, master_ctx, worker_closed.r_worker_type_t, worker_closed.index) != SUCCESS) {
                            continue;
                        }
                        if (create_socket_pair(label, master_ctx, worker_closed.r_worker_type_t, worker_closed.index) != SUCCESS) {
                            continue;
                        }
                        if (setup_fork_worker(label, master_ctx, worker_closed.r_worker_type_t, worker_closed.index) != SUCCESS) {
                            continue;
                        }
                        if (master_worker_info(label, master_ctx, worker_closed.r_worker_type_t, worker_closed.index, IT_READY) != SUCCESS) {
                            continue;
                        }
//----------------------------------------------------------------------
                        continue;
                    } else {
                        status_t hie_rslt = handle_master_ipc_event(label, master_ctx, &current_fd);
//----------------------------------------------------------------------
// All Worker Ready To Comunication In Secure Encription
//----------------------------------------------------------------------
                        if (hie_rslt == SUCCESS_WRKSRDY) {
                            if (!master_ctx->is_rekeying) {
                                uint64_t_status_t rt = get_monotonic_time_ns(label);
                                uint64_t now_ns = rt.r_uint64_t;
                                for (int i = 0; i < MAX_SIO_WORKERS; ++i) {
                                    worker_metrics_t *metrics = &master_ctx->sio_session[i].metrics;
                                    metrics->last_checkhealthy = now_ns;
                                    metrics->count_ack = (double)0;
                                    metrics->hb_interval = (double)0;
                                    metrics->sum_hb_interval = metrics->hb_interval;
                                }
                                for (int i = 0; i < MAX_LOGIC_WORKERS; ++i) { 
                                    worker_metrics_t *metrics = &master_ctx->logic_session[i].metrics;
                                    metrics->last_checkhealthy = now_ns;
                                    metrics->count_ack = (double)0;
                                    metrics->hb_interval = (double)0;
                                    metrics->sum_hb_interval = metrics->hb_interval;
                                }
                                for (int i = 0; i < MAX_COW_WORKERS; ++i) { 
                                    worker_metrics_t *metrics = &master_ctx->cow_session[i].metrics;
                                    metrics->last_checkhealthy = now_ns;
                                    metrics->count_ack = (double)0;
                                    metrics->hb_interval = (double)0;
                                    metrics->sum_hb_interval = metrics->hb_interval;
                                }
                                for (int i = 0; i < MAX_DBR_WORKERS; ++i) { 
                                    worker_metrics_t *metrics = &master_ctx->dbr_session[i].metrics;
                                    metrics->last_checkhealthy = now_ns;
                                    metrics->count_ack = (double)0;
                                    metrics->hb_interval = (double)0;
                                    metrics->sum_hb_interval = metrics->hb_interval;
                                }
                                for (int i = 0; i < MAX_DBW_WORKERS; ++i) { 
                                    worker_metrics_t *metrics = &master_ctx->dbw_session[i].metrics;
                                    metrics->last_checkhealthy = now_ns;
                                    metrics->count_ack = (double)0;
                                    metrics->hb_interval = (double)0;
                                    metrics->sum_hb_interval = metrics->hb_interval;
                                }
                                if (async_create_timerfd(label, &master_ctx->check_healthy_timer_fd) != SUCCESS) {
                                    LOG_INFO("%sGagal async_create_timerfd hb checker. Initiating graceful shutdown...", label);
                                    master_ctx->shutdown_requested = 1;
                                    master_workers_info(label, master_ctx, IT_SHUTDOWN);
                                    continue;
                                }
                                if (async_set_timerfd_time(label, &master_ctx->check_healthy_timer_fd,
                                    WORKER_CHECK_HEALTHY, 0,
                                    WORKER_CHECK_HEALTHY, 0) != SUCCESS)
                                {
                                    LOG_INFO("%sGagal async_set_timerfd_time hb checker. Initiating graceful shutdown...", label);
                                    master_ctx->shutdown_requested = 1;
                                    master_workers_info(label, master_ctx, IT_SHUTDOWN);
                                    continue;
                                }
                                if (async_create_incoming_event(label, &master_ctx->master_async, &master_ctx->check_healthy_timer_fd) != SUCCESS) {
                                    LOG_INFO("%sGagal async_create_incoming_event hb checker. Initiating graceful shutdown...", label);
                                    master_ctx->shutdown_requested = 1;
                                    master_workers_info(label, master_ctx, IT_SHUTDOWN);
                                    continue;
                                }
                                for (int ic = 0; ic < master_ctx->bootstrap_nodes.len; ic++) {
                                    int cow_worker_idx = select_best_worker(label, master_ctx, COW);
                                    if (cow_worker_idx == -1) {
                                        LOG_ERROR("%sFailed to select an COW worker for new task. Initiating graceful shutdown...", label);
                                        master_ctx->shutdown_requested = 1;
                                        master_workers_info(label, master_ctx, IT_SHUTDOWN);
                                        continue;
                                    }
                                    uint8_t slot_found = 0xff;
                                    for(uint8_t i = 0; i < MAX_CONNECTION_PER_COW_WORKER; ++i) {
                                        if(!master_ctx->cow_c_session[(cow_worker_idx * MAX_CONNECTION_PER_COW_WORKER) + i].in_use) {
                                            master_ctx->cow_c_session[(cow_worker_idx * MAX_CONNECTION_PER_COW_WORKER) + i].cow_index = cow_worker_idx;
                                            master_ctx->cow_c_session[(cow_worker_idx * MAX_CONNECTION_PER_COW_WORKER) + i].in_use = true;
                                            slot_found = i;
                                            break;
                                        }
                                    }
                                    if (slot_found == 0xff) {
                                        LOG_ERROR("%sWARNING: No free session slots in cow-%d sessions. Initiating graceful shutdown...", label, cow_worker_idx);
                                        master_ctx->shutdown_requested = 1;
                                        master_workers_info(label, master_ctx, IT_SHUTDOWN);
                                        continue;
                                    }
                                    if (new_task_metrics(label, master_ctx, COW, cow_worker_idx) != SUCCESS) {
                                        LOG_ERROR("%sFailed to input new task in COW %d metrics. Initiating graceful shutdown...", label, cow_worker_idx);
                                        master_ctx->shutdown_requested = 1;
                                        master_workers_info(label, master_ctx, IT_SHUTDOWN);
                                        continue;
                                    }
                                    uint64_t *id_connection = &master_ctx->cow_c_session[(cow_worker_idx * MAX_CONNECTION_PER_COW_WORKER) + slot_found].id_connection;
                                    struct sockaddr_in6 *remote_addr = &master_ctx->cow_c_session[(cow_worker_idx * MAX_CONNECTION_PER_COW_WORKER) + slot_found].remote_addr;
                                    if (generate_uint64_t_id(label, id_connection) != SUCCESS) goto exit;
                                    memcpy(remote_addr, &master_ctx->bootstrap_nodes.addr[ic], sizeof(struct sockaddr_in6));
                                    if (master_cow_connect(label, master_ctx, remote_addr, cow_worker_idx, slot_found, *id_connection) != SUCCESS) goto exit;
                                }
                                if (setup_master_socket_udp(label, master_ctx) != SUCCESS) {
                                    LOG_ERROR("%sFailed to setup_master_socket_udp. Initiating graceful shutdown...", label);
                                    master_ctx->shutdown_requested = 1;
                                    master_workers_info(label, master_ctx, IT_SHUTDOWN);
                                    continue;
                                }	
                                if (async_create_incoming_event(label, &master_ctx->master_async, &master_ctx->udp_sock) != SUCCESS) {
                                    LOG_ERROR("%sFailed to async_create_incoming_event socket_udp. Initiating graceful shutdown...", label);
                                    master_ctx->shutdown_requested = 1;
                                    master_workers_info(label, master_ctx, IT_SHUTDOWN);
                                    continue;
                                }
                                LOG_INFO("%sPID %d UDP Server listening on port %d.", label, master_ctx->master_pid, master_ctx->listen_port);
                            } else {
                                master_ctx->is_rekeying = false;
                            }
                            continue;
                        } else {
                            continue;
                        }
                    }
                }
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
    cleanup_workers(label, master_ctx);
}
