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
#include "kalman.h"
#include "types.h"
#include "master/socket_listenner.h"
#include "master/ipc.h"
#include "master/workers.h"
#include "master/process.h"
#include "ipc/protocol.h"
#include "ipc/shutdown.h"
#include "sessions/master_session.h"


status_t setup_master(master_context *master_ctx) {
    const char *label = "[Master]: ";
    for (int i = 0; i < MAX_MASTER_CONCURRENT_SESSIONS; ++i) {
        master_ctx->sio_c_session[i].sio_index = -1;
        master_ctx->sio_c_session[i].in_use = false;
        memset(master_ctx->sio_c_session[i].ip, 0, IP_ADDRESS_LEN);
    }
    master_ctx->last_sio_rr_idx = 0;
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
		master_ctx->sio[i].uds[0] = 0; 
		master_ctx->sio[i].uds[1] = 0; 
	}
    for (int i = 0; i < MAX_LOGIC_WORKERS; ++i) { 
		master_ctx->logic[i].uds[0] = 0; 
		master_ctx->logic[i].uds[1] = 0; 
	}
    for (int i = 0; i < MAX_COW_WORKERS; ++i) { 
		master_ctx->cow[i].uds[0] = 0; 
		master_ctx->cow[i].uds[1] = 0; 
	}
    for (int i = 0; i < MAX_DBR_WORKERS; ++i) { 
		master_ctx->dbr[i].uds[0] = 0; 
		master_ctx->dbr[i].uds[1] = 0; 
	}
    for (int i = 0; i < MAX_DBW_WORKERS; ++i) { 
		master_ctx->dbw[i].uds[0] = 0; 
		master_ctx->dbw[i].uds[1] = 0; 
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
    for (int i = 0; i < MAX_DBR_WORKERS; ++i) {
		if (create_socket_pair(label, master_ctx, DBR, i) != SUCCESS) return FAILURE;
    }
    for (int i = 0; i < MAX_DBW_WORKERS; ++i) {
		if (create_socket_pair(label, master_ctx, DBW, i) != SUCCESS) return FAILURE;
    }
    return SUCCESS;
}

status_t setup_workers(master_context *master_ctx) {
	const char *label = "[Master]: ";
	for (int i = 0; i < MAX_SIO_WORKERS; ++i) {
		if (setup_fork_worker(label, master_ctx, SIO, i) != SUCCESS) {
			return FAILURE;
		}
    }
    for (int i = 0; i < MAX_LOGIC_WORKERS; ++i) {
		if (setup_fork_worker(label, master_ctx, LOGIC, i) != SUCCESS) {
			return FAILURE;
		}
    }
    for (int i = 0; i < MAX_COW_WORKERS; ++i) {
		if (setup_fork_worker(label, master_ctx, COW, i) != SUCCESS) {
			return FAILURE;
		}
    }
    for (int i = 0; i < MAX_DBR_WORKERS; ++i) {
		if (setup_fork_worker(label, master_ctx, DBR, i) != SUCCESS) {
			return FAILURE;
		}
    }
    for (int i = 0; i < MAX_DBW_WORKERS; ++i) {
		if (setup_fork_worker(label, master_ctx, DBW, i) != SUCCESS) {
			return FAILURE;
		}
    }
//======================================================================	
	if (async_create_timerfd(label, &master_ctx->master_timer_fd) != SUCCESS) {
		return FAILURE;
	}
	if (async_set_timerfd_time(label, &master_ctx->master_timer_fd,
		1, 0,
        1, 0) != SUCCESS)
    {
		return FAILURE;
	}
    if (async_create_incoming_event(label, &master_ctx->master_async, &master_ctx->master_timer_fd) != SUCCESS) {
		return FAILURE;
	}
//======================================================================	    
    return SUCCESS;
}

static inline status_t broadcast_shutdown(master_context *master_ctx) {
	const char *label = "[Master]: ";
	int not_used_fd = -1;
	for (int i = 0; i < MAX_SIO_WORKERS; ++i) { 
		ipc_protocol_t_status_t cmd_result = ipc_prepare_cmd_shutdown(label, &not_used_fd);
		if (cmd_result.status != SUCCESS) {
			return FAILURE;
		}
		ssize_t_status_t send_result = send_ipc_protocol_message(label, &master_ctx->sio[i].uds[0], cmd_result.r_ipc_protocol_t, &not_used_fd);
		if (send_result.status != SUCCESS) {
			LOG_ERROR("%sFailed to sent shutdown to SIO %ld.", label, i);
		} else {
			LOG_DEBUG("%sSent shutdown to SIO %ld.", label, i);
		}
		CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t); 
	}
	for (int i = 0; i < MAX_LOGIC_WORKERS; ++i) {
		ipc_protocol_t_status_t cmd_result = ipc_prepare_cmd_shutdown(label, &not_used_fd);
		if (cmd_result.status != SUCCESS) {
			return FAILURE;
		}	
		ssize_t_status_t send_result = send_ipc_protocol_message(label, &master_ctx->logic[i].uds[0], cmd_result.r_ipc_protocol_t, &not_used_fd);
		if (send_result.status != SUCCESS) {
			LOG_ERROR("%sFailed to sent shutdown to Logic %ld.", label, i);
		} else {
			LOG_DEBUG("%sSent shutdown to Logic %ld.", label, i);
		}
		CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
	}
	for (int i = 0; i < MAX_COW_WORKERS; ++i) { 
		ipc_protocol_t_status_t cmd_result = ipc_prepare_cmd_shutdown(label, &not_used_fd);
		if (cmd_result.status != SUCCESS) {
			return FAILURE;
		}	
		ssize_t_status_t send_result = send_ipc_protocol_message(label, &master_ctx->cow[i].uds[0], cmd_result.r_ipc_protocol_t, &not_used_fd);
		if (send_result.status != SUCCESS) {
			LOG_ERROR("%sFailed to sent shutdown to COW %ld.", label, i);
		} else {
			LOG_DEBUG("%sSent shutdown to COW %ld.", label, i);
		}
		CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
	}
    for (int i = 0; i < MAX_DBR_WORKERS; ++i) { 
		ipc_protocol_t_status_t cmd_result = ipc_prepare_cmd_shutdown(label, &not_used_fd);
		if (cmd_result.status != SUCCESS) {
			return FAILURE;
		}	
		ssize_t_status_t send_result = send_ipc_protocol_message(label, &master_ctx->dbr[i].uds[0], cmd_result.r_ipc_protocol_t, &not_used_fd);
		if (send_result.status != SUCCESS) {
			LOG_ERROR("%sFailed to sent shutdown to DBR %ld.", label, i);
		} else {
			LOG_DEBUG("%sSent shutdown to DBR %ld.", label, i);
		}
		CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
	}
    for (int i = 0; i < MAX_DBW_WORKERS; ++i) { 
		ipc_protocol_t_status_t cmd_result = ipc_prepare_cmd_shutdown(label, &not_used_fd);
		if (cmd_result.status != SUCCESS) {
			return FAILURE;
		}	
		ssize_t_status_t send_result = send_ipc_protocol_message(label, &master_ctx->dbw[i].uds[0], cmd_result.r_ipc_protocol_t, &not_used_fd);
		if (send_result.status != SUCCESS) {
			LOG_ERROR("%sFailed to sent shutdown to DBW %ld.", label, i);
		} else {
			LOG_DEBUG("%sSent shutdown to DBW %ld.", label, i);
		}
		CLOSE_IPC_PROTOCOL(&cmd_result.r_ipc_protocol_t);
	}
	return SUCCESS;
}

static inline status_t check_worker_healthy(const char* label, worker_type_t wot, int index, worker_metrics_t* m) {
    const char *worker_name = "Unknown";
    switch (wot) {
        case SIO: { worker_name = "SIO"; break; }
        case LOGIC: { worker_name = "Logic"; break; }
        case COW: { worker_name = "COW"; break; }
        case DBR: { worker_name = "DBR"; break; }
        case DBW: { worker_name = "DBW"; break; }
        default: { worker_name = "Unknown"; break; }
    }
    uint64_t_status_t rt = get_realtime_time_ns(label);
    uint64_t now_ns = rt.r_uint64_t;

    if (m->first_check_healthy == (uint8_t)0x01) {
        m->first_check_healthy = (uint8_t)0x00;
        kalman_init(&m->health_kalman_filter, 0.5f, 5.0f, 100.0f, 100.0f);
        m->healthypct = 100.0;
        m->ishealthy = true;
        m->last_checkhealthy = now_ns;
        m->kalman_initialized_count = 0;
        m->count_ack = 0;
        m->sum_hbtime = m->hbtime;
        LOG_DEVEL_DEBUG("%s[%s %d] First-time health check -> assumed healthy (100%%)", label, worker_name, index);
        return SUCCESS;
    }
    double actual_elapsed_sec = (double)(now_ns - m->last_checkhealthy) / 1e9;
    double ttl_delay_jitter = (m->sum_hbtime - m->hbtime) - ((double)WORKER_HEARTBEATSEC_NODE_HEARTBEATSEC_TIMEOUT * m->count_ack);
    double setup_elapsed_sec = (double)WORKER_HEARTBEATSEC_TIMEOUT + ttl_delay_jitter;
    double setup_count_ack = setup_elapsed_sec / (double)WORKER_HEARTBEATSEC_NODE_HEARTBEATSEC_TIMEOUT;
    double comp_elapsed_sec = actual_elapsed_sec / setup_elapsed_sec;
    double expected_count_ack = setup_count_ack * comp_elapsed_sec;
    float current_health_ratio_measurement;
    if (expected_count_ack == (double)0) {
        current_health_ratio_measurement = 0.0f;
    } else {
        current_health_ratio_measurement = (float)(m->count_ack / expected_count_ack);
    }
    current_health_ratio_measurement *= 100.0f;
    if (current_health_ratio_measurement < 0.0f) current_health_ratio_measurement = 0.0f;
    if (current_health_ratio_measurement > 1000.0f) current_health_ratio_measurement = 1000.0f;
    if (m->kalman_initialized_count < KALMAN_CALIBRATION_SAMPLES) {
        m->kalman_calibration_samples[m->kalman_initialized_count] = current_health_ratio_measurement;
        m->kalman_initialized_count++;
        if (m->kalman_initialized_count == KALMAN_CALIBRATION_SAMPLES) {
            float avg_health = calculate_average(m->kalman_calibration_samples, KALMAN_CALIBRATION_SAMPLES);
            float var_health = calculate_variance(m->kalman_calibration_samples, KALMAN_CALIBRATION_SAMPLES, avg_health);
            if (var_health < 0.1f) var_health = 0.1f;
            float kalman_q = 1.0f;
            float kalman_r = var_health;
            float kalman_p0 = var_health * 2.0f;
            kalman_init(&m->health_kalman_filter, kalman_q, kalman_r, kalman_p0, avg_health);
            LOG_DEVEL_DEBUG("%s[%s %d] Kalman Health Filter initialized. Avg: %.2f, Var: %.2f (Q:%.2f, R:%.2f, P0:%.2f)",
                            label, worker_name, index, avg_health, var_health, kalman_q, kalman_r, kalman_p0);
        } else {
            //m->healthypct = current_health_ratio_measurement;
            //m->ishealthy = (m->healthypct >= HEALTHY_THRESHOLD);
            m->healthypct = 100.0;
            m->ishealthy = true;
            m->last_checkhealthy = now_ns;
            m->count_ack = (double)0;
            m->sum_hbtime = m->hbtime;
            LOG_DEVEL_DEBUG("%s[%s %d] Calibrating health... (%d/%d) -> %.2f%% [%s]",
                            label, worker_name, index, m->kalman_initialized_count, KALMAN_CALIBRATION_SAMPLES,
                            m->healthypct, m->ishealthy ? "HEALTHY" : "UNHEALTHY");
            return SUCCESS;
        }
    }
    m->healthypct = kalman_filter(&m->health_kalman_filter, current_health_ratio_measurement);
    if (m->healthypct < 0.0f) m->healthypct = 0.0f;
    if (m->healthypct > 100.0f) m->healthypct = 100.0f;
    m->ishealthy = (m->healthypct >= HEALTHY_THRESHOLD);
    m->last_checkhealthy = now_ns;
    m->count_ack = (double)0;
    m->sum_hbtime = m->hbtime;
    LOG_DEVEL_DEBUG(
        "%s[%s %d] Meas health: %.2f%% -> Est health: %.2f%% [%s]",
        label, worker_name, index,
        current_health_ratio_measurement,
        m->healthypct,
        m->ishealthy ? "HEALTHY" : "UNHEALTHY"
    );
    return SUCCESS;
}

static inline status_t check_workers_healthy(master_context *master_ctx) {
	const char *label = "[Master]: ";
	for (int i = 0; i < MAX_SIO_WORKERS; ++i) { 
		if (check_worker_healthy(label, SIO, i, &master_ctx->sio_state[i].metrics) != SUCCESS) {
            return FAILURE;
        }
        if (master_ctx->sio_state[i].metrics.healthypct < (double)25) {
            master_ctx->sio_state[i].metrics.isactive = false;
            if (close_worker(label, master_ctx, SIO, i) != SUCCESS) {
                return FAILURE;
            }
            if (create_socket_pair(label, master_ctx, SIO, i) != SUCCESS) {
                return FAILURE;
            }
            if (setup_fork_worker(label, master_ctx, SIO, i) != SUCCESS) {
                return FAILURE;
            }
        }
	}
	for (int i = 0; i < MAX_LOGIC_WORKERS; ++i) {
		if (check_worker_healthy(label, LOGIC, i, &master_ctx->logic_state[i].metrics) != SUCCESS) {
            return FAILURE;
        }
        if (master_ctx->logic_state[i].metrics.healthypct < (double)25) {
            master_ctx->logic_state[i].metrics.isactive = false;
            if (close_worker(label, master_ctx, LOGIC, i) != SUCCESS) {
                return FAILURE;
            }
            if (create_socket_pair(label, master_ctx, LOGIC, i) != SUCCESS) {
                return FAILURE;
            }
            if (setup_fork_worker(label, master_ctx, LOGIC, i) != SUCCESS) {
                return FAILURE;
            }
        }
	}
	for (int i = 0; i < MAX_COW_WORKERS; ++i) { 
		if (check_worker_healthy(label, COW, i, &master_ctx->cow_state[i].metrics) != SUCCESS) {
            return FAILURE;
        }
        if (master_ctx->cow_state[i].metrics.healthypct < (double)25) {
            master_ctx->cow_state[i].metrics.isactive = false;
            if (close_worker(label, master_ctx, COW, i) != SUCCESS) {
                return FAILURE;
            }
            if (create_socket_pair(label, master_ctx, COW, i) != SUCCESS) {
                return FAILURE;
            }
            if (setup_fork_worker(label, master_ctx, COW, i) != SUCCESS) {
                return FAILURE;
            }
        }
	}
    for (int i = 0; i < MAX_DBR_WORKERS; ++i) { 
		if (check_worker_healthy(label, DBR, i, &master_ctx->dbr_state[i].metrics) != SUCCESS) {
            return FAILURE;
        }
        if (master_ctx->dbr_state[i].metrics.healthypct < (double)25) {
            master_ctx->dbr_state[i].metrics.isactive = false;
            if (close_worker(label, master_ctx, DBR, i) != SUCCESS) {
                return FAILURE;
            }
            if (create_socket_pair(label, master_ctx, DBR, i) != SUCCESS) {
                return FAILURE;
            }
            if (setup_fork_worker(label, master_ctx, DBR, i) != SUCCESS) {
                return FAILURE;
            }
        }
	}
    for (int i = 0; i < MAX_DBW_WORKERS; ++i) { 
		if (check_worker_healthy(label, DBW, i, &master_ctx->dbw_state[i].metrics) != SUCCESS) {
            return FAILURE;
        }
        if (master_ctx->dbw_state[i].metrics.healthypct < (double)25) {
            master_ctx->dbw_state[i].metrics.isactive = false;
            if (close_worker(label, master_ctx, DBW, i) != SUCCESS) {
                return FAILURE;
            }
            if (create_socket_pair(label, master_ctx, DBW, i) != SUCCESS) {
                return FAILURE;
            }
            if (setup_fork_worker(label, master_ctx, DBW, i) != SUCCESS) {
                return FAILURE;
            }
        }
	}
	return SUCCESS;
}

void run_master_process(master_context *master_ctx) {
	const char *label = "[Master]: ";
	volatile sig_atomic_t master_shutdown_requested = 0;
	uint64_t client_num = 1ULL;
    
    LOG_INFO("%sPID %d TCP Server listening on port %d.", label, master_ctx->master_pid, node_config.listen_port);
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
					if (handle_listen_sock_event(label, master_ctx, &client_num) != SUCCESS) {
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
    workers_cleanup(master_ctx);
    memset(&node_config, 0, sizeof(node_config_t));
    CLOSE_FD(&master_ctx->listen_sock);
    async_delete_event(label, &master_ctx->master_async, &master_ctx->master_timer_fd);
    CLOSE_FD(&master_ctx->master_timer_fd);
    CLOSE_FD(&master_ctx->master_async.async_fd);
}
