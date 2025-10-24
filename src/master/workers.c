#include <string.h>      // for memset, strncpy
#include <errno.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>

#include "log.h"
#include "utilities.h"
#include "constants.h"
#include "types.h"
#include "workers/workers.h"
#include "master/workers.h"
#include "master/worker_metrics.h"
#include "master/ipc/worker_ipc_cmds.h"
#include "async.h"
#include "master/master.h"
#include "kalman.h"
#include "pqc.h"
#include "ipc.h"

status_t close_worker(const char *label, master_context_t *master_ctx, worker_type_t wot, uint8_t index) {
    master_worker_session_t *session = get_master_worker_session(master_ctx, wot, index);
    if (session == NULL) {
        return FAILURE;
    }
    uds_pair_pid_t *upp = &session->upp;
    worker_security_t *security = &session->security;
    worker_rekeying_t *rekeying = &session->rekeying;
    cleanup_oricle_long_double(&session->avgtt);
    cleanup_oricle_double(&session->healthy);
    session->isactive = false;
    session->ishealthy = false;
    session->isready = false;
    memset(security->kem_publickey, 0, KEM_PUBLICKEY_BYTES);
    memset(security->kem_ciphertext, 0, KEM_CIPHERTEXT_BYTES);
    memset(security->kem_sharedsecret, 0, KEM_SHAREDSECRET_BYTES);
    memset(security->aes_key, 0, HASHES_BYTES);
    memset(security->mac_key, 0, HASHES_BYTES);
    memset(security->local_nonce, 0, AES_NONCE_BYTES);
    security->local_ctr = (uint32_t)0;
    memset(security->remote_nonce, 0, AES_NONCE_BYTES);
    security->remote_ctr = (uint32_t)0;
    free(security->kem_publickey);
    free(security->kem_ciphertext);
    free(security->kem_sharedsecret);
    free(security->aes_key);
    free(security->mac_key);
    free(security->local_nonce);
    free(security->remote_nonce);
    security->hello1_rcvd = false;
    security->hello1_ack_sent = false;
    security->hello2_rcvd = false;
    security->hello2_ack_sent = false;
    rekeying->is_rekeying = false;
    ipc_cleanup_protocol_queue(&rekeying->rekeying_queue);
    async_delete_event(label, &master_ctx->master_async, &upp->uds[0]);
    CLOSE_UDS(&upp->uds[0]);
    CLOSE_UDS(&upp->uds[1]);
    CLOSE_PID(&upp->pid);
	return SUCCESS;
}

status_t create_socket_pair(const char *label, master_context_t *master_ctx, worker_type_t wot, uint8_t index) {
    master_worker_session_t *session = get_master_worker_session(master_ctx, wot, index);
    if (session == NULL) {
        return FAILURE;
    }
    const char *worker_name = get_master_worker_name(wot);
    uds_pair_pid_t *upp = &session->upp;
    worker_security_t *security = &session->security;
    worker_rekeying_t *rekeying = &session->rekeying;
    upp->uds[0] = 0; 
    upp->uds[1] = 0; 
    setup_oricle_long_double(&session->avgtt, (long double)0);
    setup_oricle_double(&session->healthy, (double)100);
    session->isactive = true;
    session->ishealthy = true;        
    session->isready = false;   
    security->kem_publickey = (uint8_t *)calloc(1, KEM_PUBLICKEY_BYTES);
    security->kem_ciphertext = (uint8_t *)calloc(1, KEM_CIPHERTEXT_BYTES);
    security->kem_sharedsecret = (uint8_t *)calloc(1, KEM_SHAREDSECRET_BYTES);
    security->aes_key = (uint8_t *)calloc(1, HASHES_BYTES);
    security->mac_key = (uint8_t *)calloc(1, HASHES_BYTES);
    security->local_nonce = (uint8_t *)calloc(1, AES_NONCE_BYTES);
    security->remote_nonce = (uint8_t *)calloc(1, AES_NONCE_BYTES);
    security->local_ctr = (uint32_t)0;
    security->remote_ctr = (uint32_t)0;
    security->hello1_rcvd = false;
    security->hello1_ack_sent = false;
    security->hello2_rcvd = false;
    security->hello2_ack_sent = false;
    rekeying->is_rekeying = false;
    rekeying->rekeying_queue = NULL;
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, upp->uds) == -1) {
        LOG_ERROR("%ssocketpair (%s) creation failed: %s", label, worker_name, strerror(errno));
        return FAILURE;
    }
    if (set_nonblocking(label, upp->uds[0]) != SUCCESS) {
        return FAILURE;
    }
    if (set_nonblocking(label, upp->uds[1]) != SUCCESS) {
        return FAILURE;
    }
    LOG_DEBUG("%sCreated UDS pair for %s Worker %d (Master side: %d, Worker side: %d).", label, worker_name, index, upp->uds[0], upp->uds[1]);
	return SUCCESS;
}

void close_master_resource(master_context_t *master_ctx, worker_type_t wot, uint8_t index) {
    master_worker_session_t *session = get_master_worker_session(master_ctx, wot, index);
    if (session == NULL) {
        return;
    }
    worker_security_t *security = &session->security;
    if (!security) return;
//----------------------------------------------------------------------
// Jika di close, kadang terjadi EBADF saat recreate worker dengan cepat
//----------------------------------------------------------------------
/*
    CLOSE_FD(&master_ctx->listen_sock);
    CLOSE_FD(&master_ctx->master_async.async_fd);
    CLOSE_FD(&master_ctx->heartbeat_timer_fd);
    CLOSE_FD(&master_ctx->shutdown_event_fd);
*/
//----------------------------------------------------------------------
    memset(security->kem_publickey, 0, KEM_PUBLICKEY_BYTES);
    memset(security->kem_ciphertext, 0, KEM_CIPHERTEXT_BYTES);
    memset(security->kem_sharedsecret, 0, KEM_SHAREDSECRET_BYTES);
    memset(security->aes_key, 0, HASHES_BYTES);
    memset(security->mac_key, 0, HASHES_BYTES);
    memset(security->local_nonce, 0, AES_NONCE_BYTES);
    security->local_ctr = (uint32_t)0;
    memset(security->remote_nonce, 0, AES_NONCE_BYTES);
    security->remote_ctr = (uint32_t)0;
    free(security->kem_publickey);
    free(security->kem_ciphertext);
    free(security->kem_sharedsecret);
    free(security->aes_key);
    free(security->mac_key);
    free(security->local_nonce);
    free(security->remote_nonce);
}

status_t setup_fork_worker(const char* label, master_context_t *master_ctx, worker_type_t wot, uint8_t index) {
    master_worker_session_t *session = get_master_worker_session(master_ctx, wot, index);
    if (session == NULL) {
        return FAILURE;
    }
    const char *worker_name = get_master_worker_name(wot);
    double initial_delay_ms = (double)0;
    session->upp.pid = fork();
    if (session->upp.pid == -1) {
        LOG_ERROR("%sfork (%s): %s", label, worker_name, strerror(errno));
        return FAILURE;
    } else if (session->upp.pid == 0) {
        close_master_resource(master_ctx, wot, index);
        CLOSE_UDS(&session->upp.uds[0]);
        for (uint8_t j = 0; j < MAX_SIO_WORKERS; ++j) {
            master_worker_session_t *jsession = get_master_worker_session(master_ctx, SIO, j);
            if (jsession == NULL) {
                return FAILURE;
            }
            if (wot == SIO) {
                if (j != index) {
                    CLOSE_UDS(&jsession->upp.uds[0]);
                    CLOSE_UDS(&jsession->upp.uds[1]);
                }
            } else {
                CLOSE_UDS(&jsession->upp.uds[0]);
                CLOSE_UDS(&jsession->upp.uds[1]);
            }
        }
        for (int j = 0; j < MAX_LOGIC_WORKERS; ++j) {
            master_worker_session_t *jsession = get_master_worker_session(master_ctx, LOGIC, j);
            if (jsession == NULL) {
                return FAILURE;
            }
            if (wot == LOGIC) {
                if (j != index) {
                    CLOSE_UDS(&jsession->upp.uds[0]);
                    CLOSE_UDS(&jsession->upp.uds[1]);
                }
            } else {
                CLOSE_UDS(&jsession->upp.uds[0]);
                CLOSE_UDS(&jsession->upp.uds[1]);
            }
        }
        for (int j = 0; j < MAX_COW_WORKERS; ++j) {
            master_worker_session_t *jsession = get_master_worker_session(master_ctx, COW, j);
            if (jsession == NULL) {
                return FAILURE;
            }
            if (wot == COW) {
                if (j != index) {
                    CLOSE_UDS(&jsession->upp.uds[0]);
                    CLOSE_UDS(&jsession->upp.uds[1]);
                }
            } else {
                CLOSE_UDS(&jsession->upp.uds[0]);
                CLOSE_UDS(&jsession->upp.uds[1]);
            }
        }
        for (int j = 0; j < MAX_DBR_WORKERS; ++j) {
            master_worker_session_t *jsession = get_master_worker_session(master_ctx, DBR, j);
            if (jsession == NULL) {
                return FAILURE;
            }
            if (wot == DBR) {
                if (j != index) {
                    CLOSE_UDS(&jsession->upp.uds[0]);
                    CLOSE_UDS(&jsession->upp.uds[1]);
                }
            } else {
                CLOSE_UDS(&jsession->upp.uds[0]);
                CLOSE_UDS(&jsession->upp.uds[1]);
            }
        }
        for (int j = 0; j < MAX_DBW_WORKERS; ++j) {
            master_worker_session_t *jsession = get_master_worker_session(master_ctx, DBW, j);
            if (jsession == NULL) {
                return FAILURE;
            }
            if (wot == DBW) {
                if (j != index) {
                    CLOSE_UDS(&jsession->upp.uds[0]);
                    CLOSE_UDS(&jsession->upp.uds[1]);
                }
            } else {
                CLOSE_UDS(&jsession->upp.uds[0]);
                CLOSE_UDS(&jsession->upp.uds[1]);
            }
        }
        worker_type_t x_wot = wot;
        uint8_t x_index = index;
        double x_initial_delay_ms = initial_delay_ms;
        int *master_uds_fd = &session->upp.uds[1];
        switch (wot) {
            case SIO: {
                run_sio_worker(&x_wot, &x_index, &x_initial_delay_ms, master_uds_fd);
                exit(EXIT_SUCCESS);
            }
            case LOGIC: {
                run_logic_worker(&x_wot, &x_index, &x_initial_delay_ms, master_uds_fd);
                exit(EXIT_SUCCESS);
            }
            case COW: {
                run_cow_worker(&x_wot, &x_index, &x_initial_delay_ms, master_uds_fd);
                exit(EXIT_SUCCESS);
            }
            case DBR: {
                run_dbr_worker(&x_wot, &x_index, &x_initial_delay_ms, master_uds_fd);
                exit(EXIT_SUCCESS);
            }
            case DBW: {
                run_dbw_worker(&x_wot, &x_index, &x_initial_delay_ms, master_uds_fd);
                exit(EXIT_SUCCESS);
            }
            default:
                return FAILURE;
        }
    } else {
        CLOSE_UDS(&session->upp.uds[1]);
//======================================================================
// Hitung delay start dan inisialisasi metrics
//======================================================================
        session->task_count = (uint16_t)0;
        initial_delay_ms = initialize_metrics(label, &session->metrics, wot, index);
//======================================================================
        async_create_incoming_event(
            label,
            &master_ctx->master_async,
            &session->upp.uds[0]
        );
        LOG_DEBUG("%sForked %s Worker %d (PID %d).", label, worker_name, index, session->upp.pid);
    }
    return SUCCESS;
}

void cleanup_workers(const char *label, master_context_t *master_ctx) {
    LOG_INFO("[Master]: Performing cleanup...");
    for (int i = 0; i < MAX_SIO_WORKERS; ++i) {
        close_worker(label, master_ctx, SIO, i);
    }
    for (int i = 0; i < MAX_LOGIC_WORKERS; ++i) {
        close_worker(label, master_ctx, LOGIC, i);
    }
    for (int i = 0; i < MAX_COW_WORKERS; ++i) {
        close_worker(label, master_ctx, COW, i);
    }
    for (int i = 0; i < MAX_DBR_WORKERS; ++i) {
        close_worker(label, master_ctx, DBR, i);
    }
    for (int i = 0; i < MAX_DBW_WORKERS; ++i) {
        close_worker(label, master_ctx, DBW, i);
    }
    LOG_INFO("[Master]: Cleanup complete.");
}

status_t setup_workers(const char *label, master_context_t *master_ctx) {
    for (int index = 0; index < MAX_SIO_WORKERS; ++index) {
		if (create_socket_pair(label, master_ctx, SIO, index) != SUCCESS) return FAILURE;
    }
    for (int index = 0; index < MAX_LOGIC_WORKERS; ++index) {
		if (create_socket_pair(label, master_ctx, LOGIC, index) != SUCCESS) return FAILURE;
    }
    for (int index = 0; index < MAX_COW_WORKERS; ++index) {
		if (create_socket_pair(label, master_ctx, COW, index) != SUCCESS) return FAILURE;
    }
    for (int index = 0; index < MAX_DBR_WORKERS; ++index) {
		if (create_socket_pair(label, master_ctx, DBR, index) != SUCCESS) return FAILURE;
    }
    for (int index = 0; index < MAX_DBW_WORKERS; ++index) {
		if (create_socket_pair(label, master_ctx, DBW, index) != SUCCESS) return FAILURE;
    }    
	for (uint8_t index = 0; index < MAX_SIO_WORKERS; ++index) {
		if (setup_fork_worker(label, master_ctx, SIO, index) != SUCCESS) {
			return FAILURE;
		}
    }
    for (uint8_t index = 0; index < MAX_LOGIC_WORKERS; ++index) {
		if (setup_fork_worker(label, master_ctx, LOGIC, index) != SUCCESS) {
			return FAILURE;
		}
    }
    for (uint8_t index = 0; index < MAX_COW_WORKERS; ++index) {
		if (setup_fork_worker(label, master_ctx, COW, index) != SUCCESS) {
			return FAILURE;
		}
    }
    for (uint8_t index = 0; index < MAX_DBR_WORKERS; ++index) {
		if (setup_fork_worker(label, master_ctx, DBR, index) != SUCCESS) {
			return FAILURE;
		}
    }
    for (uint8_t index = 0; index < MAX_DBW_WORKERS; ++index) {
		if (setup_fork_worker(label, master_ctx, DBW, index) != SUCCESS) {
			return FAILURE;
		}
    }    
    return SUCCESS;
}

status_t calculate_avgtt(const char *label, master_context_t *master_ctx, worker_type_t wot, uint8_t index) {
    master_worker_session_t *session = get_master_worker_session(master_ctx, wot, index);
    if (session == NULL) {
        return FAILURE;
    }
    const char *worker_name = get_master_worker_name(wot);
    uint64_t_status_t rt = get_monotonic_time_ns(label);
    if (rt.status != SUCCESS) return rt.status;
    worker_metrics_t *metrics = &session->metrics;
    uint16_t *task_count = &session->task_count;
    oricle_long_double_t *oricle = &session->avgtt;
    uint64_t MAX_CONNECTION_PER_WORKER;
    if (wot == SIO) {
        MAX_CONNECTION_PER_WORKER = MAX_CONNECTION_PER_SIO_WORKER;
    } else if (wot == COW) {
        MAX_CONNECTION_PER_WORKER = MAX_CONNECTION_PER_COW_WORKER;
    } else {
        MAX_CONNECTION_PER_WORKER = (uint64_t)1;
    }
    if (!task_count || !metrics || !oricle) return FAILURE;
    metrics->last_ack = rt.r_uint64_t;
    metrics->last_task_finished = rt.r_uint64_t;
    uint64_t task_time;
    if (metrics->last_task_started == 0 ||
        rt.r_uint64_t < metrics->last_task_started) {
        task_time = 0;
        LOG_WARN("%s%s Worker %d: Invalid last_task_started detected. Resetting task_time to 0.", label, worker_name, index);
    } else {
        task_time = rt.r_uint64_t - metrics->last_task_started;
    }
    if (metrics->longest_task_time < task_time) {
        metrics->longest_task_time = task_time;
    }
    uint64_t previous_task_count = *task_count;
    if (previous_task_count > 0) {
        *task_count -= 1;
    } else {
        LOG_WARN("%sTask count for %s worker %d is already zero. Possible logic error.",
                 label, worker_name, index);
        *task_count = 0;
    }
    uint64_t current_task_count = *task_count;
    uint64_t previous_slot_kosong = MAX_CONNECTION_PER_WORKER - previous_task_count;
    uint64_t current_slot_kosong = MAX_CONNECTION_PER_WORKER - current_task_count;
    long double current_avgtt_measurement;
    if (current_slot_kosong > 0 && previous_slot_kosong > 0) {
        current_avgtt_measurement = ((oricle->value_prediction * previous_slot_kosong) + task_time) / (long double)current_slot_kosong;
    } else if (previous_slot_kosong == 0 && current_slot_kosong > 0) {
        current_avgtt_measurement = (long double)task_time;
    } else {
        current_avgtt_measurement = (long double)0;
    }
    char *desc;
	int needed = snprintf(NULL, 0, "ORICLE => AVGTT %s-%d", worker_name, index);
	desc = malloc(needed + 1);
	snprintf(desc, needed + 1, "ORICLE => AVGTT %s-%d", worker_name, index);
    calculate_oricle_long_double(label, desc, oricle, current_avgtt_measurement, (long double)0);
    free(desc);
    return SUCCESS;
}

status_t calculate_healthy(const char* label, master_context_t *master_ctx, worker_type_t wot, uint8_t index) {
    master_worker_session_t *session = get_master_worker_session(master_ctx, wot, index);
    if (session == NULL) {
        return FAILURE;
    }
    const char *worker_name = get_master_worker_name(wot);
    uint64_t_status_t rt = get_monotonic_time_ns(label);
    if (rt.status != SUCCESS) return rt.status;
    worker_metrics_t *metrics = &session->metrics;
    oricle_double_t *oricle = &session->healthy;
    bool *ishealthy = &session->ishealthy;
    if (!metrics || !oricle || !ishealthy) return FAILURE;
    uint64_t now_ns = rt.r_uint64_t;
    double actual_elapsed_sec = (double)(now_ns - metrics->last_checkhealthy) / 1e9;
    double ttl_delay_jitter = (metrics->sum_hb_interval - metrics->hb_interval) - ((double)WORKER_HEARTBEAT_INTERVAL * metrics->count_ack);
    double setup_elapsed_sec = (double)WORKER_HEARTBEAT_INTERVAL + ttl_delay_jitter;
    double setup_count_ack = setup_elapsed_sec / (double)WORKER_HEARTBEAT_INTERVAL;
    double comp_elapsed_sec = actual_elapsed_sec / setup_elapsed_sec;
    double expected_count_ack = setup_count_ack * comp_elapsed_sec;
    double current_health_measurement;
    if (expected_count_ack <= (double)0) {
        current_health_measurement = (double)100;
    } else {
        current_health_measurement = metrics->count_ack / expected_count_ack;
    }
    current_health_measurement *= (double)100;    
    char *desc;
	int needed = snprintf(NULL, 0, "ORICLE => HEALTHY %s-%d", worker_name, index);
	desc = malloc(needed + 1);
	snprintf(desc, needed + 1, "ORICLE => HEALTHY %s-%d", worker_name, index);
    calculate_oricle_double(label, desc, oricle, current_health_measurement, (double)200);
    free(desc);
    *ishealthy = (oricle->value_prediction >= HEALTHY_THRESHOLD);
    metrics->last_checkhealthy = now_ns;
    metrics->count_ack = (double)0;
    metrics->sum_hb_interval = metrics->hb_interval;
    return SUCCESS;
}

status_t recreate_worker(const char *label, master_context_t *master_ctx, worker_type_t wot, uint8_t index) {
    if (close_worker(label, master_ctx, wot, index) != SUCCESS) {
        return FAILURE;
    }
    if (create_socket_pair(label, master_ctx, wot, index) != SUCCESS) {
        return FAILURE;
    }
    if (setup_fork_worker(label, master_ctx, wot, index) != SUCCESS) {
        return FAILURE;
    }
    if (master_worker_info(label, master_ctx, wot, index, IT_READY) != SUCCESS) {
        return FAILURE;
    }
    return SUCCESS;
}

status_t check_workers_healthy(const char *label, master_context_t *master_ctx) {
	for (uint8_t i = 0; i < MAX_SIO_WORKERS; ++i) { 
		if (calculate_healthy(label, master_ctx, SIO, i) != SUCCESS) {
            return FAILURE;
        }
        master_worker_session_t *session = get_master_worker_session(master_ctx, SIO, i);
        if (session == NULL) {
            return FAILURE;
        }
        if (session->healthy.value_prediction < (double)25) {
            session->isactive = false;
            if (recreate_worker(label, master_ctx, SIO, i) != SUCCESS) {
                return FAILURE;
            }
        }
	}
	for (uint8_t i = 0; i < MAX_LOGIC_WORKERS; ++i) {
		if (calculate_healthy(label, master_ctx, LOGIC, i) != SUCCESS) {
            return FAILURE;
        }
        master_worker_session_t *session = get_master_worker_session(master_ctx, LOGIC, i);
        if (session == NULL) {
            return FAILURE;
        }
        if (session->healthy.value_prediction < (double)25) {
            session->isactive = false;
            if (recreate_worker(label, master_ctx, LOGIC, i) != SUCCESS) {
                return FAILURE;
            }
        }
	}
	for (uint8_t i = 0; i < MAX_COW_WORKERS; ++i) { 
		if (calculate_healthy(label, master_ctx, COW, i) != SUCCESS) {
            return FAILURE;
        }
        master_worker_session_t *session = get_master_worker_session(master_ctx, COW, i);
        if (session == NULL) {
            return FAILURE;
        }
        if (session->healthy.value_prediction < (double)25) {
            session->isactive = false;
            if (recreate_worker(label, master_ctx, COW, i) != SUCCESS) {
                return FAILURE;
            }
        }
	}
    for (uint8_t i = 0; i < MAX_DBR_WORKERS; ++i) { 
		if (calculate_healthy(label, master_ctx, DBR, i) != SUCCESS) {
            return FAILURE;
        }
        master_worker_session_t *session = get_master_worker_session(master_ctx, DBR, i);
        if (session == NULL) {
            return FAILURE;
        }
        if (session->healthy.value_prediction < (double)25) {
            session->isactive = false;
            if (recreate_worker(label, master_ctx, DBR, i) != SUCCESS) {
                return FAILURE;
            }
        }
	}
    for (uint8_t i = 0; i < MAX_DBW_WORKERS; ++i) { 
		if (calculate_healthy(label, master_ctx, DBW, i) != SUCCESS) {
            return FAILURE;
        }
        master_worker_session_t *session = get_master_worker_session(master_ctx, DBW, i);
        if (session == NULL) {
            return FAILURE;
        }
        if (session->healthy.value_prediction < (double)25) {
            session->isactive = false;
            if (recreate_worker(label, master_ctx, DBW, i) != SUCCESS) {
                return FAILURE;
            }
        }
	}
    return SUCCESS;
}
