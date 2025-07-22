#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include "log.h"
#include "constants.h"
#include "utilities.h"
#include "kalman.h"
#include "types.h"
#include "master/workers.h"
#include "master/process.h"
#include "sessions/master_session.h"

double initialize_metrics(const char *label, worker_metrics_t* metrics, worker_type_t wot, int index) {
    int worker_type_id = (int)wot;
    const double MAX_INITIAL_DELAY_MS = (double)WORKER_HEARTBEATSEC_NODE_HEARTBEATSEC_TIMEOUT * 1000.0;
    double initial_delay_ms = (double)worker_type_id * index * INITIAL_MILISECONDS_PER_UNIT;
    if (initial_delay_ms > MAX_INITIAL_DELAY_MS) {
        initial_delay_ms = MAX_INITIAL_DELAY_MS;
    }
    uint64_t_status_t rt = get_realtime_time_ns(label);
    metrics->first_check_healthy = (uint8_t)0x01;
    metrics->health_kalman_calibration_samples = NULL;
    metrics->health_kalman_initialized_count = 0;
    metrics->health_temp_ewma_value = (float)0;
    metrics->first_check_avgtt = (uint8_t)0x01;
    metrics->avgtt_kalman_calibration_samples = NULL;
    metrics->avgtt_kalman_initialized_count = 0;
    metrics->avgtt_temp_ewma_value = (float)0;
    metrics->sum_hbtime = (double)0;
    metrics->hbtime = (double)0;
    metrics->count_ack = (double)0;
    metrics->last_ack = rt.r_uint64_t;
    metrics->last_checkhealthy = rt.r_uint64_t;
    metrics->healthypct = (float)100;
    metrics->isactive = true;
    metrics->ishealthy = true;
    metrics->last_task_started = rt.r_uint64_t;
    metrics->last_task_finished = rt.r_uint64_t;
    metrics->longest_task_time = 0ULL;
    metrics->avg_task_time_per_empty_slot = (long double)0;
//======================================================================            
    if (initial_delay_ms > 0) {
        metrics->hbtime = (double)WORKER_HEARTBEATSEC_NODE_HEARTBEATSEC_TIMEOUT + ((double)initial_delay_ms/1000.0);
        metrics->sum_hbtime = metrics->hbtime;
        metrics->count_ack = (double)0;
    }
    return initial_delay_ms;
}

status_t check_worker_healthy(const char* label, worker_type_t wot, int index, worker_metrics_t* m) {
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
        m->healthypct = 100.0f;
        m->ishealthy = true;
        m->last_checkhealthy = now_ns;
        m->count_ack = 0;
        m->sum_hbtime = m->hbtime;
        m->health_kalman_filter.is_initialized = false;
        m->health_kalman_initialized_count = 0;
        if (m->health_kalman_calibration_samples != NULL) {
            free(m->health_kalman_calibration_samples);
            m->health_kalman_calibration_samples = NULL;
        }
        LOG_DEBUG("%s[%s %d] First-time health check -> assumed healthy (100%%)", label, worker_name, index);
    }
    double actual_elapsed_sec = (double)(now_ns - m->last_checkhealthy) / 1e9;
    double ttl_delay_jitter = (m->sum_hbtime - m->hbtime) - ((double)WORKER_HEARTBEATSEC_NODE_HEARTBEATSEC_TIMEOUT * m->count_ack);
    double setup_elapsed_sec = (double)WORKER_HEARTBEATSEC_TIMEOUT + ttl_delay_jitter;
    double setup_count_ack = setup_elapsed_sec / (double)WORKER_HEARTBEATSEC_NODE_HEARTBEATSEC_TIMEOUT;
    double comp_elapsed_sec = actual_elapsed_sec / setup_elapsed_sec;
    double expected_count_ack = setup_count_ack * comp_elapsed_sec;
    float current_health_ratio_measurement;
    if (expected_count_ack <= 0.0) {
        current_health_ratio_measurement = 100.0f;
    } else {
        current_health_ratio_measurement = (float)(m->count_ack / expected_count_ack);
    }
    current_health_ratio_measurement *= 100.0f;
    if (current_health_ratio_measurement < 0.0f) current_health_ratio_measurement = 0.0f;
    if (current_health_ratio_measurement > 200.0f) current_health_ratio_measurement = 200.0f;
    if (!m->health_kalman_filter.is_initialized) {
        if (m->health_kalman_calibration_samples == NULL) {
            m->health_kalman_calibration_samples = (float *)malloc(KALMAN_CALIBRATION_SAMPLES * sizeof(float));
            if (!m->health_kalman_calibration_samples) {
                m->healthypct = current_health_ratio_measurement;
                m->ishealthy = (m->healthypct >= HEALTHY_THRESHOLD);
                m->last_checkhealthy = now_ns;
                m->count_ack = 0;
                m->sum_hbtime = m->hbtime;
                LOG_ERROR("%s[%s %d] Failed to allocate health calibration samples. Fallback to raw measurement.", label, worker_name, index);
                return FAILURE;
            }
            m->health_temp_ewma_value = current_health_ratio_measurement;
        }
        if (m->health_kalman_initialized_count < KALMAN_CALIBRATION_SAMPLES) {
            m->health_kalman_calibration_samples[m->health_kalman_initialized_count] = current_health_ratio_measurement;
            m->health_kalman_initialized_count++;
            if (m->health_kalman_initialized_count > 1) {
                m->health_temp_ewma_value = KALMAN_ALPHA_EWMA * current_health_ratio_measurement + (1.0f - KALMAN_ALPHA_EWMA) * m->health_temp_ewma_value;
            }
            if (m->health_kalman_initialized_count == KALMAN_CALIBRATION_SAMPLES) {
                float avg_health = calculate_average(m->health_kalman_calibration_samples, KALMAN_CALIBRATION_SAMPLES);
                float var_health = calculate_variance(m->health_kalman_calibration_samples, KALMAN_CALIBRATION_SAMPLES, avg_health);
                free(m->health_kalman_calibration_samples);
                m->health_kalman_calibration_samples = NULL;
                if (var_health < 0.1f) var_health = 0.1f;               
                float kalman_q = 1.0f;
                float kalman_r = var_health;
                float kalman_p0 = var_health * 2.0f;
                kalman_init(&m->health_kalman_filter, kalman_q, kalman_r, kalman_p0, avg_health);
                m->health_kalman_filter.is_initialized = true;
                m->healthypct = m->health_kalman_filter.state_estimate;
                LOG_DEBUG("%s[%s %d] Kalman Health Filter fully initialized. Avg: %.2f, Var: %.2f (Q:%.2f, R:%.2f, P0:%.2f)",
                                label, worker_name, index, avg_health, var_health, kalman_q, kalman_r, kalman_p0);
            } else {
                m->healthypct = m->health_temp_ewma_value;
                LOG_DEBUG("Calibrating health... (%d/%d) -> Meas: %.2f -> EWMA: %.2f",
                                m->health_kalman_initialized_count, KALMAN_CALIBRATION_SAMPLES,
                                current_health_ratio_measurement, m->health_temp_ewma_value);
            }
        }
        m->ishealthy = (m->healthypct >= HEALTHY_THRESHOLD);
        m->last_checkhealthy = now_ns;
        m->count_ack = 0;
        m->sum_hbtime = m->hbtime;
        return SUCCESS;
    }
    m->healthypct = kalman_filter(&m->health_kalman_filter, current_health_ratio_measurement);
    if (m->healthypct < 0.0f) m->healthypct = 0.0f;
    if (m->healthypct > 100.0f) m->healthypct = 100.0f;
    m->ishealthy = (m->healthypct >= HEALTHY_THRESHOLD);
    m->last_checkhealthy = now_ns;
    m->count_ack = 0;
    m->sum_hbtime = m->hbtime;
    LOG_DEBUG(
        "%s[%s %d] Meas health: %.2f%% -> Est health: %.2f%% [%s]",
        label, worker_name, index,
        current_health_ratio_measurement,
        m->healthypct,
        m->ishealthy ? "HEALTHY" : "UNHEALTHY"
    );

    return SUCCESS;
}

status_t check_workers_healthy(master_context *master_ctx) {
	const char *label = "[Master]: ";
	for (int i = 0; i < MAX_SIO_WORKERS; ++i) { 
		if (check_worker_healthy(label, SIO, i, &master_ctx->sio_state[i].metrics) != SUCCESS) {
            return FAILURE;
        }
        if (master_ctx->sio_state[i].metrics.healthypct < (float)25) {
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
        if (master_ctx->logic_state[i].metrics.healthypct < (float)25) {
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
        if (master_ctx->cow_state[i].metrics.healthypct < (float)25) {
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
        if (master_ctx->dbr_state[i].metrics.healthypct < (float)25) {
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
        if (master_ctx->dbw_state[i].metrics.healthypct < (float)25) {
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
