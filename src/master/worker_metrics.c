#include <stdbool.h>
#include <stdlib.h>
#include <inttypes.h>

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

status_t new_task_metrics(const char *label, master_context *master_ctx, worker_type_t wot, int index) {
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
    if (rt.status != SUCCESS) return rt.status;
    worker_metrics_t *metrics = NULL;
    uint16_t *task_count = NULL;
    if (wot == SIO) {
        metrics = &master_ctx->sio_session[index].metrics;
        task_count = &master_ctx->sio_session[index].task_count;
    } else if (wot == COW) {
        metrics = &master_ctx->cow_session[index].metrics;
        task_count = &master_ctx->cow_session[index].task_count;
    }
    if (!task_count || !metrics) return FAILURE;
    *task_count += 1;
    metrics->last_task_started = rt.r_uint64_t;
    LOG_DEBUG("%s%s_STATE:\nTask Count: %" PRIu64 "\nLast Ack: %" PRIu64 "\nLast Started: %" PRIu64 "\nLast Finished: %" PRIu64 "\nLongest Task Time: %" PRIu64 "\nAvg Task Time: %Lf",
        label,
        worker_name,
        *task_count,
        metrics->last_ack,
        metrics->last_task_started,
        metrics->last_task_finished,
        metrics->longest_task_time,
        metrics->avg_task_time_per_empty_slot
    );
    return SUCCESS;
}

status_t calculate_avg_task_time_metrics(const char *label, master_context *master_ctx, worker_type_t wot, int index) {
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
    if (rt.status != SUCCESS) return rt.status;
    worker_metrics_t *metrics = NULL;
    uint16_t *task_count = NULL;
    if (wot == SIO) {
        metrics = &master_ctx->sio_session[index].metrics;
        task_count = &master_ctx->sio_session[index].task_count;
    } else if (wot == COW) {
        metrics = &master_ctx->cow_session[index].metrics;
        task_count = &master_ctx->cow_session[index].task_count;
    }
    if (!task_count || !metrics) return FAILURE;
    if (metrics->first_check_avgtt == (uint8_t)0x01) {
        metrics->first_check_avgtt = (uint8_t)0x00;
        metrics->avgtt_kalman_filter.is_initialized = false;
        metrics->avgtt_kalman_initialized_count = 0;
        if (metrics->avgtt_kalman_calibration_samples != NULL) {
            free(metrics->avgtt_kalman_calibration_samples);
            metrics->avgtt_kalman_calibration_samples = NULL;
        }
        metrics->longest_task_time = 0;
        metrics->avg_task_time_per_empty_slot = 0.0L;
        LOG_DEBUG("%s%s Worker %d: First-time setup for Avg Task Time metrics.", label, worker_name, index);
    }
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
    uint64_t previous_slot_kosong = MAX_CONNECTION_PER_SIO_WORKER - previous_task_count;
    uint64_t current_slot_kosong = MAX_CONNECTION_PER_SIO_WORKER - current_task_count;
    long double current_avg_task_time_measurement;
    if (current_slot_kosong > 0 && previous_slot_kosong > 0) {
        current_avg_task_time_measurement = ((metrics->avg_task_time_per_empty_slot * previous_slot_kosong) + task_time) / (long double)current_slot_kosong;
    } else if (previous_slot_kosong == 0 && current_slot_kosong > 0) {
        current_avg_task_time_measurement = (long double)task_time;
    } else {
        current_avg_task_time_measurement = 0.0L;
    }
    if (current_avg_task_time_measurement < 0.0L) current_avg_task_time_measurement = 0.0L;
    if (!metrics->avgtt_kalman_filter.is_initialized) {
        if (metrics->avgtt_kalman_calibration_samples == NULL) {
            metrics->avgtt_kalman_calibration_samples =
                (float *)malloc(KALMAN_CALIBRATION_SAMPLES * sizeof(float));
            if (!metrics->avgtt_kalman_calibration_samples) {
                LOG_ERROR("%s Failed to allocate avgtt calibration samples for %s worker %d. Fallback to raw measurement.",
                          label, worker_name, index);
                metrics->avg_task_time_per_empty_slot = current_avg_task_time_measurement;
            }
        }
        if (metrics->avgtt_kalman_initialized_count < KALMAN_CALIBRATION_SAMPLES) {
            metrics->avgtt_kalman_calibration_samples[metrics->avgtt_kalman_initialized_count] =
                (float)current_avg_task_time_measurement;
            metrics->avgtt_kalman_initialized_count++;
            if (metrics->avgtt_kalman_initialized_count == KALMAN_CALIBRATION_SAMPLES) {
                float avg_value = calculate_average(metrics->avgtt_kalman_calibration_samples, KALMAN_CALIBRATION_SAMPLES);
                float var_value = calculate_variance(metrics->avgtt_kalman_calibration_samples, KALMAN_CALIBRATION_SAMPLES, avg_value);
                free(metrics->avgtt_kalman_calibration_samples);
                metrics->avgtt_kalman_calibration_samples = NULL;
                if (var_value < 0.1f) var_value = 0.1f;
                float kalman_q_avg_task = 1.0f;
                float kalman_r_avg_task = var_value;
                float kalman_p0_avg_task = var_value * 2.0f;
                kalman_init(&metrics->avgtt_kalman_filter,
                            kalman_q_avg_task, kalman_r_avg_task, kalman_p0_avg_task, avg_value);
                metrics->avgtt_kalman_filter.is_initialized = true;                                
                metrics->avg_task_time_per_empty_slot = (long double)metrics->avgtt_kalman_filter.state_estimate;
                LOG_DEBUG("%s%s Worker %d: Kalman Avg Task Time Filter initialized. Avg: %.2Lf, Var: %.2f (Q:%.2f, R:%.2f, P0:%.2f)",
                                label, worker_name, index, (long double)avg_value, var_value, kalman_q_avg_task, kalman_r_avg_task, kalman_p0_avg_task);
            } else {
                metrics->avg_task_time_per_empty_slot = current_avg_task_time_measurement;
                LOG_DEBUG("%s%s Worker %d: Calibrating Avg Task Time... (%d/%d) -> Meas: %.2Lf",
                                label, worker_name, index, metrics->avgtt_kalman_initialized_count,
                                KALMAN_CALIBRATION_SAMPLES, current_avg_task_time_measurement);
            }
        }
    } else {
        metrics->avg_task_time_per_empty_slot =
            kalman_filter(&metrics->avgtt_kalman_filter, (float)current_avg_task_time_measurement);
        if (metrics->avg_task_time_per_empty_slot < 0.0L) {
            metrics->avg_task_time_per_empty_slot = 0.0L;
        }
    }
    LOG_DEBUG("%s%s_STATE:\nTask Count: %" PRIu64 "\nLast Ack: %" PRIu64
                    "\nLast Started: %" PRIu64 "\nLast Finished: %" PRIu64
                    "\nLongest Task Time: %" PRIu64
                    "\nMeas Avg Task Time per Empty Slot: %.2Lf -> Est Avg Task Time per Empty Slot: %.2Lf",
                    label,
                    worker_name,
                    *task_count,
                    metrics->last_ack,
                    metrics->last_task_started,
                    metrics->last_task_finished,
                    metrics->longest_task_time,
                    current_avg_task_time_measurement,
                    metrics->avg_task_time_per_empty_slot);
    return SUCCESS;
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
		if (check_worker_healthy(label, SIO, i, &master_ctx->sio_session[i].metrics) != SUCCESS) {
            return FAILURE;
        }
        if (master_ctx->sio_session[i].metrics.healthypct < (float)25) {
            master_ctx->sio_session[i].metrics.isactive = false;
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
		if (check_worker_healthy(label, LOGIC, i, &master_ctx->logic_session[i].metrics) != SUCCESS) {
            return FAILURE;
        }
        if (master_ctx->logic_session[i].metrics.healthypct < (float)25) {
            master_ctx->logic_session[i].metrics.isactive = false;
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
		if (check_worker_healthy(label, COW, i, &master_ctx->cow_session[i].metrics) != SUCCESS) {
            return FAILURE;
        }
        if (master_ctx->cow_session[i].metrics.healthypct < (float)25) {
            master_ctx->cow_session[i].metrics.isactive = false;
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
		if (check_worker_healthy(label, DBR, i, &master_ctx->dbr_session[i].metrics) != SUCCESS) {
            return FAILURE;
        }
        if (master_ctx->dbr_session[i].metrics.healthypct < (float)25) {
            master_ctx->dbr_session[i].metrics.isactive = false;
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
		if (check_worker_healthy(label, DBW, i, &master_ctx->dbw_session[i].metrics) != SUCCESS) {
            return FAILURE;
        }
        if (master_ctx->dbw_session[i].metrics.healthypct < (float)25) {
            master_ctx->dbw_session[i].metrics.isactive = false;
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
