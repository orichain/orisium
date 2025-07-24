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
    metrics->health_temp_ewma_value = (double)0;
    metrics->health_value_prediction = (double)100;
    metrics->first_check_avgtt = (uint8_t)0x01;
    metrics->avgtt_kalman_calibration_samples = NULL;
    metrics->avgtt_kalman_initialized_count = 0;
    metrics->avgtt_temp_ewma_value = (long double)0;
    metrics->avgtt_value_prediction = (long double)0;
    metrics->sum_hbtime = (double)0;
    metrics->hbtime = (double)0;
    metrics->count_ack = (double)0;
    metrics->last_ack = rt.r_uint64_t;
    metrics->last_checkhealthy = rt.r_uint64_t;
    metrics->isactive = true;
    metrics->ishealthy = true;
    metrics->last_task_started = rt.r_uint64_t;
    metrics->last_task_finished = rt.r_uint64_t;
    metrics->longest_task_time = 0ULL;
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
    LOG_DEBUG("%s%s[%d]_STATE:\nTask Count: %" PRIu64 "\nLast Ack: %" PRIu64 "\nLast Started: %" PRIu64 "\nLast Finished: %" PRIu64 "\nLongest Task Time: %" PRIu64 "\nAvg Task Time: %Lf",
        label,
        worker_name,
        index,
        *task_count,
        metrics->last_ack,
        metrics->last_task_started,
        metrics->last_task_finished,
        metrics->longest_task_time,
        metrics->avgtt_value_prediction
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
    uint64_t MAX_CONNECTION_PER_WORKER;
    if (wot == SIO) {
        metrics = &master_ctx->sio_session[index].metrics;
        task_count = &master_ctx->sio_session[index].task_count;
        MAX_CONNECTION_PER_WORKER = MAX_CONNECTION_PER_SIO_WORKER;
    } else if (wot == COW) {
        metrics = &master_ctx->cow_session[index].metrics;
        task_count = &master_ctx->cow_session[index].task_count;
        MAX_CONNECTION_PER_WORKER = MAX_CONNECTION_PER_COW_WORKER;
    }
    if (!task_count || !metrics) return FAILURE;
    if (metrics->first_check_avgtt == (uint8_t)0x01) {
        metrics->first_check_avgtt = (uint8_t)0x00;
        metrics->longest_task_time = 0;
        metrics->avgtt_value_prediction = (long double)0;
        metrics->avgtt_kalman_filter.is_initialized = false;
        metrics->avgtt_kalman_initialized_count = 0;
        if (metrics->avgtt_kalman_calibration_samples != NULL) {
            free(metrics->avgtt_kalman_calibration_samples);
            metrics->avgtt_kalman_calibration_samples = NULL;
        }
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
    uint64_t previous_slot_kosong = MAX_CONNECTION_PER_WORKER - previous_task_count;
    uint64_t current_slot_kosong = MAX_CONNECTION_PER_WORKER - current_task_count;
    long double current_avgtt_measurement;
    if (current_slot_kosong > 0 && previous_slot_kosong > 0) {
        current_avgtt_measurement = ((metrics->avgtt_value_prediction * previous_slot_kosong) + task_time) / (long double)current_slot_kosong;
    } else if (previous_slot_kosong == 0 && current_slot_kosong > 0) {
        current_avgtt_measurement = (long double)task_time;
    } else {
        current_avgtt_measurement = (long double)0;
    }
    if (current_avgtt_measurement < (long double)0) current_avgtt_measurement = (long double)0;
    if (!metrics->avgtt_kalman_filter.is_initialized) {
        if (metrics->avgtt_kalman_calibration_samples == NULL) {
            metrics->avgtt_kalman_calibration_samples = (long double *)malloc(KALMAN_CALIBRATION_SAMPLES * sizeof(long double));
            if (!metrics->avgtt_kalman_calibration_samples) {
                LOG_ERROR("%s Failed to allocate avgtt calibration samples for %s worker %d. Fallback to raw measurement.", label, worker_name, index);
                metrics->avgtt_value_prediction = current_avgtt_measurement;
                return FAILURE;
            }
            metrics->avgtt_temp_ewma_value = current_avgtt_measurement;
        }
        if (metrics->avgtt_kalman_initialized_count < KALMAN_CALIBRATION_SAMPLES) {
            metrics->avgtt_kalman_calibration_samples[metrics->avgtt_kalman_initialized_count] = (long double)current_avgtt_measurement;
            metrics->avgtt_kalman_initialized_count++;
            if (metrics->avgtt_kalman_initialized_count > 1) {
                metrics->avgtt_temp_ewma_value = (long double)KALMAN_ALPHA_EWMA * current_avgtt_measurement + ((long double)1 - (long double)KALMAN_ALPHA_EWMA) * metrics->avgtt_temp_ewma_value;
            }
            if (metrics->avgtt_kalman_initialized_count == KALMAN_CALIBRATION_SAMPLES) {
                long double avg_value = calculate_long_double_average(metrics->avgtt_kalman_calibration_samples, KALMAN_CALIBRATION_SAMPLES);
                long double var_value = calculate_long_double_variance(metrics->avgtt_kalman_calibration_samples, KALMAN_CALIBRATION_SAMPLES, avg_value);
                free(metrics->avgtt_kalman_calibration_samples);
                metrics->avgtt_kalman_calibration_samples = NULL;
                if (var_value < (long double)0.1) var_value = (long double)0.1;
                long double kalman_q_avg_task = (long double)1;
                long double kalman_r_avg_task = var_value;
                long double kalman_p0_avg_task = var_value * (long double)2;
                kalman_long_double_init(&metrics->avgtt_kalman_filter,
                            kalman_q_avg_task, kalman_r_avg_task, kalman_p0_avg_task, avg_value);
                metrics->avgtt_kalman_filter.is_initialized = true;                                
                metrics->avgtt_value_prediction = (long double)metrics->avgtt_kalman_filter.state_estimate;
                
                LOG_DEBUG("%s%s[%d] Kalman Avg Task Time Filter fully initialized. Avg: %.2Lf, Var: %.2Lf (Q:%.2Lf, R:%.2Lf, P0:%.2Lf)",
                                label, worker_name, index, avg_value, var_value, kalman_q_avg_task, kalman_r_avg_task, kalman_p0_avg_task);
            } else {
                metrics->avgtt_value_prediction = metrics->avgtt_temp_ewma_value;
                LOG_DEBUG("Calibrating avgtt... (%d/%d) -> Meas: %.2Lf -> EWMA: %.2Lf",
                                metrics->avgtt_kalman_initialized_count, KALMAN_CALIBRATION_SAMPLES,
                                current_avgtt_measurement, metrics->avgtt_temp_ewma_value);
            }
        }
        LOG_DEBUG("%s%s[%d]_STATE:\nTask Count: %" PRIu64 "\nLast Ack: %" PRIu64
                        "\nLast Started: %" PRIu64 "\nLast Finished: %" PRIu64
                        "\nLongest Task Time: %" PRIu64
                        "\nMeas Avg Task Time per Empty Slot: %.2Lf -> Est Avg Task Time per Empty Slot: %.2Lf",
                        label,
                        worker_name,
                        index,
                        *task_count,
                        metrics->last_ack,
                        metrics->last_task_started,
                        metrics->last_task_finished,
                        metrics->longest_task_time,
                        current_avgtt_measurement,
                        metrics->avgtt_value_prediction);
        return SUCCESS;
    }
    metrics->avgtt_value_prediction = kalman_long_double_filter(&metrics->avgtt_kalman_filter, (long double)current_avgtt_measurement);
    if (metrics->avgtt_value_prediction < (long double)0) {
        metrics->avgtt_value_prediction = (long double)0;
    }
    LOG_DEBUG("%s%s[%d]_STATE:\nTask Count: %" PRIu64 "\nLast Ack: %" PRIu64
                    "\nLast Started: %" PRIu64 "\nLast Finished: %" PRIu64
                    "\nLongest Task Time: %" PRIu64
                    "\nMeas Avg Task Time per Empty Slot: %.2Lf -> Est Avg Task Time per Empty Slot: %.2Lf",
                    label,
                    worker_name,
                    index,
                    *task_count,
                    metrics->last_ack,
                    metrics->last_task_started,
                    metrics->last_task_finished,
                    metrics->longest_task_time,
                    current_avgtt_measurement,
                    metrics->avgtt_value_prediction);
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
        m->health_value_prediction = (double)100;
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
    double current_health_measurement;
    if (expected_count_ack <= (double)0) {
        current_health_measurement = (double)100;
    } else {
        current_health_measurement = m->count_ack / expected_count_ack;
    }
    current_health_measurement *= (double)100;
    if (current_health_measurement < (double)0) current_health_measurement = (double)0;
    if (current_health_measurement > (double)200) current_health_measurement = (double)200;
    if (!m->health_kalman_filter.is_initialized) {
        if (m->health_kalman_calibration_samples == NULL) {
            m->health_kalman_calibration_samples = (double *)malloc(KALMAN_CALIBRATION_SAMPLES * sizeof(double));
            if (!m->health_kalman_calibration_samples) {
                m->health_value_prediction = current_health_measurement;
                m->ishealthy = (m->health_value_prediction >= HEALTHY_THRESHOLD);
                m->last_checkhealthy = now_ns;
                m->count_ack = (double)0;
                m->sum_hbtime = m->hbtime;
                LOG_ERROR("%s[%s %d] Failed to allocate health calibration samples. Fallback to raw measurement.", label, worker_name, index);
                return FAILURE;
            }
            m->health_temp_ewma_value = current_health_measurement;
        }
        if (m->health_kalman_initialized_count < KALMAN_CALIBRATION_SAMPLES) {
            m->health_kalman_calibration_samples[m->health_kalman_initialized_count] = current_health_measurement;
            m->health_kalman_initialized_count++;
            if (m->health_kalman_initialized_count > 1) {
                m->health_temp_ewma_value = (double)KALMAN_ALPHA_EWMA * current_health_measurement + ((double)1 - (double)KALMAN_ALPHA_EWMA) * m->health_temp_ewma_value;
            }
            if (m->health_kalman_initialized_count == KALMAN_CALIBRATION_SAMPLES) {
                double avg_health = calculate_double_average(m->health_kalman_calibration_samples, KALMAN_CALIBRATION_SAMPLES);
                double var_health = calculate_double_variance(m->health_kalman_calibration_samples, KALMAN_CALIBRATION_SAMPLES, avg_health);
                free(m->health_kalman_calibration_samples);
                m->health_kalman_calibration_samples = NULL;
                if (var_health < (double)0.1) var_health = (double)0.1;               
                double kalman_q = 1;
                double kalman_r = var_health;
                double kalman_p0 = var_health * (double)2;
                kalman_double_init(&m->health_kalman_filter, kalman_q, kalman_r, kalman_p0, avg_health);
                m->health_kalman_filter.is_initialized = true;
                m->health_value_prediction = m->health_kalman_filter.state_estimate;
                LOG_DEBUG("%s[%s %d] Kalman Health Filter fully initialized. Avg: %.2f, Var: %.2f (Q:%.2f, R:%.2f, P0:%.2f)",
                                label, worker_name, index, avg_health, var_health, kalman_q, kalman_r, kalman_p0);
            } else {
                m->health_value_prediction = m->health_temp_ewma_value;
                LOG_DEBUG("Calibrating health... (%d/%d) -> Meas: %.2f -> EWMA: %.2f",
                                m->health_kalman_initialized_count, KALMAN_CALIBRATION_SAMPLES,
                                current_health_measurement, m->health_temp_ewma_value);
            }
        }
        m->ishealthy = (m->health_value_prediction >= HEALTHY_THRESHOLD);
        m->last_checkhealthy = now_ns;
        m->count_ack = (double)0;
        m->sum_hbtime = m->hbtime;
        return SUCCESS;
    }
    m->health_value_prediction = kalman_double_filter(&m->health_kalman_filter, current_health_measurement);
    if (m->health_value_prediction < (double)0) m->health_value_prediction = (double)0;
    if (m->health_value_prediction > (double)100) m->health_value_prediction = (double)100;
    m->ishealthy = (m->health_value_prediction >= HEALTHY_THRESHOLD);
    m->last_checkhealthy = now_ns;
    m->count_ack = 0;
    m->sum_hbtime = m->hbtime;
    LOG_DEBUG(
        "%s[%s %d] Meas health: %.2f%% -> Est health: %.2f%% [%s]",
        label, worker_name, index,
        current_health_measurement,
        m->health_value_prediction,
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
        if (master_ctx->sio_session[i].metrics.health_value_prediction < (double)25) {
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
        if (master_ctx->logic_session[i].metrics.health_value_prediction < (double)25) {
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
        if (master_ctx->cow_session[i].metrics.health_value_prediction < (double)25) {
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
        if (master_ctx->dbr_session[i].metrics.health_value_prediction < (double)25) {
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
        if (master_ctx->dbw_session[i].metrics.health_value_prediction < (double)25) {
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
